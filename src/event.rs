use crate::attrs::EventAttrKey;
use crate::client::Client;
use crate::error::Error;
use babeltrace2_sys::{OwnedEvent, OwnedField, ScalarField};
use modality_api::{AttrKey, AttrVal, BigInt, LogicalTime, Nanoseconds};
use modality_ingest_protocol::InternedAttrKey;
use std::collections::{BTreeSet, HashMap};
use tracing::warn;
use uuid::Uuid;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CtfEvent {
    attrs: HashMap<InternedAttrKey, AttrVal>,
}

impl CtfEvent {
    pub async fn new(event: &OwnedEvent, client: &mut Client) -> Result<Self, Error> {
        let mut attrs = HashMap::new();

        let mut is_reserved_event = false;
        if let Some(n) = event.class_properties.name.as_deref() {
            // Convert the well-known modality event names from their C-identifier-like names
            let (event_name, reserved_event) = match n {
                "modality_mutator_announced" => ("modality.mutator.announced", true),
                "modality_mutator_retired" => ("modality.mutator.retired", true),
                "modality_mutation_command_communicated" => {
                    ("modality.mutation.command_communicated", true)
                }
                "modality_mutation_clear_communicated" => {
                    ("modality.mutation.clear_communicated", true)
                }
                "modality_mutation_triggered" => ("modality.mutation.triggered", true),
                "modality_mutation_injected" => ("modality.mutation.injected", true),
                _ => (n, false),
            };
            is_reserved_event = reserved_event;
            attrs.insert(
                client.interned_event_key(EventAttrKey::Name).await?,
                event_name.to_owned().into(),
            );
        }

        let timestamp_ns: Option<u64> = event.clock_snapshot.and_then(|c: i64| {
                if c < 0 {
                    warn!("Dropping Event ID {} clock snapshot because it's negative, consider adjusting the origin epoch offset input parameter",
                          event.class_properties.id);
                    None
                } else {
                    Some(c as u64)
                }
            });
        if let Some(ts) = timestamp_ns {
            attrs.insert(
                client.interned_event_key(EventAttrKey::Timestamp).await?,
                Nanoseconds::from(ts).into(),
            );
            attrs.insert(
                client
                    .interned_event_key(EventAttrKey::ClockSnapshot)
                    .await?,
                Nanoseconds::from(ts).into(),
            );
        }

        attrs.insert(
            client.interned_event_key(EventAttrKey::StreamId).await?,
            BigInt::new_attr_val(event.stream_id.into()),
        );
        attrs.insert(
            client.interned_event_key(EventAttrKey::Id).await?,
            BigInt::new_attr_val(event.class_properties.id.into()),
        );
        if let Some(ll) = event.class_properties.log_level {
            attrs.insert(
                client.interned_event_key(EventAttrKey::LogLevel).await?,
                format!("{ll:?}").to_lowercase().into(),
            );
        }

        const EMPTY_PREFIX: &str = "";
        let common_context = event
            .properties
            .common_context
            .as_ref()
            .map(|f| field_to_attr(f, EMPTY_PREFIX, false, false))
            .transpose()?
            .unwrap_or_default();
        for (k, v) in common_context.into_iter() {
            attrs.insert(
                client
                    .interned_event_key(EventAttrKey::CommonContext(k.into()))
                    .await?,
                v,
            );
        }

        let specific_context = event
            .properties
            .specific_context
            .as_ref()
            .map(|f| field_to_attr(f, EMPTY_PREFIX, false, false))
            .transpose()?
            .unwrap_or_default();
        for (k, v) in specific_context.into_iter() {
            attrs.insert(
                client
                    .interned_event_key(EventAttrKey::SpecificContext(k.into()))
                    .await?,
                v,
            );
        }

        let packet_context = event
            .properties
            .packet_context
            .as_ref()
            .map(|f| field_to_attr(f, EMPTY_PREFIX, false, false))
            .transpose()?
            .unwrap_or_default();
        for (k, v) in packet_context.into_iter() {
            attrs.insert(
                client
                    .interned_event_key(EventAttrKey::PacketContext(k.into()))
                    .await?,
                v,
            );
        }

        let event_fields = event
            .properties
            .payload
            .as_ref()
            .map(|f| {
                field_to_attr(
                    f,
                    EMPTY_PREFIX,
                    true, // auto_map_interaction_fields,
                    is_reserved_event,
                )
            })
            .transpose()?
            .unwrap_or_default();
        for (k, v) in event_fields.into_iter() {
            attrs.insert(
                client
                    .interned_event_key(EventAttrKey::Field(k.into()))
                    .await?,
                v,
            );
        }

        Ok(Self { attrs })
    }

    pub fn attr_kvs(&self) -> Vec<(InternedAttrKey, AttrVal)> {
        self.attrs.clone().into_iter().collect()
    }
}

/// Yields a map of <'<prefix>.<possibly.nested.key>', AttrVal>
fn field_to_attr(
    f: &OwnedField,
    prefix: &str,
    auto_map_interaction_fields: bool,
    is_reserved_event: bool,
) -> Result<HashMap<AttrKey, AttrVal>, Error> {
    let gen = FieldToAttrKeysGen::new(prefix, auto_map_interaction_fields, is_reserved_event)?;
    Ok(gen.generate(f))
}

#[derive(Debug)]
struct FieldToAttrKeysGen {
    /// A stack of indices for each nested structure.
    /// We use this to name fields that did not come with a name
    /// since it's allowed in the spec, although unlikely in the wild.
    /// Invariant: len is always >= 1 for the root structure
    anonymous_field_idices_per_nesting_depth: Vec<usize>,

    /// A stack of attr key components built from the field names.
    /// A stack so we can push/pop as we encounter nested structures
    /// mixed inbetween parent container fields.
    /// Invariant: len is always >= 1 for the root structure's key_prefix
    /// Invariant: none of the entries should contain a '.' character
    ///   We're certain ctf-plugins/babeltrace won't produce field names with that character because
    ///   it's not allowed by the spec (must be valid C identifiers)
    attr_key_stack: Vec<String>,

    root_struct_observed: bool,

    /// Whether or not to auto map root-level interaction fields to be
    /// an artificial '.interaction.' structure.
    /// These elevates the producer from having to nest an interaction struct in their data
    /// which is impossible in some cases/implementations
    auto_map_interaction_fields: bool,

    /// True if this is for a modality reserved event.
    /// We'll consider more attr key/val transformations if so.
    is_reserved_event: bool,

    attrs: HashMap<AttrKey, AttrVal>,
}

impl FieldToAttrKeysGen {
    /// Invariant: key_prefix must not end in a '.', this util will handle that based
    /// on compound or singular scalar types
    fn new(
        key_prefix: &str,
        auto_map_interaction_fields: bool,
        is_reserved_event: bool,
    ) -> std::result::Result<Self, Error> {
        if key_prefix.starts_with('.') || key_prefix.ends_with('.') {
            Err(Error::InvalidAttrKeyPrefix)
        } else {
            Ok(Self {
                anonymous_field_idices_per_nesting_depth: vec![0],
                attr_key_stack: vec![key_prefix.to_string()],
                root_struct_observed: false,
                auto_map_interaction_fields,
                is_reserved_event,
                attrs: Default::default(),
            })
        }
    }

    /// Destructure the contents of `root_field`
    /// into its representative set of attr keys and values
    fn generate(mut self, root_field: &OwnedField) -> HashMap<AttrKey, AttrVal> {
        self.generate_inner(root_field);
        self.attrs
    }

    fn generate_inner(&mut self, root_field: &OwnedField) {
        match root_field {
            OwnedField::Scalar(name, scalar) => match self.handle_scalar_field(name, scalar) {
                ScalarFieldAttrKeyVal::Single(kv) => {
                    self.attrs.insert(kv.0, kv.1);
                }
                ScalarFieldAttrKeyVal::Double(kv, extra_kv) => {
                    self.attrs.insert(kv.0, kv.1);
                    self.attrs.insert(extra_kv.0, extra_kv.1);
                }
            },
            OwnedField::Structure(name, fields) => {
                self.begin_nested_struture(name);

                // Recurse on down each field
                for f in fields.iter() {
                    self.generate_inner(f);
                }

                self.end_nested_structure();
            }
        }
    }

    fn handle_scalar_field(
        &mut self,
        field_name: &Option<String>,
        s: &ScalarField,
    ) -> ScalarFieldAttrKeyVal {
        let k = self.attr_key_for_field_name(field_name);
        // Enums get an extra `.label` attr
        match s {
            ScalarField::UnsignedEnumeration(_, labels)
            | ScalarField::SignedEnumeration(_, labels) => enum_label_attr(&k, labels)
                .map(|extra_kv| {
                    ScalarFieldAttrKeyVal::Double(
                        (AttrKey::new(k.clone()), scalar_field_to_val(s)),
                        extra_kv,
                    )
                })
                .unwrap_or_else(|| {
                    ScalarFieldAttrKeyVal::Single((AttrKey::new(k.clone()), scalar_field_to_val(s)))
                }),
            _ => {
                if self.auto_map_interaction_fields {
                    if ReservedAttrKey::TimelineId.matches_key(&k) {
                        if let ScalarField::String(tid) = s {
                            match tid.parse::<Uuid>() {
                                Ok(tid) => {
                                    return
                                        ScalarFieldAttrKeyVal::Single((AttrKey::new(
                                                    ReservedAttrKey::TimelineId.to_modality_key()
                                                    .to_string()), AttrVal::TimelineId(Box::new(tid.into()))))
                                }
                                Err(e) => warn!("Failed to auto map interaction field as timeline ID UUID type. {e}"),
                            }
                        } else {
                            warn!("Mapping interaction remote timeline ID requires a string type");
                        }
                    } else if ReservedAttrKey::LogicalTime.matches_key(&k) {
                        if let ScalarField::String(t) = s {
                            match t.parse::<LogicalTime>() {
                                Ok(t) => {
                                    return
                                        ScalarFieldAttrKeyVal::Single((AttrKey::new(
                                                    ReservedAttrKey::LogicalTime.to_modality_key()
                                                    .to_string()), AttrVal::LogicalTime(t)))
                                }
                                Err(e) => warn!("Failed to auto map interaction field as timeline ID UUID type. {e:?}"),
                            }
                        } else {
                            warn!("Mapping interaction remote logical time requires a string type");
                        }
                    } else if ReservedAttrKey::Timestamp.matches_key(&k) {
                        if let ScalarField::UnsignedInteger(t) = s {
                            return ScalarFieldAttrKeyVal::Single((
                                AttrKey::new(
                                    ReservedAttrKey::Timestamp.to_modality_key().to_string(),
                                ),
                                AttrVal::Timestamp((*t).into()),
                            ));
                        } else {
                            warn!("Mapping interaction remote timestamp requires a u64 type");
                        }
                    } else if ReservedAttrKey::Nonce.matches_key(&k) {
                        return ScalarFieldAttrKeyVal::Single((
                            AttrKey::new(ReservedAttrKey::Nonce.to_modality_key().to_string()),
                            scalar_field_to_val(s),
                        ));
                    }
                }

                if self.is_reserved_event {
                    if ReservedAttrKey::MutatorId.matches_key(&k) {
                        if let ScalarField::String(id) = s {
                            match id.parse::<Uuid>() {
                                Ok(id) => {
                                    return
                                        ScalarFieldAttrKeyVal::Single((AttrKey::new(
                                                    ReservedAttrKey::MutatorId.to_modality_key()
                                                    .to_string()), uuid_to_integer_attr_val(&id) ))
                                }
                                Err(e) => warn!("Failed to auto map reserved field as mutator ID UUID type. {e}"),
                            }
                        } else {
                            warn!("Mapping reserved mutator ID requires a string type");
                        }
                    } else if ReservedAttrKey::MutationId.matches_key(&k) {
                        if let ScalarField::String(id) = s {
                            match id.parse::<Uuid>() {
                                Ok(id) => {
                                    return
                                        ScalarFieldAttrKeyVal::Single((AttrKey::new(
                                                    ReservedAttrKey::MutationId.to_modality_key()
                                                    .to_string()), uuid_to_integer_attr_val(&id) ))
                                }
                                Err(e) => warn!("Failed to auto map reserved field as mutation ID UUID type. {e}"),
                            }
                        } else {
                            warn!("Mapping reserved mutation ID requires a string type");
                        }
                    } else if ReservedAttrKey::MutationSuccess.matches_key(&k) {
                        let maybe_success = match s {
                            ScalarField::Bool(val) => Some(*val),
                            ScalarField::UnsignedInteger(val) => Some(*val != 0),
                            ScalarField::SignedInteger(val) => Some(*val != 0),
                            _ => None,
                        };
                        if let Some(success) = maybe_success {
                            return ScalarFieldAttrKeyVal::Single((
                                AttrKey::new(
                                    ReservedAttrKey::MutationSuccess
                                        .to_modality_key()
                                        .to_string(),
                                ),
                                success.into(),
                            ));
                        } else {
                            warn!("Mapping reserved mutation success requires a boolean or integer type");
                        }
                    }
                }

                ScalarFieldAttrKeyVal::Single((AttrKey::new(k), scalar_field_to_val(s)))
            }
        }
    }

    /// Get the fully qualified attr key for the given field name.
    ///
    /// The key is returned as a string so the caller may do additional things
    /// like join with `.label` in the case of enum fields.
    fn attr_key_for_field_name(&mut self, field_name: &Option<String>) -> String {
        // TODO - make this lessy stringy/allocation-heavy
        let key_suffix = self.resolve_field_name(field_name);
        self.attr_key_stack
            .iter()
            .filter(|k| !k.is_empty())
            .cloned()
            .chain(std::iter::once(key_suffix))
            .collect::<Vec<String>>()
            .join(".")
    }

    /// If the field name is none, generate the next anonymous field name
    /// at the current nesting depth, otherwise return the provided name.
    fn resolve_field_name(&mut self, field_name: &Option<String>) -> String {
        if let Some(n) = field_name {
            n.to_string()
        } else {
            // Safety: this impl ensures self.anonymous_field_idices_per_nesting_depth.len() >= 1
            let nesting_depth = self.anonymous_field_idices_per_nesting_depth.len() - 1;
            let n = format!(
                "anonymous_{}",
                self.anonymous_field_idices_per_nesting_depth[nesting_depth]
            );
            self.anonymous_field_idices_per_nesting_depth[nesting_depth] += 1;
            n
        }
    }

    /// Push down a new level of structure nesting.
    fn begin_nested_struture(&mut self, field_name: &Option<String>) {
        // We intentionally don't generate anonymous component for the
        // root-level structure, normally it's called 'fields' (implied by babeltrace/ctf-plugins)
        // but we flatten that one out.
        if !self.root_struct_observed {
            self.root_struct_observed = true;
            return;
        }

        // Push on the next attr key component, either provided, or
        // anonymous
        //
        let name = self.resolve_field_name(field_name);
        self.attr_key_stack.push(name);

        // Make a new anonymous field index for the fields contained
        // within this new structure.
        //
        // Safety: do this after we possibly updated the current nesting_depth's
        // anonymous index
        self.anonymous_field_idices_per_nesting_depth.push(0);
    }

    /// Mark the end of the current level of structure nesting.
    fn end_nested_structure(&mut self) {
        let _ = self.anonymous_field_idices_per_nesting_depth.pop();
        let _ = self.attr_key_stack.pop();
    }
}

enum ScalarFieldAttrKeyVal {
    // Most ScalarFields will be in this variant
    Single((AttrKey, AttrVal)),
    // Enum ScalarFields get an extre '.label' attr
    Double((AttrKey, AttrVal), (AttrKey, AttrVal)),
}

// NOTE: We don't have a good strategy for arrays/sequences yet, so for now enumeration classes
// with mutliple label mappings will omit the '.label' Attr.
fn enum_label_attr(key_prefix: &str, labels: &BTreeSet<String>) -> Option<(AttrKey, AttrVal)> {
    if labels.len() == 1 {
        labels.iter().next().map(|l| {
            (
                AttrKey::new(format!("{key_prefix}.label")),
                l.to_owned().into(),
            )
        })
    } else {
        None
    }
}

fn scalar_field_to_val(s: &ScalarField) -> AttrVal {
    match s {
        ScalarField::Bool(v) => (*v).into(),
        ScalarField::UnsignedInteger(v) => BigInt::new_attr_val(i128::from(*v)),
        ScalarField::SignedInteger(v) => (*v).into(),
        ScalarField::SinglePrecisionReal(v) => f64::from(v.0).into(),
        ScalarField::DoublePrecisionReal(v) => v.0.into(),
        ScalarField::String(v) => v.clone().into(),
        ScalarField::UnsignedEnumeration(v, _) => BigInt::new_attr_val(i128::from(*v)),
        ScalarField::SignedEnumeration(v, _) => (*v).into(),
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
enum ReservedAttrKey {
    TimelineId,
    LogicalTime,
    Timestamp,
    Nonce,
    MutatorId,
    MutationId,
    MutationSuccess,
}

impl ReservedAttrKey {
    fn matches_key(self, k: &str) -> bool {
        !k.contains(self.to_modality_key()) && k.contains(self.to_ctf_key())
    }

    fn to_ctf_key(self) -> &'static str {
        use ReservedAttrKey::*;
        match self {
            TimelineId => "remote_timeline_id",
            LogicalTime => "remote_logical_time",
            Timestamp => "remote_timestamp",
            Nonce => "remote_nonce",
            MutatorId => "mutator_id",
            MutationId => "mutation_id",
            MutationSuccess => "mutation_success",
        }
    }

    fn to_modality_key(self) -> &'static str {
        use ReservedAttrKey::*;
        match self {
            TimelineId => "interaction.remote_timeline_id",
            LogicalTime => "interaction.remote_logical_time",
            Timestamp => "interaction.remote_timestamp",
            Nonce => "interaction.remote_nonce",
            MutatorId => "mutator.id",
            MutationId => "mutation.id",
            MutationSuccess => "mutation.success",
        }
    }
}

fn uuid_to_integer_attr_val(u: &Uuid) -> AttrVal {
    i128::from_le_bytes(*u.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // {
    //   l0_f0: bool,               == <prefix>.l0_f0 = true
    //   anonymous_0: u64,          == <prefix>.anonymous_0 = 0
    //   l0_f1: String,             == <prefix>.l0_f1 = "blah"
    //   l0_s0: struct {
    //     anonymous_0: bool,       == <prefix>.l0_s0.anonymous_0 = false
    //     l1_f0: i64,              == <prefix>.l0_s0.l1_f0 = -1
    //     anonymous_1: struct {
    //       l2_f0: String,         == <prefix>.l0_s0.anonymous_1.l2_f0 = "blah"
    //       anonymous_0: bool,     == <prefix>.l0_s0.anonymous_1.anonymous_0 = true
    //       anonymous_1: u64,      == <prefix>.l0_s0.anonymous_1.anonymous_1 = 2
    //     }
    //     anonymous_2: i64,        == <prefix>.l0_s0.anonymous_2 = 3
    //     l1_f1: String,           == <prefix>.l0_s0.l1_f1 = "foo"
    //   },
    //   l0_f2: i64,                == <prefix>.l0_f2 = -2
    //   anonymous_1: bool,         == <prefix>.anonymous_1 = false
    // }
    fn messy_event_structure() -> OwnedField {
        use OwnedField::*;
        use ScalarField::*;
        Structure(
            None, // Root structure never has a name
            vec![
                Scalar("l0_f0".to_string().into(), Bool(true)),
                Scalar(None, UnsignedInteger(0)),
                Scalar("l0_f1".to_string().into(), String("blah".to_string())),
                Structure(
                    "l0_s0".to_string().into(),
                    vec![
                        Scalar(None, Bool(false)),
                        Scalar("l1_f0".to_string().into(), SignedInteger(-1)),
                        Structure(
                            None,
                            vec![
                                Scalar("l2_f0".to_string().into(), String("blah".to_string())),
                                Scalar(None, Bool(true)),
                                Scalar(None, UnsignedInteger(2)),
                            ],
                        ),
                        Scalar(None, SignedInteger(3)),
                        Scalar("l1_f1".to_string().into(), String("foo".to_string())),
                    ],
                ),
                Scalar("l0_f2".to_string().into(), SignedInteger(-2)),
                Scalar(None, Bool(false)),
                Scalar(
                    "remote_timeline_id".to_string().into(),
                    String("d1118896-314e-45f0-ae50-18a38786d957".to_string()),
                ),
                Scalar("remote_nonce".to_string().into(), UnsignedInteger(8)),
                Scalar(
                    "mutator_id".to_string().into(),
                    String("d1118891-314e-45f0-ae50-18a38786d957".to_string()),
                ),
                Scalar(
                    "mutation_id".to_string().into(),
                    String("d1118892-314e-45f0-ae50-18a38786d957".to_string()),
                ),
                Scalar("mutation_success".to_string().into(), UnsignedInteger(1)),
            ],
        )
    }

    #[test]
    fn attr_key_gen_mixed_nested_structs() {
        let root = messy_event_structure();
        let gen = FieldToAttrKeysGen::new("some.prefix", true, true).unwrap();
        let mut attrs = gen.generate(&root).into_iter().collect::<Vec<(_, _)>>();
        attrs.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
        assert_eq!(
            attrs,
            vec![
                (
                    AttrKey::new("interaction.remote_nonce".to_owned()),
                    BigInt::new_attr_val(8)
                ),
                (
                    AttrKey::new("interaction.remote_timeline_id".to_owned()),
                    AttrVal::TimelineId(Box::new(
                        "d1118896-314e-45f0-ae50-18a38786d957"
                            .parse::<Uuid>()
                            .unwrap()
                            .into()
                    )),
                ),
                (
                    AttrKey::new("mutation.id".to_owned()),
                    BigInt::new_attr_val(116772292640754019124460142024662192593)
                ),
                (AttrKey::new("mutation.success".to_owned()), true.into()),
                (
                    AttrKey::new("mutator.id".to_owned()),
                    BigInt::new_attr_val(116772292640754019124460142024645415377)
                ),
                (
                    AttrKey::new("some.prefix.anonymous_0".to_owned()),
                    BigInt::new_attr_val(0)
                ),
                (
                    AttrKey::new("some.prefix.anonymous_1".to_owned()),
                    false.into()
                ),
                (AttrKey::new("some.prefix.l0_f0".to_owned()), true.into()),
                (
                    AttrKey::new("some.prefix.l0_f1".to_owned()),
                    "blah".to_string().into()
                ),
                (
                    AttrKey::new("some.prefix.l0_f2".to_owned()),
                    AttrVal::from(-2_i64)
                ),
                (
                    AttrKey::new("some.prefix.l0_s0.anonymous_0".to_owned()),
                    false.into()
                ),
                (
                    AttrKey::new("some.prefix.l0_s0.anonymous_1.anonymous_0".to_owned()),
                    true.into()
                ),
                (
                    AttrKey::new("some.prefix.l0_s0.anonymous_1.anonymous_1".to_owned()),
                    BigInt::new_attr_val(2)
                ),
                (
                    AttrKey::new("some.prefix.l0_s0.anonymous_1.l2_f0".to_owned()),
                    "blah".to_string().into()
                ),
                (
                    AttrKey::new("some.prefix.l0_s0.anonymous_2".to_owned()),
                    3_i64.into()
                ),
                (
                    AttrKey::new("some.prefix.l0_s0.l1_f0".to_owned()),
                    AttrVal::from(-1_i64)
                ),
                (
                    AttrKey::new("some.prefix.l0_s0.l1_f1".to_owned()),
                    "foo".to_string().into()
                ),
            ]
        );
    }

    #[test]
    fn attr_key_gen_smoke() {
        assert!(FieldToAttrKeysGen::new(".asdf", false, false).is_err());
        assert!(FieldToAttrKeysGen::new("asdf.", false, false).is_err());
    }
}
