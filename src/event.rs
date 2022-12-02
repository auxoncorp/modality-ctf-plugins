use crate::attrs::EventAttrKey;
use crate::client::Client;
use crate::error::Error;
use babeltrace2_sys::{OwnedEvent, OwnedField, ScalarField};
use modality_api::{AttrKey, AttrVal, BigInt, Nanoseconds};
use modality_ingest_protocol::InternedAttrKey;
use std::collections::{BTreeSet, HashMap};
use tracing::warn;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CtfEvent {
    attrs: HashMap<InternedAttrKey, AttrVal>,
}

impl CtfEvent {
    pub async fn new(event: &OwnedEvent, client: &mut Client) -> Result<Self, Error> {
        let mut attrs = HashMap::new();

        if let Some(n) = event.class_properties.name.as_ref() {
            attrs.insert(
                client.interned_event_key(EventAttrKey::Name).await?,
                n.to_owned().into(),
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
                format!("{:?}", ll).to_lowercase().into(),
            );
        }

        const EMPTY_PREFIX: &str = "";
        let common_context = event
            .properties
            .common_context
            .as_ref()
            .map(|f| field_to_attr(EMPTY_PREFIX, f))
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
            .map(|f| field_to_attr(EMPTY_PREFIX, f))
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
            .map(|f| field_to_attr(EMPTY_PREFIX, f))
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
            .map(|f| field_to_attr(EMPTY_PREFIX, f))
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
fn field_to_attr(prefix: &str, f: &OwnedField) -> Result<HashMap<AttrKey, AttrVal>, Error> {
    let gen = FieldToAttrKeysGen::new(prefix)?;
    Ok(gen.generate(f))
}

#[derive(Debug)]
struct FieldToAttrKeysGen {
    // A stack of indices for each nested structure.
    // We use this to name fields that did not come with a name
    // since it's allowed in the spec, although unlikely in the wild.
    // Invariant: len is always >= 1 for the root structure
    anonymous_field_idices_per_nesting_depth: Vec<usize>,

    // A stack of attr key components built from the field names.
    // A stack so we can push/pop as we encounter nested structures
    // mixed inbetween parent container fields.
    // Invariant: len is always >= 1 for the root structure's key_prefix
    // Invariant: none of the entries should contain a '.' character
    //   We're certain ctf-plugins/babeltrace won't produce field names with that character because
    //   it's not allowed by the spec (must be valid C identifiers)
    attr_key_stack: Vec<String>,

    root_struct_observed: bool,

    attrs: HashMap<AttrKey, AttrVal>,
}

impl FieldToAttrKeysGen {
    /// Invariant: key_prefix must not end in a '.', this util will handle that based
    /// on compound or singular scalar types
    fn new(key_prefix: &str) -> std::result::Result<Self, Error> {
        if key_prefix.starts_with('.') || key_prefix.ends_with('.') {
            Err(Error::InvalidAttrKeyPrefix)
        } else {
            Ok(Self {
                anonymous_field_idices_per_nesting_depth: vec![0],
                attr_key_stack: vec![key_prefix.to_string()],
                root_struct_observed: false,
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
            _ => ScalarFieldAttrKeyVal::Single((AttrKey::new(k), scalar_field_to_val(s))),
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
                AttrKey::new(format!("{}.label", key_prefix)),
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
            ],
        )
    }

    #[test]
    fn attr_key_gen_mixed_nested_structs() {
        let root = messy_event_structure();
        let gen = FieldToAttrKeysGen::new("some.prefix").unwrap();
        let mut attrs = gen.generate(&root).into_iter().collect::<Vec<(_, _)>>();
        attrs.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
        assert_eq!(
            attrs,
            vec![
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
        assert!(FieldToAttrKeysGen::new(".asdf").is_err());
        assert!(FieldToAttrKeysGen::new("asdf.").is_err());
    }
}
