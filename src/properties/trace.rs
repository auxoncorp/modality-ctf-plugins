use crate::attrs::TimelineAttrKey;
use crate::client::Client;
use crate::error::Error;
use babeltrace2_sys::{EnvValue, TraceProperties};
use modality_api::{AttrVal, BigInt};
use modality_ingest_protocol::InternedAttrKey;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CtfTraceProperties {
    attrs: HashMap<InternedAttrKey, AttrVal>,
}

impl CtfTraceProperties {
    pub async fn new(
        run_id: Option<Uuid>,
        trace_uuid_override: Option<Uuid>,
        stream_count: u64,
        t: &TraceProperties,
        client: &mut Client,
    ) -> Result<Self, Error> {
        let mut attrs = HashMap::default();

        attrs.insert(
            client.interned_timeline_key(TimelineAttrKey::RunId).await?,
            run_id.unwrap_or_else(Uuid::new_v4).to_string().into(),
        );

        if let Some(uuid) = trace_uuid_override.or(t.uuid) {
            attrs.insert(
                client
                    .interned_timeline_key(TimelineAttrKey::TraceUuid)
                    .await?,
                uuid.to_string().into(),
            );
        }

        attrs.insert(
            client
                .interned_timeline_key(TimelineAttrKey::TraceStreamCount)
                .await?,
            BigInt::new_attr_val(stream_count.into()),
        );

        if let Some(name) = t.name.as_ref() {
            attrs.insert(
                client.interned_timeline_key(TimelineAttrKey::Name).await?,
                name.to_owned().into(),
            );
            attrs.insert(
                client
                    .interned_timeline_key(TimelineAttrKey::TraceName)
                    .await?,
                name.to_owned().into(),
            );
        }

        if let Some(e) = &t.env {
            for (k, v) in e.entries() {
                let key = TimelineAttrKey::TraceEnv(k.to_owned());
                attrs.insert(
                    client.interned_timeline_key(key).await?,
                    match v {
                        EnvValue::Integer(int) => AttrVal::Integer(*int),
                        EnvValue::String(s) => AttrVal::String(s.clone()),
                    },
                );
            }
        }

        Ok(Self { attrs })
    }

    pub fn attr_kvs(&self) -> Vec<(InternedAttrKey, AttrVal)> {
        self.attrs.clone().into_iter().collect()
    }
}
