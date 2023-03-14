use crate::attrs::{TimelineAttrKey, TIMELINE_INGEST_SOURCE_VAL};
use crate::client::Client;
use crate::error::Error;
use babeltrace2_sys::StreamProperties;
use modality_api::{AttrVal, BigInt, TimelineId};
use modality_ingest_protocol::InternedAttrKey;
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

const CLOCK_STYLE_RELATIVE: &str = "relative";
const CLOCK_STYLE_UTC: &str = "utc";

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CtfStreamProperties {
    timeline_id: TimelineId,
    attrs: HashMap<InternedAttrKey, AttrVal>,
}

impl CtfStreamProperties {
    pub async fn new(
        trace_uuid: &Uuid,
        s: &StreamProperties,
        client: &mut Client,
    ) -> Result<Self, Error> {
        let mut attrs = HashMap::default();
        let timeline_id = TimelineId::from(Uuid::new_v5(trace_uuid, &s.id.to_le_bytes()));

        // The stream name produced by babeltrace is the path to the stream file within
        // a trace. This is rather ugly and hard to write specs against
        // (event @ "/some annoyingly/long path to/a trace/stream_0").
        // So instead of making a timeline name directly from a stream name, we first
        // attempt to use the file name component if possible, and fallback to
        // "stream{stream_id}" which is the default naming convention used within
        // the LTTng ecosystem when not provided by babeltrace.
        let stream_name_from_path = s.name.as_ref().and_then(|sn| {
            let p = Path::new(sn);
            if p.exists() {
                p.file_name().map(|s| s.to_string_lossy())
            } else {
                None
            }
        });
        let stream_name = stream_name_from_path
            .map(|s| s.to_string())
            .or_else(|| s.name.clone())
            .unwrap_or_else(|| format!("stream{}", s.id));

        attrs.insert(
            client
                .interned_timeline_key(TimelineAttrKey::Description)
                .await?,
            format!("CTF stream '{stream_name}'").into(),
        );
        attrs.insert(
            client.interned_timeline_key(TimelineAttrKey::Name).await?,
            stream_name.clone().into(),
        );

        attrs.insert(
            client
                .interned_timeline_key(TimelineAttrKey::StreamName)
                .await?,
            stream_name.into(),
        );
        attrs.insert(
            client
                .interned_timeline_key(TimelineAttrKey::StreamId)
                .await?,
            BigInt::new_attr_val(s.id.into()),
        );

        attrs.insert(
            client
                .interned_timeline_key(TimelineAttrKey::IngestSource)
                .await?,
            TIMELINE_INGEST_SOURCE_VAL.into(),
        );

        if let Some(c) = &s.clock {
            attrs.insert(
                client
                    .interned_timeline_key(TimelineAttrKey::StreamClockFreq)
                    .await?,
                BigInt::new_attr_val(c.frequency.into()),
            );
            attrs.insert(
                client
                    .interned_timeline_key(TimelineAttrKey::StreamClockOffsetSeconds)
                    .await?,
                c.offset_seconds.into(),
            );
            attrs.insert(
                client
                    .interned_timeline_key(TimelineAttrKey::StreamClockOffsetCycles)
                    .await?,
                BigInt::new_attr_val(c.offset_cycles.into()),
            );
            attrs.insert(
                client
                    .interned_timeline_key(TimelineAttrKey::StreamClockPrecision)
                    .await?,
                BigInt::new_attr_val(c.precision.into()),
            );
            attrs.insert(
                client
                    .interned_timeline_key(TimelineAttrKey::StreamClockUnixEpoch)
                    .await?,
                c.unix_epoch_origin.into(),
            );
            if let Some(cn) = &c.name {
                attrs.insert(
                    client
                        .interned_timeline_key(TimelineAttrKey::StreamClockName)
                        .await?,
                    cn.to_owned().into(),
                );
            }
            if let Some(cd) = &c.description {
                attrs.insert(
                    client
                        .interned_timeline_key(TimelineAttrKey::StreamClockDesc)
                        .await?,
                    cd.to_owned().into(),
                );
            }
            if let Some(cid) = &c.uuid {
                attrs.insert(
                    client
                        .interned_timeline_key(TimelineAttrKey::StreamClockUuid)
                        .await?,
                    cid.to_string().into(),
                );
                attrs.insert(
                    client
                        .interned_timeline_key(TimelineAttrKey::TimeDomain)
                        .await?,
                    cid.to_string().into(),
                );
            }
            attrs.insert(
                client
                    .interned_timeline_key(TimelineAttrKey::ClockStyle)
                    .await?,
                String::from(if c.unix_epoch_origin {
                    CLOCK_STYLE_UTC
                } else {
                    CLOCK_STYLE_RELATIVE
                })
                .into(),
            );
        }

        Ok(Self { timeline_id, attrs })
    }

    pub fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    pub fn attr_kvs(&self) -> Vec<(InternedAttrKey, AttrVal)> {
        self.attrs.clone().into_iter().collect()
    }
}
