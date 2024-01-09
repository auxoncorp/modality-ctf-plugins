use crate::client::Client;
use crate::error::Error;
use babeltrace2_sys::{StreamId, StreamProperties, TraceProperties};
use modality_api::{AttrVal, TimelineId};
use modality_ingest_protocol::InternedAttrKey;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub use stream::CtfStreamProperties;
pub use trace::CtfTraceProperties;

pub(crate) mod stream;
pub(crate) mod trace;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CtfProperties {
    pub trace: CtfTraceProperties,
    pub streams: BTreeMap<StreamId, CtfStreamProperties>,
}

impl CtfProperties {
    pub async fn new(
        run_id: Option<Uuid>,
        trace_uuid_override: Option<Uuid>,
        t: &TraceProperties,
        s: &BTreeSet<StreamProperties>,
        client: &mut Client,
    ) -> Result<Self, Error> {
        // TimelineIds are a composite of the trace UUID and the stream ID
        // Use the override if present, otherwise use the trace's UUID
        // Fallback to making a new random UUID
        let trace_uuid = trace_uuid_override.or(t.uuid).unwrap_or_else(Uuid::new_v4);

        let stream_count = s.len() as u64;
        let trace =
            CtfTraceProperties::new(run_id, trace_uuid_override, stream_count, t, client).await?;
        let mut streams = BTreeMap::default();
        for stream in s.iter() {
            streams.insert(
                stream.id,
                CtfStreamProperties::new(&trace_uuid, stream, client).await?,
            );
        }
        Ok(Self { trace, streams })
    }

    #[allow(clippy::type_complexity)]
    pub fn timelines(
        &self,
    ) -> Box<dyn Iterator<Item = (StreamId, TimelineId, Vec<(InternedAttrKey, AttrVal)>)> + '_>
    {
        let trace_attr_kvs = self.trace.attr_kvs();
        Box::new(self.streams.iter().map(move |(stream_id, p)| {
            let mut attr_kvs = p.attr_kvs();
            attr_kvs.extend_from_slice(&trace_attr_kvs);
            (*stream_id, p.timeline_id(), attr_kvs)
        }))
    }
}
