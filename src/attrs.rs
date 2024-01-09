use crate::error::Error;
use async_trait::async_trait;
use derive_more::Display;
use modality_ingest_protocol::InternedAttrKey;

// N.B. maybe we'll expand on this to separate out the various types
// of ctf-plugins producers (lttng/ctf-plugins/barectf/python-logger-backend/etc).
// Probably relevant for inferring a communications/interactions synthesis pattern.
pub(crate) const TIMELINE_INGEST_SOURCE_VAL: &str = "ctf-plugins";

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
pub enum TimelineAttrKey {
    #[display(fmt = "timeline.name")]
    Name,
    #[display(fmt = "timeline.description")]
    Description,
    #[display(fmt = "timeline.run_id")]
    RunId,
    #[display(fmt = "timeline.time_domain")]
    TimeDomain,
    #[display(fmt = "timeline.clock_style")]
    ClockStyle,
    #[display(fmt = "timeline.ingest_source")]
    IngestSource,

    #[display(fmt = "timeline.internal.ctf.trace.name")]
    TraceName,
    #[display(fmt = "timeline.internal.ctf.trace.uuid")]
    TraceUuid,
    #[display(fmt = "timeline.internal.ctf.trace.stream_count")]
    TraceStreamCount,
    #[display(fmt = "timeline.internal.ctf.trace.env.{_0}")]
    TraceEnv(String),

    #[display(fmt = "timeline.internal.ctf.stream.id")]
    StreamId,
    #[display(fmt = "timeline.internal.ctf.stream.name")]
    StreamName,
    #[display(fmt = "timeline.internal.ctf.stream.clock.frequency")]
    StreamClockFreq,
    #[display(fmt = "timeline.internal.ctf.stream.clock.offset_seconds")]
    StreamClockOffsetSeconds,
    #[display(fmt = "timeline.internal.ctf.stream.clock.offset_cycles")]
    StreamClockOffsetCycles,
    #[display(fmt = "timeline.internal.ctf.stream.clock.precision")]
    StreamClockPrecision,
    #[display(fmt = "timeline.internal.ctf.stream.clock.unix_epoch_origin")]
    StreamClockUnixEpoch,
    #[display(fmt = "timeline.internal.ctf.stream.clock.name")]
    StreamClockName,
    #[display(fmt = "timeline.internal.ctf.stream.clock.description")]
    StreamClockDesc,
    #[display(fmt = "timeline.internal.ctf.stream.clock.uuid")]
    StreamClockUuid,

    #[display(fmt = "timeline.internal.config.merge_stream_id")]
    MergeStreamId,

    #[display(fmt = "timeline.{_0}")]
    Custom(String),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
pub enum EventAttrKey {
    #[display(fmt = "event.name")]
    Name,
    #[display(fmt = "event.timestamp")]
    Timestamp,

    #[display(fmt = "event.internal.ctf.stream_id")]
    StreamId,
    #[display(fmt = "event.internal.ctf.id")]
    Id,
    #[display(fmt = "event.internal.ctf.log_level")]
    LogLevel,
    #[display(fmt = "event.internal.ctf.clock_snapshot")]
    ClockSnapshot,

    #[display(fmt = "event.internal.ctf.common_context.{_0}")]
    CommonContext(String),
    #[display(fmt = "event.internal.ctf.specific_context.{_0}")]
    SpecificContext(String),
    #[display(fmt = "event.internal.ctf.packet_context.{_0}")]
    PacketContext(String),

    #[display(fmt = "event.{_0}")]
    Field(String),
}

#[async_trait]
pub trait TimelineAttrKeyExt {
    async fn interned_key(&mut self, key: TimelineAttrKey) -> Result<InternedAttrKey, Error>;
}

#[async_trait]
pub trait EventAttrKeyExt {
    async fn interned_key(&mut self, key: EventAttrKey) -> Result<InternedAttrKey, Error>;
}
