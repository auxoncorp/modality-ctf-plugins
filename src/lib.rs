//! # Overview
//!
//! Conceptually CTF data is organized as followed (from babeltrace2 docs):
//! * Trace (all the specified physical CTF traces must belong to the same logical CTF trace)
//!   - One or more streams (timelines)
//!     * Series of events
//!
//! ![trace-structure](https://babeltrace.org/docs/v2.0/libbabeltrace2/trace-structure.png)
//!
//! # Attrs Mappings
//!
//! Trace Attrs
//! * timeline.internal.ctf.trace.name
//! * timeline.internal.ctf.trace.uuid
//! * timeline.internal.ctf.trace.stream_count
//! * timeline.internal.ctf.trace.env.`<fields>`
//!
//! Stream Attrs
//! * timeline.internal.ctf.stream.id
//! * timeline.internal.ctf.stream.name
//!   - timeline.name
//! * timeline.internal.ctf.stream.clock.frequency
//! * timeline.internal.ctf.stream.clock.offset_seconds
//! * timeline.internal.ctf.stream.clock.offset_cycles
//! * timeline.internal.ctf.stream.clock.precision
//! * timeline.internal.ctf.stream.clock.unix_epoch_origin
//! * timeline.internal.ctf.stream.clock.name
//! * timeline.internal.ctf.stream.clock.description
//! * timeline.internal.ctf.stream.clock.uuid
//!   - timeline.time_domain
//! * timeline.ingest_source
//!
//! Event Attrs
//! * event.internal.ctf.stream_id
//! * event.internal.ctf.id
//! * event.name
//! * event.internal.ctf.log_level
//! * event.internal.ctf.clock_snapshot
//!   - event.timestamp
//! * event.internal.ctf.common_context.<possibly.nested.fields>
//! * event.internal.ctf.specific_context.<possibly.nested.fields>
//! * event.internal.ctf.packet_context.<possibly.nested.fields>
//! * event.<possibly.nested.fields>
//!
//! # Mapping Conventions
//!
//! ## Enumeration classes
//!
//! CTF signed/unsigned enumeration classes will be given at Attr for the discriminant value
//! and possibly one or more Attrs for the label mappings.
//! Values are allowed to have no label mapping, or have many label
//! mappings (values are allowed to overlap).
//!
//! NOTE: We don't have a good strategy for arrays/sequences yet, so for now enumeration classes
//! with mutliple label mappings will omit the `.label` Attr.
//!
//! Example: `my_enum` is an enumeration class with value 5 and single label mapping "RUNNING"
//! * event.my_enum = 5
//! * event.my_enum.label = "RUNNING"
//!
//! Example: `my_enum` is an enumeration class with value 1 and no label mapping
//! * event.my_enum = 5
#![deny(warnings, clippy::all)]

pub mod attrs;
pub mod auth;
pub mod client;
pub mod config;
pub mod error;
pub mod event;
pub mod opts;
pub mod prelude;
pub mod properties;
pub mod tracing;
pub mod types;
