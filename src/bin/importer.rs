#![deny(warnings, clippy::all)]

use babeltrace2_sys::{CtfIterator, CtfPluginSourceFsInitParams};
use clap::Parser;
use modality_api::types::TimelineId;
use modality_ctf::config::AttrKeyRename;
use modality_ctf::{prelude::*, tracing::try_init_tracing_subscriber};
use modality_ingest_client::IngestClient;
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tracing::warn;

/// Import CTF trace data from files
#[derive(Parser, Debug, Clone)]
#[clap(version)]
pub struct Opts {
    #[clap(flatten)]
    pub rf_opts: ReflectorOpts,

    #[clap(flatten)]
    pub bt_opts: BabeltraceOpts,

    /// Set the name of the trace object that the component creates, overriding the data's trace
    /// name if present
    #[clap(long, name = "trace-name", help_heading = "IMPORT CONFIGURATION")]
    pub trace_name: Option<String>,

    /// Add offset-ns nanoseconds to the offset of all the clock classes that the component creates
    #[clap(long, name = "offset-ns", help_heading = "IMPORT CONFIGURATION")]
    pub clock_class_offset_ns: Option<i64>,

    /// Add offset-s seconds to the offset of all the clock classes that the component creates
    #[clap(long, name = "offset-s", help_heading = "IMPORT CONFIGURATION")]
    pub clock_class_offset_s: Option<i64>,

    /// Force the origin of all clock classes that the component creates to have a Unix epoch origin
    #[clap(long, name = "unix-epoch", help_heading = "IMPORT CONFIGURATION")]
    pub force_clock_class_origin_unix_epoch: Option<bool>,

    /// Rename a timeline attribute key as it is being imported. Specify as 'original_key,new_key'
    #[clap(long, name = "original.tl.attr,new.tl.attr", help_heading = "IMPORT CONFIGURATION", value_parser = parse_attr_key_rename)]
    pub rename_timeline_attr: Vec<AttrKeyRename>,

    /// Rename an event attribute key as it is being imported. Specify as 'original_key,new_key'
    #[clap(long, name = "original.event.attr,new.event.attr", help_heading = "IMPORT CONFIGURATION", value_parser = parse_attr_key_rename)]
    pub rename_event_attr: Vec<AttrKeyRename>,

    /// Path to trace directories
    #[clap(name = "input", help_heading = "IMPORT CONFIGURATION")]
    pub inputs: Vec<PathBuf>,
}

fn parse_attr_key_rename(
    s: &str,
) -> Result<AttrKeyRename, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let pos = s
        .find(',')
        .ok_or_else(|| format!("invalid original,new: no `,` found in `{s}`"))?;
    let original = s[..pos].parse()?;
    let new = s[pos + 1..].parse()?;
    Ok(AttrKeyRename { original, new })
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Ctf(#[from] modality_ctf::error::Error),

    #[error("At least one CTF containing input path is required.")]
    MissingInputs,
}

#[tokio::main]
async fn main() {
    match do_main().await {
        Ok(()) => (),
        Err(e) => {
            eprintln!("{e}");
            let mut cause = e.source();
            while let Some(err) = cause {
                eprintln!("Caused by: {err}");
                cause = err.source();
            }
            std::process::exit(exitcode::SOFTWARE);
        }
    }
}

async fn do_main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();

    try_init_tracing_subscriber()?;

    let intr = Interruptor::new();
    let interruptor = intr.clone();
    ctrlc::set_handler(move || {
        if intr.is_set() {
            // 128 (fatal error signal "n") + 2 (control-c is fatal error signal 2)
            std::process::exit(130);
        } else {
            intr.set();
        }
    })?;

    let mut cfg = CtfConfig::load_merge_with_opts(opts.rf_opts, opts.bt_opts)?;
    if let Some(tn) = opts.trace_name {
        cfg.plugin.import.trace_name = tn.into();
    }
    if let Some(ns) = opts.clock_class_offset_ns {
        cfg.plugin.import.clock_class_offset_ns = ns.into();
    }
    if let Some(s) = opts.clock_class_offset_s {
        cfg.plugin.import.clock_class_offset_s = s.into();
    }
    if let Some(ue) = opts.force_clock_class_origin_unix_epoch {
        cfg.plugin.import.force_clock_class_origin_unix_epoch = ue.into();
    }
    if !opts.inputs.is_empty() {
        cfg.plugin.import.inputs = opts.inputs;
    }

    let mut rename_timeline_attrs = opts.rename_timeline_attr.clone();
    rename_timeline_attrs.extend(cfg.plugin.rename_timeline_attrs.clone());

    let mut rename_event_attrs = opts.rename_event_attr.clone();
    rename_event_attrs.extend(cfg.plugin.rename_event_attrs.clone());

    if cfg.plugin.import.inputs.is_empty() {
        return Err(Error::MissingInputs.into());
    }
    for p in cfg.plugin.import.inputs.iter() {
        if !p.join("metadata").exists() {
            warn!(
                "Input path '{}' does not contain a metadata file",
                p.display()
            );
        }
    }

    let c =
        IngestClient::connect(&cfg.protocol_parent_url()?, cfg.ingest.allow_insecure_tls).await?;
    let c_authed = c.authenticate(cfg.resolve_auth()?.into()).await?;
    let mut client = Client::new(c_authed, rename_timeline_attrs, rename_event_attrs);

    let ctf_params = CtfPluginSourceFsInitParams::try_from(&cfg.plugin.import)?;
    let trace_iter = CtfIterator::new(cfg.plugin.log_level.into(), &ctf_params)?;
    let props = CtfProperties::new(
        cfg.plugin.run_id,
        cfg.plugin.trace_uuid,
        trace_iter.trace_properties(),
        trace_iter.stream_properties(),
        &mut client,
    )
    .await?;

    let mut last_timeline_ordering_val: HashMap<TimelineId, u128> = Default::default();

    if props.streams.is_empty() {
        warn!("The CTF containing input path(s) don't contain any trace data");
    }

    for (tid, attr_kvs) in props.timelines() {
        client.c.open_timeline(tid).await?;
        client.c.timeline_metadata(attr_kvs).await?;
        last_timeline_ordering_val.insert(tid, 0);
    }

    for maybe_event in trace_iter {
        if interruptor.is_set() {
            break;
        }
        let event = maybe_event?;

        let timeline_id = match props.streams.get(&event.stream_id).map(|s| s.timeline_id()) {
            Some(tid) => tid,
            None => {
                warn!(
                    "Dropping event ID {} because it's stream ID was not reported in the metadata",
                    event.class_properties.id
                );
                continue;
            }
        };

        let ordering = match last_timeline_ordering_val.get_mut(&timeline_id) {
            Some(ord) => ord,
            None => {
                warn!(
                    "Dropping event ID {} because it's timeline ID was not registered",
                    event.class_properties.id
                );
                continue;
            }
        };

        let event = CtfEvent::new(&event, &mut client).await?;
        client.c.open_timeline(timeline_id).await?;
        client.c.event(*ordering, event.attr_kvs()).await?;
        *ordering += 1;
        client.c.close_timeline();
    }

    Ok(())
}

/// Plugin descriptor related data, pointers to this data
/// will end up in special linker sections in the binary
/// so libbabeltrace2 can discover it
///
/// TODO: figure out how to work around <https://github.com/rust-lang/rust/issues/47384>
/// For now, this has to be defined in the binary crate for it to work
pub mod proxy_plugin_descriptors {
    use babeltrace2_sys::ffi::*;
    use babeltrace2_sys::proxy_plugin_descriptors::*;

    #[used]
    #[link_section = "__bt_plugin_descriptors"]
    pub static PLUGIN_DESC_PTR: __bt_plugin_descriptor_ptr =
        __bt_plugin_descriptor_ptr(&PLUGIN_DESC);

    #[used]
    #[link_section = "__bt_plugin_component_class_descriptors"]
    pub static SINK_COMP_DESC_PTR: __bt_plugin_component_class_descriptor_ptr =
        __bt_plugin_component_class_descriptor_ptr(&SINK_COMP_DESC);

    #[used]
    #[link_section = "__bt_plugin_component_class_descriptor_attributes"]
    pub static SINK_COMP_CLASS_INIT_ATTR_PTR: __bt_plugin_component_class_descriptor_attribute_ptr =
        __bt_plugin_component_class_descriptor_attribute_ptr(&SINK_COMP_CLASS_INIT_ATTR);

    #[used]
    #[link_section = "__bt_plugin_component_class_descriptor_attributes"]
    pub static SINK_COMP_CLASS_FINI_ATTR_PTR: __bt_plugin_component_class_descriptor_attribute_ptr =
        __bt_plugin_component_class_descriptor_attribute_ptr(&SINK_COMP_CLASS_FINI_ATTR);

    #[used]
    #[link_section = "__bt_plugin_component_class_descriptor_attributes"]
    pub static SINK_COMP_CLASS_GRAPH_CONF_ATTR_PTR:
        __bt_plugin_component_class_descriptor_attribute_ptr =
        __bt_plugin_component_class_descriptor_attribute_ptr(&SINK_COMP_CLASS_GRAPH_CONF_ATTR);
}

pub mod utils_plugin_descriptors {
    use babeltrace2_sys::ffi::*;

    #[link(
        name = "babeltrace-plugin-utils",
        kind = "static",
        modifiers = "+whole-archive"
    )]
    extern "C" {
        pub static __bt_plugin_descriptor_auto_ptr: *const __bt_plugin_descriptor;
    }
}

pub mod ctf_plugin_descriptors {
    use babeltrace2_sys::ffi::*;

    #[link(
        name = "babeltrace-plugin-ctf",
        kind = "static",
        modifiers = "+whole-archive"
    )]
    extern "C" {
        pub static __bt_plugin_descriptor_auto_ptr: *const __bt_plugin_descriptor;
    }
}
