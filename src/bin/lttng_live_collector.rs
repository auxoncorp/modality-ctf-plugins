#![deny(warnings, clippy::all)]

use babeltrace2_sys::{CtfPluginSourceLttnLiveInitParams, CtfStream, RunStatus};
use clap::Parser;
use modality_api::types::TimelineId;
use modality_ctf::{
    config::AttrKeyRename,
    prelude::*,
    tracing::try_init_tracing_subscriber,
    types::{RetryDurationUs, SessionNotFoundAction},
};
use modality_ingest_client::IngestClient;
use socket2::{Domain, Socket, Type};
use std::collections::HashMap;
use std::ffi::CString;
use std::time::Duration;
use std::{net, thread};
use thiserror::Error;
use tracing::{debug, warn};
use url::Url;

/// Import CTF trace data from files
#[derive(Parser, Debug, Clone)]
#[clap(version)]
pub struct Opts {
    #[clap(flatten)]
    pub rf_opts: ReflectorOpts,

    #[clap(flatten)]
    pub bt_opts: BabeltraceOpts,

    /// When babeltrace2 needs to retry to run
    /// the graph later, retry in retry-duration-us µs
    /// (default: 100000)
    #[clap(long, name = "duration µs")]
    pub retry_duration_us: Option<RetryDurationUs>,

    /// When the message iterator does not find the specified remote tracing
    /// session (SESSION part of the inputs parameter), do one of the following actions.
    /// * continue (default)
    /// * fail
    /// * end
    #[clap(long, verbatim_doc_comment, name = "action")]
    pub session_not_found_action: Option<SessionNotFoundAction>,

    /// Rename a timeline attribute key as it is being imported. Specify as 'original_key,new_key'
    #[clap(long, name = "original,new", help_heading = "IMPORT CONFIGURATION", value_parser = parse_attr_key_rename)]
    pub rename_timeline_attr: Vec<AttrKeyRename>,

    /// Rename an event attribute key as it is being imported. Specify as 'original_key,new_key'
    #[clap(long, name = "original,new", help_heading = "IMPORT CONFIGURATION", value_parser = parse_attr_key_rename)]
    pub rename_event_attr: Vec<AttrKeyRename>,

    /// The URL to connect to the LTTng relay daemon.
    ///
    /// Format: net\[4\]://RDHOST\[:RDPORT\]/host/TGTHOST/SESSION
    /// * RDHOST
    ///   LTTng relay daemon’s host name or IP address.
    /// * RDPORT
    ///   LTTng relay daemon’s listening port.
    ///   If not specified, the component uses the default port (5344).
    /// * TGTHOST
    ///   Target’s host name or IP address.
    /// * SESSION
    ///   Name of the LTTng tracing session from which to receive data.
    ///
    /// Example: net://localhost/host/ubuntu-focal/my-kernel-session
    #[clap(verbatim_doc_comment, name = "url")]
    pub url: Option<Url>,
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

    #[error("The URL to connect to the LTTng relay daemon is required.")]
    MissingUrl,

    #[error("The CTF connection was established but the trace doesn't contain any stream data.")]
    EmptyCtfTrace,
}

const LTTNG_RELAYD_DEFAULT_PORT: u16 = 5344;
const RELAYD_QUICK_PING_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

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
    if let Some(retry) = opts.retry_duration_us {
        cfg.plugin.lttng_live.retry_duration_us = retry;
    }
    if let Some(action) = opts.session_not_found_action {
        cfg.plugin.lttng_live.session_not_found_action = action;
    }
    if let Some(url) = opts.url {
        cfg.plugin.lttng_live.url = url.into();
    }

    let mut rename_timeline_attrs = opts.rename_timeline_attr.clone();
    rename_timeline_attrs.extend(cfg.plugin.rename_timeline_attrs.clone());

    let mut rename_event_attrs = opts.rename_event_attr.clone();
    rename_event_attrs.extend(cfg.plugin.rename_event_attrs.clone());

    let url = match cfg.plugin.lttng_live.url.as_ref() {
        Some(url) => url.clone(),
        None => return Err(Error::MissingUrl.into()),
    };

    let retry_duration = Duration::from_micros(cfg.plugin.lttng_live.retry_duration_us.into());

    // Attempt to inform user if we can't connect to remote to provide
    // some help when babeltrace2 can't connect, since its error is just -1
    // and you'd have to turn on logging to really know
    //
    // If session-no-found-action == Continue, then do this indefinately to keep
    // babeltrace2 from erroring out early in cases where the plugin is started
    // before relayd is started.
    'conn_loop: loop {
        if let Ok(relayd_addrs) = url.socket_addrs(|| Some(LTTNG_RELAYD_DEFAULT_PORT)) {
            if !relayd_addrs.is_empty() {
                let addr = relayd_addrs[0];
                let domain = if addr.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                };
                let sock = Socket::new(domain, Type::STREAM, None)?;

                let connected_to_remote = sock
                    .connect_timeout(&addr.into(), RELAYD_QUICK_PING_CONNECT_TIMEOUT)
                    .is_ok();
                let _ = sock.shutdown(net::Shutdown::Both).ok();

                if connected_to_remote {
                    // Host is up
                    break 'conn_loop;
                } else {
                    warn!(
                        "Failed to connect to '{}', the remote host may not be reachable",
                        url
                    );
                }
                if cfg.plugin.lttng_live.session_not_found_action.0
                    != babeltrace2_sys::SessionNotFoundAction::Continue
                {
                    break 'conn_loop;
                } else {
                    // Keep trying
                    thread::sleep(retry_duration);
                }
            }
        } else {
            break 'conn_loop;
        }
    }

    let url_cstring = CString::new(url.to_string().as_bytes())?;
    let params = CtfPluginSourceLttnLiveInitParams::new(
        &url_cstring,
        Some(cfg.plugin.lttng_live.session_not_found_action.into()),
    )?;
    let mut ctf_stream = CtfStream::new(cfg.plugin.log_level.into(), &params)?;

    debug!("Waiting for CTF metadata");

    // Loop until we get some metadata from the relayd
    while !ctf_stream.has_metadata() {
        if interruptor.is_set() {
            return Ok(());
        }

        match ctf_stream.update()? {
            RunStatus::Ok => (),
            RunStatus::TryAgain => {
                thread::sleep(retry_duration);
                continue;
            }
            RunStatus::End => break,
        }
    }

    debug!("Found CTF metadata");

    if ctf_stream.stream_properties().is_empty() {
        return Err(Error::EmptyCtfTrace.into());
    }

    let c =
        IngestClient::connect(&cfg.protocol_parent_url()?, cfg.ingest.allow_insecure_tls).await?;
    let c_authed = c.authenticate(cfg.resolve_auth()?.into()).await?;
    let mut client = Client::new(c_authed, rename_timeline_attrs, rename_event_attrs);

    let props = CtfProperties::new(
        cfg.plugin.run_id,
        cfg.plugin.trace_uuid,
        ctf_stream.trace_properties(),
        ctf_stream.stream_properties(),
        &mut client,
    )
    .await?;

    let mut last_timeline_ordering_val: HashMap<TimelineId, u128> = Default::default();

    let mut additional_timeline_attributes = Vec::with_capacity(
        cfg.ingest
            .timeline_attributes
            .additional_timeline_attributes
            .len(),
    );
    for kv in cfg
        .ingest
        .timeline_attributes
        .additional_timeline_attributes
        .iter()
    {
        additional_timeline_attributes.push((
            client
                .interned_timeline_key(TimelineAttrKey::Custom(kv.0.to_string()))
                .await?,
            kv.1.clone(),
        ));
    }

    let mut override_timeline_attributes = Vec::with_capacity(
        cfg.ingest
            .timeline_attributes
            .override_timeline_attributes
            .len(),
    );
    for kv in cfg
        .ingest
        .timeline_attributes
        .override_timeline_attributes
        .iter()
    {
        override_timeline_attributes.push((
            client
                .interned_timeline_key(TimelineAttrKey::Custom(kv.0.to_string()))
                .await?,
            kv.1.clone(),
        ));
    }

    for (tid, attr_kvs) in props.timelines() {
        let mut attrs = HashMap::new();
        for (k, v) in attr_kvs
            .into_iter()
            .chain(additional_timeline_attributes.clone().into_iter())
            .chain(override_timeline_attributes.clone().into_iter())
        {
            attrs.insert(k, v);
        }

        client.c.open_timeline(tid).await?;
        client.c.timeline_metadata(attrs).await?;
        last_timeline_ordering_val.insert(tid, 0);
    }

    // Loop until user-signaled-exit or server-side-signaled-done
    loop {
        if interruptor.is_set() {
            break;
        }

        match ctf_stream.update()? {
            RunStatus::Ok => (),
            RunStatus::TryAgain => {
                thread::sleep(retry_duration);
                continue;
            }
            RunStatus::End => break,
        }

        for event in ctf_stream.events_chunk() {
            if interruptor.is_set() {
                break;
            }

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
