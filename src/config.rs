use crate::auth::{AuthTokenBytes, AuthTokenError};
use crate::opts::{BabeltraceOpts, ReflectorOpts};
use crate::types::{LoggingLevel, RetryDurationUs, SessionNotFoundAction};
use babeltrace2_sys::CtfPluginSourceFsInitParams;
use modality_reflector_config::{Config, TomlValue, TopLevelIngest, CONFIG_ENV_VAR};
use serde::Deserialize;
use std::convert::TryFrom;
use std::env;
use std::ffi::{CString, NulError};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CtfConfig {
    pub auth_token: Option<String>,
    pub ingest: TopLevelIngest,
    pub plugin: PluginConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct PluginConfig {
    pub run_id: Option<Uuid>,

    /// Optionally provide a trace UUID to override any present (or not) UUID contained
    /// in the CTF metadata.
    ///
    /// This is useful for constructing deterministic trace UUIDis which form the timeline IDs.
    pub trace_uuid: Option<Uuid>,

    /// Logging level for libbabeltrace
    pub log_level: LoggingLevel,

    /// Rename a timeline attribute key as it is being imported
    pub rename_timeline_attrs: Vec<AttrKeyRename>,

    /// Rename an event attribute key as it is being imported
    pub rename_event_attrs: Vec<AttrKeyRename>,

    /// Merge all streams into the stream with the given ID, producing a single timeline.
    pub merge_stream_id: Option<u64>,

    #[serde(flatten)]
    pub import: ImportConfig,

    #[serde(flatten)]
    pub lttng_live: LttngLiveConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct AttrKeyRename {
    /// The attr key to rename
    pub original: String,

    /// The new attr key name to use
    pub new: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct ImportConfig {
    /// See <https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.fs.7/#doc-param-trace-name>
    pub trace_name: Option<String>,

    /// See <https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.fs.7/#doc-param-clock-class-offset-ns>
    pub clock_class_offset_ns: Option<i64>,

    /// See <https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.fs.7/#doc-param-clock-class-offset-s>
    pub clock_class_offset_s: Option<i64>,

    /// See <https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.fs.7/#doc-param-force-clock-class-origin-unix-epoch>
    pub force_clock_class_origin_unix_epoch: Option<bool>,

    /// See <https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.fs.7/#doc-param-inputs>
    pub inputs: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct LttngLiveConfig {
    /// When libbabeltrace needs to retry to run
    /// the graph later, retry in retry-duration-us µs
    pub retry_duration_us: RetryDurationUs,

    /// See
    /// <https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.lttng-live.7/#doc-param-session-not-found-action>
    pub session_not_found_action: SessionNotFoundAction,

    /// See
    /// <https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.lttng-live.7/#doc-param-inputs>
    pub url: Option<Url>,
}

impl CtfConfig {
    pub fn load_merge_with_opts(
        rf_opts: ReflectorOpts,
        bt_opts: BabeltraceOpts,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cfg = if let Some(cfg_path) = &rf_opts.config_file {
            modality_reflector_config::try_from_file(cfg_path)?
        } else if let Ok(env_path) = env::var(CONFIG_ENV_VAR) {
            modality_reflector_config::try_from_file(Path::new(&env_path))?
        } else {
            Config::default()
        };

        let mut ingest = cfg.ingest.clone().unwrap_or_default();
        if let Some(url) = &rf_opts.protocol_parent_url {
            ingest.protocol_parent_url = Some(url.clone());
        }
        if rf_opts.allow_insecure_tls {
            ingest.allow_insecure_tls = true;
        }

        let plugin_cfg: PluginConfig =
            TomlValue::Table(cfg.metadata.into_iter().collect()).try_into()?;
        let plugin = PluginConfig {
            run_id: rf_opts.run_id.or(plugin_cfg.run_id),
            trace_uuid: bt_opts.trace_uuid.or(plugin_cfg.trace_uuid),
            log_level: bt_opts.log_level.unwrap_or(plugin_cfg.log_level),
            import: plugin_cfg.import,
            lttng_live: plugin_cfg.lttng_live,
            rename_timeline_attrs: plugin_cfg.rename_timeline_attrs,
            rename_event_attrs: plugin_cfg.rename_event_attrs,
            merge_stream_id: bt_opts.merge_stream_id.or(plugin_cfg.merge_stream_id),
        };

        Ok(Self {
            auth_token: rf_opts.auth_token,
            ingest,
            plugin,
        })
    }

    pub fn protocol_parent_url(&self) -> Result<Url, url::ParseError> {
        if let Some(url) = &self.ingest.protocol_parent_url {
            Ok(url.clone())
        } else {
            let url = Url::parse("modality-ingest://127.0.0.1:14188")?;
            Ok(url)
        }
    }

    pub fn resolve_auth(&self) -> Result<AuthTokenBytes, AuthTokenError> {
        AuthTokenBytes::resolve(self.auth_token.as_deref())
    }
}

impl TryFrom<&ImportConfig> for CtfPluginSourceFsInitParams {
    type Error = babeltrace2_sys::Error;

    fn try_from(config: &ImportConfig) -> Result<Self, Self::Error> {
        let trace_name: Option<CString> = config
            .trace_name
            .as_ref()
            .map(|n| CString::new(n.as_bytes()))
            .transpose()?;

        let input_cstrings: Vec<CString> = config
            .inputs
            .iter()
            .map(|p| CString::new(p.as_os_str().as_bytes()))
            .collect::<Result<Vec<CString>, NulError>>()?;
        let inputs = input_cstrings
            .iter()
            .map(|i| i.as_c_str())
            .collect::<Vec<_>>();

        CtfPluginSourceFsInitParams::new(
            trace_name.as_deref(),
            config.clock_class_offset_ns,
            config.clock_class_offset_s,
            config.force_clock_class_origin_unix_epoch,
            &inputs,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use modality_reflector_config::{AttrKeyEqValuePair, TimelineAttributes};
    use pretty_assertions::assert_eq;
    use std::str::FromStr;
    use std::{env, fs::File, io::Write};

    const IMPORT_CONFIG: &str = r#"[ingest]
protocol-parent-url = 'modality-ingest://127.0.0.1:14182'
additional-timeline-attributes = [
    "ci_run=1",
    "module='linux-import'",
]

[metadata]
run-id = 'a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d1'
trace-uuid = 'a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d2'
log-level = 'info'
trace-name = 'my-trace'
clock-class-offset-ns = -1
clock-class-offset-s = 2
force-clock-class-origin-unix-epoch = true
inputs = ['path/traces-a', 'path/traces-b']
"#;

    const LTTNG_LIVE_CONFIG: &str = r#"[ingest]
protocol-parent-url = 'modality-ingest://127.0.0.1:14182'
additional-timeline-attributes = [
    "ci_run=1",
    "module='linux-import'",
]

[metadata]
run-id = 'a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d1'
trace-uuid = 'a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d2'
log-level = 'debug'
retry-duration-us = 100
session-not-found-action = 'end'
url = 'net://localhost/host/ubuntu-focal/my-kernel-session'
"#;

    #[test]
    fn import_cfg() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("my_config.toml");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(IMPORT_CONFIG.as_bytes()).unwrap();
            f.flush().unwrap();
        }

        let cfg = CtfConfig::load_merge_with_opts(
            ReflectorOpts {
                config_file: Some(path.to_path_buf()),
                ..Default::default()
            },
            Default::default(),
        )
        .unwrap();

        env::set_var(CONFIG_ENV_VAR, path);
        let env_cfg =
            CtfConfig::load_merge_with_opts(Default::default(), Default::default()).unwrap();
        env::remove_var(CONFIG_ENV_VAR);
        assert_eq!(cfg, env_cfg);

        assert_eq!(
            cfg,
            CtfConfig {
                auth_token: None,
                ingest: TopLevelIngest {
                    protocol_parent_url: Url::parse("modality-ingest://127.0.0.1:14182")
                        .unwrap()
                        .into(),
                    allow_insecure_tls: false,
                    protocol_child_port: None,
                    timeline_attributes: TimelineAttributes {
                        additional_timeline_attributes: vec![
                            AttrKeyEqValuePair::from_str("ci_run=1").unwrap(),
                            AttrKeyEqValuePair::from_str("module='linux-import'").unwrap(),
                        ],
                        override_timeline_attributes: Default::default(),
                    },
                    max_write_batch_staleness: None,
                },
                plugin: PluginConfig {
                    run_id: Uuid::from_str("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d1")
                        .unwrap()
                        .into(),
                    trace_uuid: Uuid::from_str("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d2")
                        .unwrap()
                        .into(),
                    log_level: babeltrace2_sys::LoggingLevel::Info.into(),
                    rename_timeline_attrs: Default::default(),
                    rename_event_attrs: Default::default(),
                    merge_stream_id: None,
                    import: ImportConfig {
                        trace_name: "my-trace".to_owned().into(),
                        clock_class_offset_ns: Some(-1_i64),
                        clock_class_offset_s: 2_i64.into(),
                        force_clock_class_origin_unix_epoch: true.into(),
                        inputs: vec![
                            PathBuf::from("path/traces-a"),
                            PathBuf::from("path/traces-b")
                        ],
                    },
                    lttng_live: Default::default(),
                }
            }
        );
    }

    #[test]
    fn lttng_live_cfg() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("my_config.toml");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(LTTNG_LIVE_CONFIG.as_bytes()).unwrap();
            f.flush().unwrap();
        }

        let cfg = CtfConfig::load_merge_with_opts(
            ReflectorOpts {
                config_file: Some(path.to_path_buf()),
                ..Default::default()
            },
            Default::default(),
        )
        .unwrap();

        env::set_var(CONFIG_ENV_VAR, path);
        let env_cfg =
            CtfConfig::load_merge_with_opts(Default::default(), Default::default()).unwrap();
        env::remove_var(CONFIG_ENV_VAR);
        assert_eq!(cfg, env_cfg);

        assert_eq!(
            cfg,
            CtfConfig {
                auth_token: None,
                ingest: TopLevelIngest {
                    protocol_parent_url: Url::parse("modality-ingest://127.0.0.1:14182")
                        .unwrap()
                        .into(),
                    allow_insecure_tls: false,
                    protocol_child_port: None,
                    timeline_attributes: TimelineAttributes {
                        additional_timeline_attributes: vec![
                            AttrKeyEqValuePair::from_str("ci_run=1").unwrap(),
                            AttrKeyEqValuePair::from_str("module='linux-import'").unwrap(),
                        ],
                        override_timeline_attributes: Default::default(),
                    },
                    max_write_batch_staleness: None,
                },
                plugin: PluginConfig {
                    run_id: Uuid::from_str("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d1")
                        .unwrap()
                        .into(),
                    trace_uuid: Uuid::from_str("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d2")
                        .unwrap()
                        .into(),
                    log_level: babeltrace2_sys::LoggingLevel::Debug.into(),
                    import: Default::default(),
                    rename_timeline_attrs: Default::default(),
                    rename_event_attrs: Default::default(),
                    merge_stream_id: None,
                    lttng_live: LttngLiveConfig {
                        retry_duration_us: 100.into(),
                        session_not_found_action: babeltrace2_sys::SessionNotFoundAction::End
                            .into(),
                        url: Url::parse("net://localhost/host/ubuntu-focal/my-kernel-session")
                            .unwrap()
                            .into(),
                    }
                }
            }
        );
    }
}
