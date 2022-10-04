# modality-ctf-plugins &emsp; ![ci]

A [Modality][modality] reflector plugin suite and ingest adapter library for [CTF][ctf] data.

## Getting Started

1. Configure a modality reflector to run either the CTF importer or the LTTng collector (see Configuration below)
2. Use the importer to import a CTF trace from disk, or use the LTTng streaming collector to collect data from an LTTng relay daemon

## Adapter Concept Mapping

The following describes the default mapping between [CTF][ctf] concepts
and [Modality's][modality] concepts. See the configuration section for ways to change the
default behavior.

* CTF streams are represented as separate Modality timelines
* CTF trace and stream properties are represented as Modality timeline attributes under the `timeline.internal.ctf` prefix
* CTF event common, specific, and packet context fields are represented as Modality event attributes under the `timeline.internal.ctf` prefix
* CTF event field attributes are at the root level

See the [Modality documentation](https://docs.auxon.io/modality/) for more information on the Modality concepts.

## Configuration

All of the plugins can be configured through a TOML configuration file (from either the `--config` option or the `MODALITY_REFLECTOR_CONFIG` environment variable).
All of the configuration fields can optionally be overridden at the CLI, see `--help` for more details.

See the [`modality-reflector` Configuration File documentation](https://docs.auxon.io/modality/ingest/modality-reflector-configuration-file.html) for more information
about the reflector configuration.

### Common Sections

These sections are the same for each of the plugins.

* `[ingest]` — Top-level ingest configuration.
  - `additional-timeline-attributes` — Array of key-value attribute pairs to add to every timeline seen by the plugin.
  - `override-timeline-attributes` — Array of key-value attribute pairs to override on every timeline seen by this plugin.
  - `allow-insecure-tls` — Whether to allow insecure connections. Defaults to `false`.
  - `protocol-parent-url` — URL to which this reflector will send its collected data.

* `[plugins.ingest.importers.ctf.metadata]` or `[plugins.ingest.collectors.lttng-live.metadata]` — Plugin configuration table. (just `metadata` if running standalone)
  - `run-id` — Use the provided UUID as the run ID instead of generating a random one.
  - `trace-uuid` — Use the provided UUID as the trace UUID to override any present (or not) UUID contained in the CTF metadata.
  - `log-level` — Logging level for libbabeltrace. Defaults to `none`.

### Importer Section

These `metadata` fields are specific to the CTF importer plugin.
See [babeltrace2-source.ctf.fs][ctf-fs-docs] for more information.

* `[metadata]` — Plugin configuration table.
* `[plugins.ingest.importers.ctf.metadata]` — Plugin configuration table. (just `metadata` if running standalone)
  - `trace-name` — Set the name of the trace object.
  - `clock-class-offset-ns` — Add nanoseconds to the offset of all the clock classes.
  - `clock-class-offset-s` — Add seconds to the offset of all the clock classes.
  - `force-clock-class-origin-unix-epoch` — Force the origin of all clock classes that the component creates to have a Unix epoch origin.
  - `inputs` — The metadata file paths of the CTF traces to import.

### LTTng Collector Section

These `metadata` fields are specific to the LTTng collector plugin.
See [babeltrace2-source.ctf.lttng-live][lttng-live-docs] for more information.

* `[metadata]` — Plugin configuration table.
* `[plugins.ingest.collectors.lttng-live.metadata]` — Plugin configuration table. (just `metadata` if running standalone)
  - `retry-duration-us` — The libbabeltrace graph run retry interval.
  - `session-not-found-action` — The action to take when the remote tracing session is not found. Defaults to `continue`.
  - `url` — The URL of the LTTng relay daemon to connect to.

## LICENSE

See [LICENSE](./LICENSE) for more details.

Copyright 2022 [Auxon Corporation](https://auxon.io)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[ci]: https://github.com/auxoncorp/modality-ctf-plugins/workflows/CI/badge.svg
[ctf]: https://diamon.org/ctf/
[modality]: https://auxon.io/products/modality
[lttng-live-docs]: https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.lttng-live.7/
[ctf-fs-docs]: https://babeltrace.org/docs/v2.0/man7/babeltrace2-source.ctf.fs.7/
