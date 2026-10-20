# Structured output

Execution emits exactly one document per prepared target. JSON and Signal are newline-delimited; YAML documents are separated with `---`. The pre-release `schema_version` is currently `0.1.0`.

```json
{
  "schema_version": "0.1.0",
  "technique": "WMIExec",
  "target": "10.0.0.15",
  "run_id": "5f0c1e9a2b7d4c18",
  "payload_type": "command",
  "status": "failed",
  "started_at": "2026-10-20T00:00:00Z",
  "finished_at": "2026-10-20T00:00:02Z",
  "artifacts": [],
  "error": "authorization: access denied",
  "error_kind": "authorization"
}
```

## Fields

| Field | Description |
| --- | --- |
| `schema_version` | Semantic contract version. Before 1.0, incompatible changes bump the minor component and compatible changes bump the patch. No stability guarantee applies until 1.0. |
| `technique` | Stable technique selector. |
| `target` | Hostname or IP address as supplied. |
| `run_id` | Per-target run identifier. It names the verification marker on the target. Omitted when no backend preflight ran. |
| `payload_type` | `dll`, `cpl`, `managed`, `executable`, `service`, or `command`. |
| `status` | `planned` (dry run), `succeeded`, or `failed`. |
| `started_at`, `finished_at` | RFC 3339 UTC timestamps. |
| `artifacts` | Created or changed artifacts. Always an array, never `null`. A `failed` result can still carry artifacts from steps that completed before the failure. |
| `error` | Human-readable failure message. Present only when `status` is `failed`. |
| `error_kind` | Failure class: `validation`, `authentication`, `authorization`, `reachability`, `conflict`, `execution`, or `cleanup`. Unclassified failures and timeouts report `execution`. |

Preflight runs for every target before any target changes. If preflight fails for any target, execution does not start and no documents are emitted; the command exits with the preflight error. If a run is interrupted after execution starts, targets that already ran keep their documents, and each remaining target gets a `failed` document whose `error` begins with `not attempted:`. Those targets were not changed.

## Artifacts

Each artifact carries `kind`, `location`, and, depending on the kind, `digest`, `original`, `invocation_id`, `program`, `process_id`, `related_process_id`, and `recovery`. Structured fields are the recovery record; `recovery` is only its human-readable summary.

| `kind` | `location` | `original` |
| --- | --- | --- |
| `staged_file` | Remote file path; `digest` is `sha256:<hex>` | `absent` |
| `verify_marker` | Remote marker file path | — |
| `process_invocation` | Staged path, or `command:sha256:<hex>` when no file was staged | — |
| `scheduled_task` | Task name | `absent` |
| `temporary_service` | Service name | `absent` |
| `service_path` | Service name | Prior configuration as `\|`-separated, URL-escaped `key=value` pairs (`name`, `display_name`, `path`, `start_mode`, `start_name`, `state`) |
| `service_start` | `<service>:start` | Prior run state |
| `wmi_provider` | Provider name | `absent` |
| `registry_key` | Registry path | `absent` |

`original` is `absent` when remoteexec created the artifact. Process artifacts identify an invocation as `launcher:sha256:<hex>` or `command:sha256:<hex>` without retaining its arguments. `program` contains only the executable name. `process_id` is emitted when the execution API returns or observes the launched PID. `related_process_id` identifies a distinct process affected by the launcher, such as an injection target.

remoteexec does not automatically recover artifacts or retain a disk journal. Losing stdout loses the recovery record, so redirect it to an engagement-controlled file when recovery matters. Signal output wraps the same object in `{"signal":"remoteexec.result.v0","data":...}`; the signal tag tracks the schema major family. Credentials, raw command text, and launcher arguments are not part of the schema.
