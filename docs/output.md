# Structured output

Execution emits exactly one document per prepared target. JSON and Signal are newline-delimited; YAML documents are separated with `---`. The pre-release `schema_version` is currently `0.2.0`.

```json
{
  "schema_version": "0.2.0",
  "technique": "WMIExec",
  "target": "10.0.0.15",
  "run_id": "5f0c1e9a2b7d4c18",
  "payload_type": "command",
  "status": "succeeded",
  "started_at": "2026-10-20T00:00:00Z",
  "finished_at": "2026-10-20T00:00:02Z",
  "execution": {
    "disposition": "dispatched",
    "evidence": [{
      "kind": "process_invocation",
      "source": "Win32_Process.Create",
      "outcome": "accepted",
      "invocation_id": "command:sha256:...",
      "program": "cmd.exe",
      "process_id": 4242,
      "process_id_status": "returned_or_observed",
      "detail": "remote API accepted the invocation and returned or exposed the process identifier; payload completion is not independently observed"
    }]
  },
  "recovery": {
    "required": false,
    "artifacts": [],
    "constraints": []
  }
}
```

## Result fields

| Field | Description |
| --- | --- |
| `schema_version` | Semantic contract version. Before 1.0, incompatible changes bump the minor component and compatible changes bump the patch. |
| `technique` | Stable technique selector. |
| `target` | Hostname or IP address as supplied. |
| `run_id` | Per-target run identifier, omitted when backend preflight did not run. |
| `payload_type` | `dll`, `cpl`, `managed`, `executable`, `service`, or `command`. |
| `status` | Technique outcome: `planned`, `succeeded`, or `failed`. Success means that technique's documented verification condition passed; it does not always mean payload completion. |
| `execution` | What the remote execution API proved. |
| `recovery` | Persistent state remoteexec created or changed and constraints that affect its safe recovery. |
| `started_at`, `finished_at` | RFC 3339 UTC timestamps. |
| `error`, `error_kind` | Failure detail and class, present only for failed results. |

Preflight runs for every target before any target changes. If any target fails preflight, execution does not begin and no result documents are emitted. Once execution starts, a failed result can still contain recovery artifacts created before the failure. Interrupted targets that were never reached use `execution.disposition: not_attempted`.

## Execution evidence

`execution.disposition` avoids conflating API acceptance with payload completion:

| Disposition | Meaning |
| --- | --- |
| `planned` | Dry run only; no invocation occurred. |
| `dispatched` | The remote API accepted or exposed the invocation, but payload completion was not proved. |
| `completed` | A synchronous API reported completion with exit code 0. |
| `failed` | The invocation or a preceding mutation failed. |
| `not_attempted` | Another target or cancellation stopped the batch before this target ran. |

Each evidence item names its `source`, `outcome`, redacted `invocation_id`, and available process information. `process_id_status` is always present: `returned_or_observed` means a PID is included; `not_provided_by_api` explains why it is absent. WSMan and SSH successful commands report `exit_code: 0` and `completed`; WMI process creation reports a PID and `dispatched`; Task Scheduler and DCOM report only what their APIs make observable.

## Recovery

`recovery.required` is true when `recovery.artifacts` contains state to review. Process invocations are execution evidence, not persistent artifacts. When a running or injected process affects whether an artifact can be removed safely, the process appears in `recovery.constraints` instead.

| Artifact `kind` | `location` | `original` |
| --- | --- | --- |
| `staged_file` | Remote file path; `digest` is `sha256:<hex>` | `absent` |
| `verify_marker` | Remote marker file path | — |
| `scheduled_task` | Task name | `absent` |
| `temporary_service` | Service name | `absent` |
| `service_path` | Service name | Prior URL-escaped service configuration |
| `service_start` | `<service>:start` | Prior run state |
| `wmi_provider` | Provider name | `absent` |
| `registry_key` | Registry path | `absent` |

Structured artifact fields are the recovery record; human-readable `recovery` and constraint `description` fields summarize the same operation. remoteexec does not automatically recover state or retain a disk journal. Losing stdout loses the recovery record, so redirect it to an engagement-controlled file when recovery matters.

Signal output wraps the same result in `{"signal":"remoteexec.result.v0","data":...}`. Credentials, raw command text, and launcher arguments are not part of the schema.
