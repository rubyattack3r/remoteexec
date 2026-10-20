# Runtime configuration

remoteexec keeps technique selectors and recovery behavior stable while allowing environment-specific delivery and transport settings to be selected per run.

| Flag | Default | Scope |
|---|---|---|
| `--payload-type` | none | Required input contract: `dll`, `cpl`, `managed`, `executable`, `service`, or `command`. The selected technique must advertise support for it. |
| `--payload` | none | Local source file for every input except `command`. |
| `--command` | none | Direct command line for a `command` payload. This mode does not stage a file. |
| `--arguments` | none | Raw argument string appended to a staged `executable` payload. |
| `--remote-path` | none | Required exact absolute drive path for every file payload. Its parent directory must already exist and be reachable through the corresponding administrative share. |
| `--winrm-https` | `false` | Selects HTTPS for `WSManExec`; HTTP is used otherwise. |
| `--winrm-port` | `5985` for HTTP; `5986` for HTTPS | Overrides the WinRM listener port used by both preflight and execution. |
| `--min-staging-bytes` | `16777216` | Minimum free space required in the parent directory of `--remote-path`. |
| `--ssh-port` | `22` | SSH listener used by preflight and execution. |
| `--private-key` | none | Unencrypted OpenSSH private key for `SSHExec`, mutually exclusive with password authentication. |
| `--service-name` | none | Existing service reconfigured by `WMIService`/`SCMChangeService`, or temporary service created by `SCMCreateService`. |
| `--lolbin` | none | Required compatible selector for `dll`, `cpl`, and `managed` payloads launched as a process. It is invalid for `WMIProvider`, which loads its provider DLL natively. |
| `--launcher-program` | none | Absolute remote `.exe` required for `custom`, or a built-in program-path override. Preflight requires absolute launcher paths to exist. |
| `--launcher-arguments` | none | Required single-line custom template containing `{remote_path}`; optional `{entry_point}` and `{process_id}` placeholders bind their corresponding flags. |
| `--process-id` | none | Existing remote PID required by process-bound launchers such as `mavinject.exe`. Preflight confirms existence before staging. |
| `--entry-point` | `ServiceMain` | DLL export used by `rundll32.exe`; other LOLBAS selectors use their required registration export. |
| `--timeout`, `--sleep`, `--jitter` | see `--help` | Execution budget and pacing. |

The local source and remote destination are independent. For example:

```bash
remoteexec exec technique --dry-run \
  --targets server01 --technique WSManExec \
  --payload-type dll --payload ./dist/loader.dll \
  --remote-path 'D:\ProgramData\RedTeam\stage.dll' \
  --lolbin rundll32.exe --entry-point ServiceMain \
  --winrm-https --winrm-port 8443 --min-staging-bytes 33554432 \
  --domain CORP --username operator --password-stdin
```

Preflight rejects a missing staging directory, an existing destination file, insufficient space, an unreachable configured port, or an unsafe/non-absolute destination before any target is allowed to execute. remoteexec does not create the parent directory because doing so would add an unrequested artifact.

`Executable` and direct `command` modes are available for `WMIExec`, `WSManExec`, `TaskSchedExec`, and `DCOMIShellDispatch2`. Executable mode stages and launches a local EXE, then reports the staged file for operator recovery. Command mode expects the referenced executable or command to already exist remotely and skips SMB delivery and all staging checks.

See the [LOLBins reference](lolbins.md) for exact selectors, required exports, generated invocations, compatibility boundaries, and detection considerations.

`SSHExec` supports command payloads only and requires an explicit password or private key. See the [SSH reference](techniques/sshexec.md) for its execution, output, and server-identity boundary.

`SCMCreateService` is the PsExec-style primitive. It stages a service executable, creates and starts a temporary SCM service named by `--service-name`, and then stops/deletes that service and removes the file. It implements the mechanism natively and does not bundle or invoke Microsoft's PsExec utility.

remoteexec reports the artifacts it creates but does not automatically remove or restore them. A user-supplied command can create files, processes, accounts, registry values, or other state that remoteexec cannot infer. Operators are responsible for retaining output and reversing desired side effects within the engagement plan.

Protocol identifiers such as WMI namespaces, COM class identifiers, WSMan resource URIs, and registry locations are implementation invariants rather than runtime configuration. Changing those values can alter the selected technique.
