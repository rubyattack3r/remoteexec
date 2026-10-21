# LOLBins and launcher payloads

remoteexec uses an explicit LOLBin selector when a process-launch technique must load a staged native DLL, Control Panel module, or managed assembly. There is no default: the operator must provide the local source with `--payload`, the exact destination with `--remote-path`, and a compatible `--lolbin`. Run `remoteexec exec binaries` for the machine-readable built-in contracts.

If you build the payload yourself, start with [authoring launcher-compatible payloads](authoring.md), then use the family-specific native, CPL, managed, injection, or custom-launcher reference.

`WMIProvider` is the exception. Its provider host loads the registered DLL directly, so it requires `--remote-path` but rejects launcher flags. Service payloads, executable payloads, and direct commands also do not use them.

## Launcher documentation

- [Payload authoring and validation](authoring.md)
- [Native DLL launchers](native.md)
- [Control Panel modules](cpl.md)
- [Managed launchers](managed.md)
- [Process-bound injection](injection.md)
- [Custom launchers](custom.md)

## Supported selectors

| Selector | Payload | Generated invocation | Required contract | Key telemetry |
|---|---|---|---|---|
| `rundll32.exe` | `dll` | `rundll32.exe <remote-path>,<entry-point>` | Export supplied by `--entry-point` | `rundll32` command line, DLL load |
| `rundll32.exe (advpack RegisterOCX)` | `dll` | `rundll32.exe advpack.dll,RegisterOCX <remote-path>` | `DllRegisterServer` | `rundll32` loading `advpack.dll`, DLL load |
| `msiexec.exe (/y)`, `msiexec.exe (/z)` | `dll` | `msiexec.exe /y|/z <remote-path>` | `DllRegisterServer` or `DllUnregisterServer` | `msiexec` DLL registration, DLL load |
| `odbcconf.exe` | `dll` | `odbcconf.exe /a {REGSVR <remote-path>}` | `DllRegisterServer` | `odbcconf` process, DLL load |
| `regsvr32.exe` variants | `dll` | `regsvr32.exe /s [...] <remote-path>` | `DllRegisterServer`, `DllUnregisterServer`, or `DllInstall` | `regsvr32` command line, DLL load |
| `control.exe` | `cpl` | `control.exe <remote-path>` | CPL module implementing `CPlApplet` | Control Panel module path, child processes |
| `mavinject.exe` | `dll` | `mavinject.exe <process-id> /INJECTRUNNING <remote-path>` | Native DLL compatible with the selected process | Cross-process injection, module load |
| `RegAsm.exe`, `RegAsm.exe (/U)` | `managed` | `RegAsm.exe [/U] <remote-path>` | COM registration or unregistration callback | .NET registration process, registry writes |
| `RegSvcs.exe`, `RegSvcs.exe (/U)` | `managed` | `RegSvcs.exe [/U] <remote-path>` | Signed serviced-component assembly | Enterprise-services registration |
| `InstallUtil.exe`, `InstallUtil.exe (/U)` | `managed` | `InstallUtil.exe ... [/U] <remote-path>` | `[RunInstaller(true)]` installer implementation | `InstallUtil` process, managed assembly load |

Selectors containing spaces or parentheses must be quoted in a shell:

```bash
remoteexec exec technique --dry-run \
  --targets server01 --technique WMIExec \
  --payload-type dll --payload ./loader.dll \
  --remote-path 'D:\Staging\loader.dll' \
  --lolbin 'regsvr32.exe (/u)' \
  --domain CORP --username operator --password-stdin
```

`--entry-point` affects only `rundll32.exe`. `mavinject.exe` also requires `--process-id`; preflight confirms that the process exists before staging, but the operator must ensure the process and DLL architectures match. Managed selectors default to the 64-bit .NET Framework v4 paths and verify that executable before staging. Use `--launcher-program` to select an installed 32-bit or alternate framework path.

## Custom launchers

Use the reserved `custom` selector to describe a target-resident executable without changing the built-in registry. It works with `dll`, `cpl`, and `managed` payloads. The program must be an absolute drive path to an existing `.exe`; preflight checks it before any target executes. The single-line argument template must contain `{remote_path}` and may contain `{entry_point}` and `{process_id}`. If a template uses `{entry_point}` or `{process_id}`, the corresponding flag is required. Unknown placeholders are rejected, and paths are quoted when needed.

```bash
remoteexec exec technique --dry-run \
  --targets server01 --technique WMIExec \
  --payload-type dll --payload ./loader.dll \
  --remote-path 'D:\Staging\loader.dll' \
  --lolbin custom \
  --launcher-program 'D:\Approved Tools\loader-host.exe' \
  --launcher-arguments '--load {remote_path} --export {entry_point}' \
  --entry-point Run \
  --domain CORP --username operator --password-stdin
```

Custom means operator-defined, not trusted or low-observability. The executable is not added to `exec binaries`, and remoteexec cannot infer its required entry contract, side effects, or cleanup beyond the staged payload. Preserve the emitted invocation and validate the launcher under the engagement's change-control process.

For a PID-bound custom launcher:

```bash
remoteexec exec technique --dry-run \
  --targets server01 --technique WMIExec \
  --payload-type dll --payload ./loader.dll \
  --remote-path 'D:\Staging\loader.dll' \
  --lolbin custom \
  --launcher-program 'D:\Approved Tools\injector.exe' \
  --launcher-arguments '--pid {process_id} --module {remote_path}' \
  --process-id 4242 \
  --domain CORP --username operator --password-stdin
```

## Delivery and recovery contract

For a file payload, preflight confirms that the parent of `--remote-path` exists, the destination does not already exist, sufficient free space is available, and SMB is reachable. Execution stages the bytes, invokes the selected binary through the chosen remote-execution technique, reports the invocation under `execution.evidence`, and reports the staged file under `recovery.artifacts`.

remoteexec does not automatically remove artifacts. Remove the reported staged file only after the launcher has exited and the module is no longer mapped. Registration and installer callbacks can create arbitrary registry, COM, service, or file state; those payload-defined effects are outside the generic delivery contract. Injection cannot be generically undone: execution evidence and the corresponding recovery constraint include `related_process_id`, and the operator must decide whether to leave, unload, or terminate the disposable process before removing the DLL.

## Detection considerations

No selector is quiet or undetectable. Defenders can correlate the remote-management parent activity with SMB file creation, process creation, command-line telemetry, module loads, image reputation, and any registration side effects. Changing the signed Windows binary changes telemetry details, not the underlying observability of staged remote DLL execution.

References: [Microsoft `regsvr32` syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32), [Microsoft `DllInstall` contract](https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-dllinstall), [LOLBAS Advpack](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Advpack.yml), [executing Control Panel items](https://learn.microsoft.com/en-us/windows/win32/shell/executing-control-panel-items), [InstallUtil](https://learn.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool), and [RegSvcs](https://learn.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool).
