# Windows live-test fixtures

These fixtures exercise remoteexec's payload and launcher contracts without embedding an assessment payload. They only write deterministic marker files or return an exit status. They do not open a shell, make network connections, collect data, or establish persistence.

Source is committed so contract validation is reproducible. Compiled fixtures, generated signing keys, target details, runner scripts, logs, and results must remain under `.scratch/` and must not be committed. Supply credentials through an approved local secret mechanism; a gitignored directory is not a secret store.

## Layout

| Source | Contract | Build output | Observable result |
| --- | --- | --- | --- |
| `payloads/command` | Ordinary Windows executable | `command-probe.exe` | Writes the marker path supplied as its only argument. |
| `payloads/service` | Windows service executable | `service-probe.exe` | Reports `Running`, writes `C:\Windows\Temp\remoteexec-service.marker`, and exits after ten seconds or a stop request. |
| `techniques/wmi-provider` | In-process COM server implementing the WMI provider initialization and event-provider interfaces | `wmi-provider-probe.dll` | Writes `C:\Windows\Temp\remoteexec-wmi-provider.marker` when loaded. |
| `launcher-contracts/native-dll` | `rundll32`, registration, unregistration, install, and uninstall exports | `launcher-probe.dll` | Writes an export-specific marker under `C:\Windows\Temp`. |
| `launcher-contracts/cpl` | Control Panel module implementing `CPlApplet` | `control-probe.cpl` | Writes `C:\Windows\Temp\remoteexec-control.marker` during `CPL_INIT`. |
| `launcher-contracts/managed` | COM registration, Enterprise Services, and installer callbacks | `managed-probe.dll` | Writes callback-specific registration or installer markers under `C:\Windows\Temp`. |

The managed fixture's GUID and COM+ application name are fixed test identities. Its strong-name key is generated for each build and deleted immediately after compilation.

## Build on Windows

The full builder requires Go, the Visual Studio x64 C++ toolchain, and the x64 .NET Framework v4 compiler:

```powershell
.\testdata\windows\build.ps1
```

Output defaults to `.scratch/fixtures/bin`. To use a different ignored directory:

```powershell
.\testdata\windows\build.ps1 -OutputDirectory .scratch\fixtures\custom
```

## Cross-build native fixtures

On a non-Windows development host with Go and the MinGW-w64 x64 compiler:

```bash
./testdata/windows/build-cross.sh
```

This builds the Go, native DLL, CPL, and WMI-provider fixtures. Build the managed fixture on Windows.

## Cleanup contract

Fixture markers are evidence, not automatic cleanup triggers. Remove only paths emitted by the test record and only after the associated process or module is no longer active. Managed registration callbacks can also create COM, COM+, or installer state; invoke the matching `/U` launcher contract before deleting the assembly. WMI provider and service state must be recovered through the corresponding technique record.

Never run live fixture validation against a production host. Follow the repository [Acceptable Use Policy](../../ACCEPTABLE_USE_POLICY.md).
