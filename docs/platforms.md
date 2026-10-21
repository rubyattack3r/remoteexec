# Tested platforms

Last validated: 2026-10-21. Windows execution was tested on Windows Server 2025 Standard x64, build 26100.

## Technique matrix

✅ validated · ❌ prerequisite rejected · Untested · — not applicable

| Technique | Server 2016 | Server 2019 | Server 2022 | Server 2025 (26100) | Windows 10 | Windows 11 | Linux SSH | Windows OpenSSH | macOS SSH |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [`WMIProvider`](techniques/wmiprovider.md) | Untested | Untested | Untested | ✅ | Untested | Untested | — | — | — |
| [`WMIService`](techniques/wmiservice.md) | Untested | Untested | Untested | ✅ | Untested | Untested | — | — | — |
| [`WMIExec`](techniques/wmiexec.md) | Untested | Untested | Untested | ✅ ¹ | Untested | Untested | — | — | — |
| [`WSManExec`](techniques/wsmanexec.md) | Untested | Untested | Untested | ✅ | Untested | Untested | — | — | — |
| [`TaskSchedExec`](techniques/taskschedexec.md) | Untested | Untested | Untested | ✅ | Untested | Untested | — | — | — |
| [`DCOMIShellDispatch2`](techniques/dcomishelldispatch2.md) | Untested | Untested | Untested | ❌ ² | Untested | Untested | — | — | — |
| [`SCMChangeService`](techniques/scmchangeservice.md) | Untested | Untested | Untested | ✅ | Untested | Untested | — | — | — |
| [`SCMCreateService`](techniques/scmcreateservice.md) | Untested | Untested | Untested | ✅ | Untested | Untested | — | — | — |
| [`SSHExec`](techniques/sshexec.md) | — | — | — | — | — | — | ✅ ³ | ✅ ³ | Untested |

1. WMI process creation returned dispatch status and a PID, but not the process's eventual exit code.
2. Preflight reached DCOM but `IShellWindows.Item` returned access denied despite an active Explorer session. Nothing was staged or executed.
3. `SSHExec` is command-only and does not use the Windows file-delivery pipeline. Linux validation used Debian 12 x64 with OpenSSH 9.2p1; Windows validation used the optional OpenSSH Server feature on build 26100.

## Launcher matrix

All launcher selectors below were validated through `WMIExec` on Windows Server 2025 build 26100 using the benign contract fixtures under `testdata/windows`. See the [launcher reference](launchers/index.md) for payload contracts and prerequisites.

| Selector | Result |
| --- | --- |
| `rundll32.exe` | ✅ |
| `rundll32.exe (advpack RegisterOCX)` | ✅ |
| `msiexec.exe (/y)`, `msiexec.exe (/z)` | ✅ |
| `odbcconf.exe` | ✅ |
| `regsvr32.exe` variants | ✅ |
| `control.exe` | ✅ |
| `mavinject.exe` | ✅ ⁴ |
| `RegAsm.exe`, `RegAsm.exe (/U)` | ✅ |
| `RegSvcs.exe`, `RegSvcs.exe (/U)` | ✅ |
| `InstallUtil.exe`, `InstallUtil.exe (/U)` | ✅ |
| `custom` | ✅ |

4. An architecture-matched DLL completed; an x86/x64 mismatch was rejected during preflight before staging.

Record the target edition, build, architecture, technique, launcher selector, and relevant security baseline with assessment results. Use the emitted [`execution` and `recovery` fields](output.md) as the result for an individual run.
