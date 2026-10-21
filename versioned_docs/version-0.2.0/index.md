# remoteexec documentation

remoteexec provides a common command surface and result contract for authorized remote-execution assessments, with Windows as its primary platform. No technique is undetectable. Visibility depends on the target's endpoint, operating-system, and network telemetry, and on what ordinary administration looks like in that environment.

Cross-platform SSH support is limited to the command-only [SSHExec](techniques/sshexec.md) primitive. Windows-specific lateral-movement techniques remain the main focus.

| Selector | Payload types | Privilege | Surface | Key telemetry |
|---|---|---|---|---|
| [WMIProvider](techniques/wmiprovider.md) | DLL | Local administrator | WMI/DCOM, SMB | Provider registration, `StdRegProv` registry writes, DLL load |
| [WMIService](techniques/wmiservice.md) | Service | Local administrator | WMI/DCOM, SMB | Service reconfiguration, image-path change, service start |
| [WMIExec](techniques/wmiexec.md) | DLL, executable, command | Local administrator | WMI/DCOM; SMB for files | WMI process creation, command line |
| [WSManExec](techniques/wsmanexec.md) | DLL, executable, command | Local administrator | WinRM; SMB for files | WinRM shell creation, command line |
| [TaskSchedExec](techniques/taskschedexec.md) | DLL, executable, command | Local administrator | DCOM/RPC; SMB for files | Task registration and execution events, process creation |
| [DCOMIShellDispatch2](techniques/dcomishelldispatch2.md) | DLL, executable, command | Local administrator plus active shell | DCOM/RPC; SMB for files | DCOM activation, `ShellExecute` child process |
| [SCMChangeService](techniques/scmchangeservice.md) | Service | Local administrator | SCM/RPC, SMB | Service reconfiguration, image-path change, service start |
| [SCMCreateService](techniques/scmcreateservice.md) | Service | Local administrator | SCM/RPC, SMB | Service installation, admin-share write, service start |
| [SSHExec](techniques/sshexec.md) | Command | Authenticated account | SSH | SSH authentication, session, and process events |

Additional references:

- [Output schema](output.md)
- [Runtime configuration](configuration.md)
- [LOLBins and launcher payloads](launchers/index.md)
- [Launcher payload authoring](launchers/authoring.md)
- [Architecture and platform boundaries](architecture.md)
- [Tested operating systems and build-specific limitations](platforms.md)
- [SSH command execution](techniques/sshexec.md)
- [Operator recovery](recovery.md)
- [Acceptable Use Policy](https://github.com/rubyattack3r/remoteexec/blob/v0.2.0/ACCEPTABLE_USE_POLICY.md)

Windows builds include the native execution backend. Linux and macOS builds support the command-only `SSHExec` technique. `--dry-run` is an explicit operator choice that validates prerequisites and emits a plan without changing the target.
