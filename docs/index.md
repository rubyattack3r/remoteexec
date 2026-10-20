# remoteexec documentation

remoteexec provides a common command surface and result contract for authorized remote-execution assessments, with Windows as its primary platform. No technique is undetectable. Ratings are relative and assume modern endpoint, operating-system, and network telemetry; local policy and ordinary administration patterns can materially change visibility.

Cross-platform SSH support is limited to the command-only [SSHExec](techniques/sshexec.md) primitive. Windows-specific lateral-movement techniques remain the main focus.

| Selector | Payload types | Privilege | Surface | Relative detectability |
|---|---|---|---|---|
| [WMIProvider](techniques/wmiprovider.md) | DLL | Local administrator | WMI/DCOM, SMB | High; well-signatured |
| [WMIService](techniques/wmiservice.md) | Service | Local administrator | WMI/DCOM, SMB | High; well-signatured |
| [WMIExec](techniques/wmiexec.md) | DLL, executable, command | Local administrator | WMI/DCOM; SMB for files | High; well-signatured |
| [WSManExec](techniques/wsmanexec.md) | DLL, executable, command | Local administrator | WinRM; SMB for files | Medium; mature WinRM telemetry |
| [TaskSchedExec](techniques/taskschedexec.md) | DLL, executable, command | Local administrator | DCOM/RPC; SMB for files | High; well-signatured |
| [DCOMIShellDispatch2](techniques/dcomishelldispatch2.md) | DLL, executable, command | Local administrator plus active shell | DCOM/RPC; SMB for files | Medium; conditional on telemetry |
| [SCMChangeService](techniques/scmchangeservice.md) | Service | Local administrator | SCM/RPC, SMB | High; well-signatured |
| [SCMCreateService](techniques/scmcreateservice.md) | Service | Local administrator | SCM/RPC, SMB | High; well-signatured PsExec-style behavior |
| [SSHExec](techniques/sshexec.md) | Command | Authenticated account | SSH | Medium; authentication, session, and process telemetry |

Additional references:

- [Output schema](output.md)
- [Runtime configuration](configuration.md)
- [LOLBins and launcher payloads](lolbins.md)
- [Architecture and platform boundaries](architecture.md)
- [SSH command execution](techniques/sshexec.md)
- [Operator recovery](recovery.md)
- [Acceptable Use Policy](https://github.com/rubyattack3r/remoteexec/blob/develop/ACCEPTABLE_USE_POLICY.md)

Windows mutation remains isolated behind an experimental build tag, so the public build requires `--dry-run` for Windows techniques. `SSHExec` command execution is available in the public build.
