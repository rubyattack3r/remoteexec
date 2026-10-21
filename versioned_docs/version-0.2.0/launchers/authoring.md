# Authoring launcher-compatible payloads

A launcher-compatible payload is defined by its binary format, architecture, exported entry points, and callback behavior—not merely its file extension. Build and validate payloads in an engagement-controlled environment before using them with remoteexec. `remoteexec exec binaries` is the authoritative machine-readable inventory of selectors and contracts.

Family-specific details are organized separately:

- [Native DLL launchers](native.md)
- [Control Panel modules](cpl.md)
- [Managed launchers](managed.md)
- [Process-bound injection](injection.md)
- [Custom launchers](custom.md)

## Contract map

| Selector family | Payload format | Required implementation |
|---|---|---|
| `rundll32.exe` | Native DLL | The export named by `--entry-point`, using a `CALLBACK`/`WINAPI` calling convention compatible with Rundll32 |
| `advpack`, `msiexec /y`, `odbcconf`, `regsvr32` | Native DLL | `DllRegisterServer(void)` returning `HRESULT` |
| `msiexec /z`, `regsvr32 /u` | Native DLL | `DllUnregisterServer(void)` returning `HRESULT` |
| `regsvr32 /i` variants | Native DLL | `DllInstall(BOOL install, LPCWSTR commandLine)`; combined variants can also call the registration exports |
| `control.exe` | Native CPL module | Exported `CPlApplet(HWND, UINT, LPARAM, LPARAM)` callback |
| `mavinject.exe` | Native DLL | Valid `DllMain`; DLL architecture must match the selected target process |
| `RegAsm.exe` | Managed assembly | COM-visible types and, when side effects are needed, `ComRegisterFunction` / `ComUnregisterFunction` callbacks |
| `RegSvcs.exe` | Managed, strong-named assembly | Enterprise Services component derived from `ServicedComponent` with appropriate assembly metadata |
| `InstallUtil.exe` | Managed assembly | A public `Installer` type marked `[RunInstaller(true)]`, with deliberate install/uninstall behavior |
| `custom` | Contract chosen by the operator | An absolute launcher path and an argument template containing `{remote_path}` |

## Build-time inspection

Inspect the final artifact, not just its source project:

```powershell
dumpbin.exe /headers .\payload.dll
dumpbin.exe /exports .\payload.dll
corflags.exe .\payload-managed.dll
```

On a non-Windows build host, `llvm-objdump -p`, the MinGW `objdump -p`, or `file` can confirm PE architecture and exported names. For managed payloads, inspect assembly references and custom attributes with `ildasm.exe` or an equivalent metadata reader.

Before a remote run, validate all of the following:

1. Payload type matches the selector family.
2. PE architecture matches the launcher and, for injection, the target process.
3. Required exports have the exact public names and calling conventions.
4. The selected framework/runtime and every dependency exist on the target.
5. Callbacks return useful failure codes and tolerate repeated invocation.
6. Payload-defined side effects and their recovery steps are documented separately from remoteexec's staged-file record.
7. A local disposable-host test proves the expected callback ran and the module can be released before deletion.

Then run the exact remoteexec command with `--dry-run`. Dry-run validates delivery, launcher presence, collisions, credentials, and technique prerequisites; it cannot prove that an arbitrary payload implements its claimed ABI. A live test in a disposable authorized host remains the final contract check.

The family pages contain their corresponding platform references and recovery constraints.
