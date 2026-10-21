# Native DLL launchers

The `rundll32`, Advpack, `msiexec`, `odbcconf`, and `regsvr32` selectors consume native DLLs, but they do not call the same export. Select the launcher whose callback contract the final binary actually implements.

## Required exports

Use Windows ABI types and calling conventions from the platform headers:

```c
#include <windows.h>

STDAPI DllRegisterServer(void);
STDAPI DllUnregisterServer(void);
STDAPI DllInstall(BOOL install, LPCWSTR command_line);

__declspec(dllexport)
void CALLBACK Run(HWND window, HINSTANCE instance, LPSTR command_line, int show);
```

| Selector | Export called |
|---|---|
| `rundll32.exe` | Value of `--entry-point`, such as `Run` |
| `rundll32.exe (advpack RegisterOCX)` | `DllRegisterServer` |
| `msiexec.exe (/y)` | `DllRegisterServer` |
| `msiexec.exe (/z)` | `DllUnregisterServer` |
| `odbcconf.exe` | `DllRegisterServer` |
| `regsvr32.exe` | `DllRegisterServer` |
| `regsvr32.exe (/u)` | `DllUnregisterServer` |
| `regsvr32.exe (/i)` | `DllInstall(TRUE, ...)` |
| `regsvr32.exe (/u /i)` | Uninstall-oriented registration callbacks |

Export only the callbacks the selected launcher needs. Return a failing `HRESULT` when initialization fails. Keep `DllMain` minimal: loader-lock restrictions make network access, process creation, synchronization, and complex runtime initialization unsafe there. Put substantive work in the invoked export or in a deliberately created worker.

## Export names and architecture

For 32-bit builds, verify that the public name is undecorated. A module exporting `_Run@16` does not satisfy an invocation that requests `Run`. A module-definition file can pin names:

```def
LIBRARY payload
EXPORTS
    Run
    DllRegisterServer
    DllUnregisterServer
    DllInstall
```

Match the launcher architecture. Native system binaries under `System32` are 64-bit on 64-bit Windows; their 32-bit counterparts are under `SysWOW64`. Use `--launcher-program` when the built-in path does not match the payload.

## Validation and recovery

Inspect exports with `dumpbin /exports` or `objdump -p`, invoke the selected callback locally on a disposable host, and verify its return behavior. Registration callbacks can create state that remoteexec cannot infer. Document and reverse those payload-defined changes separately, wait for the launcher to release the DLL, and then remove the digest-matched staged file.

References: [Rundll32](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32), [DLL entry point](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function), [`DllInstall`](https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-dllinstall), and [`regsvr32`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32).
