# Control Panel modules

`control.exe` requires a real Control Panel module, not an arbitrary DLL renamed to `.cpl`. The native module must export `CPlApplet` with the Control Panel callback signature.

```c
#include <windows.h>
#include <cpl.h>

__declspec(dllexport)
LONG CALLBACK CPlApplet(HWND window, UINT message, LPARAM first, LPARAM second) {
    switch (message) {
    case CPL_INIT:
        return TRUE;
    case CPL_GETCOUNT:
        return 0;
    default:
        return 0;
    }
}
```

At minimum, handle `CPL_INIT` and `CPL_GETCOUNT`. If the module advertises applets, also implement the information and invocation messages those applets require. Build for the architecture of the selected `control.exe`, confirm the undecorated `CPlApplet` export, and test the module locally on a disposable Windows host.

Use `--payload-type cpl --lolbin control.exe`. After execution, wait for `control.exe` to release the module before removing the reported staged path. Any state created by the callback is payload-defined and must have its own recovery procedure.

Reference: [Control Panel applications](https://learn.microsoft.com/en-us/windows/win32/shell/control-panel-applications).
