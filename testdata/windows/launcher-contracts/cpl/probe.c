#include <windows.h>
#include <cpl.h>

__declspec(dllexport) LONG CALLBACK CPlApplet(
    HWND window, UINT message, LPARAM first, LPARAM second) {
    (void)window;
    (void)first;
    (void)second;
    if (message == CPL_INIT) {
        HANDLE marker = CreateFileW(
            L"C:\\Windows\\Temp\\remoteexec-control.marker", GENERIC_WRITE,
            0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (marker != INVALID_HANDLE_VALUE) {
            CloseHandle(marker);
        }
        return TRUE;
    }
    if (message == CPL_GETCOUNT) {
        return 0;
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
