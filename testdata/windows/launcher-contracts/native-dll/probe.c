#include <windows.h>

static HRESULT write_marker(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    CloseHandle(file);
    return S_OK;
}

__declspec(dllexport) void CALLBACK Run(
    HWND window, HINSTANCE instance, LPSTR command_line, int show) {
    (void)window;
    (void)instance;
    (void)command_line;
    (void)show;
    write_marker(L"C:\\Windows\\Temp\\remoteexec-rundll32.marker");
}

__declspec(dllexport) HRESULT __stdcall DllRegisterServer(void) {
    return write_marker(
        L"C:\\Windows\\Temp\\remoteexec-regsvr32-register.marker");
}

__declspec(dllexport) HRESULT __stdcall DllUnregisterServer(void) {
    return write_marker(
        L"C:\\Windows\\Temp\\remoteexec-regsvr32-unregister.marker");
}

__declspec(dllexport) HRESULT __stdcall DllInstall(
    BOOL install, LPCWSTR command_line) {
    (void)command_line;
    if (install) {
        return write_marker(
            L"C:\\Windows\\Temp\\remoteexec-regsvr32-install.marker");
    }
    return write_marker(
        L"C:\\Windows\\Temp\\remoteexec-regsvr32-uninstall.marker");
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        write_marker(L"C:\\Windows\\Temp\\remoteexec-dllmain.marker");
    }
    return TRUE;
}
