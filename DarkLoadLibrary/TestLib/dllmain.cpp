// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

extern "C"
_declspec(dllexport) VOID InvokeMessageBox()
{
    DWORD pid = ::GetCurrentProcessId();
    WCHAR exeName[MAX_PATH] = { 0 };
    WCHAR message[MAX_PATH * 2] = { 0 };

    ::GetModuleFileName(NULL, exeName, MAX_PATH);

    wsprintf(message, TEXT("Loaded to %s (PID : %d)."), exeName, pid);

    ::MessageBoxW(NULL, message, TEXT("DLL_PROCESS_ATTACH"), 0);
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  dwReason,
    LPVOID lpReserved
)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        InvokeMessageBox();

    return TRUE;
}

