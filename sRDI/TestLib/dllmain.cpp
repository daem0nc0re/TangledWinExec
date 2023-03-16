// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    DWORD pid = ::GetCurrentProcessId();
    WCHAR exeName[MAX_PATH] = { 0 };
    WCHAR message[MAX_PATH * 2] = { 0 };

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        ::GetModuleFileName(NULL, exeName, MAX_PATH);

        wsprintf(message, TEXT("Executed from %s (PID : %d)."), exeName, pid);

        ::MessageBoxW(NULL, message, TEXT("DLL_PROCESS_ATTACH"), 0);
    }

    return TRUE;
}

