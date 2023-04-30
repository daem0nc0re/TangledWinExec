#pragma once

// 
// Structs
// 
typedef struct
{
    WORD	offset : 12;
    WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

// 
// Function Signatures
// 
typedef ULONG_PTR (__stdcall *GetCurrentPointer_t)();
typedef ULONG_PTR (WINAPI *GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef ULONG_PTR (WINAPI *LoadLibraryA_t)(LPCSTR lpLibFileName);
typedef ULONG_PTR (WINAPI *VirtualAlloc_t)(
    _In_ ULONG_PTR lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect);
typedef BOOL (WINAPI *VirtualProtect_t)(
    _In_ ULONG_PTR lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD  flNewProtect,
    _Out_ PDWORD lpflOldProtect);
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    _In_ HANDLE ProcessHandle,
    _Inout_ ULONG_PTR* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    _In_ HANDLE ProcessHandle,
    _Inout_ ULONG_PTR* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);
typedef NTSTATUS (NTAPI *NtFlushInstructionCache_t)(
    HANDLE ProcessHandle,
    LPVOID BaseAddress,
    ULONG NumberOfBytesToFlush);

#ifdef _WIN64
typedef BOOLEAN (__cdecl *RtlAddFunctionTable_t)(
    _In_ PRUNTIME_FUNCTION FunctionTable,
    _In_ DWORD EntryCount,
    _In_ DWORD64 BaseAddress
);
#endif

typedef BOOL (*DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

// 
// Consts.
// 
#define STATUS_SUCCESS 0
// Following hashes generated from uppercase unicode string
#define KERNEL32_HASH 0x6A4ABC5B
#define NTDLL_HASH 0x3CFA685D
// Following hashes generated from uppercase ASCII string
#define LOADLIBRARYA_HASH 0x8A8B4676
#define GETPROCADDRESS_HASH 0x1ACAEE7A
#define NTPROTECTVIRTUALMEMORY_HASH 0x1255C05B
#define NTALLOCATEVIRTUALMEMORY_HASH 0x5947FD91
#define NTFLUSHINSTRUCTIONCACHE_HASH 0xD95A3B7F
#define RTLADDFUNCTIONTABLE_HASH 0xB11A8928

// 
// Inline Functions
// 
__forceinline DWORD CalcHash(ULONG_PTR pValue, DWORD nLength)
{
    DWORD hash = 0;

    for (DWORD index = 0; index < nLength; index++)
    {
        hash = ((hash >> 13 | hash << (32 - 13)) & 0xFFFFFFFF);

        if (*((CHAR*)pValue) > 0x60)
            hash += *((CHAR*)pValue) - 0x20;
        else
            hash += *((CHAR*)pValue);

        pValue++;
    }

    return hash;
}

__forceinline void CopyData(ULONG_PTR pDst, ULONG_PTR pSrc, SIZE_T nSize)
{
    while (nSize--)
        *(BYTE*)pDst++ = *(BYTE*)pSrc++;
}


__forceinline
ULONG_PTR SeachImageBaseAddress(ULONG_PTR pImageBase)
{
    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;

    do
    {
        pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;

        if (pImageDosHeader->e_magic == 0x5A4D)
        {
            pImageNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);

            if (pImageNtHeaders->Signature == 0x00004550)
                break;
        }

        pImageBase--;
    } while (TRUE);

    return pImageBase;
}