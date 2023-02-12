#pragma once

/*
* Structs
*/
typedef struct
{
    WORD	offset : 12;
    WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

/*
* Function Signatures
*/
typedef ULONG_PTR (*GetCurrentPointer_t)();
typedef ULONG_PTR (*GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef ULONG_PTR (*LoadLibraryA_t)(LPCSTR lpLibFileName);
typedef ULONG_PTR (*VirtualAlloc_t)(
    _In_ ULONG_PTR lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect);
typedef BOOL (*VirtualProtect_t)(
    _In_ ULONG_PTR lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD  flNewProtect,
    _Out_ PDWORD lpflOldProtect);
typedef NTSTATUS (*NtAllocateVirtualMemory_t)(
    _In_ HANDLE ProcessHandle,
    _Inout_ ULONG_PTR* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);
typedef NTSTATUS (*NtProtectVirtualMemory_t)(
    _In_ HANDLE ProcessHandle,
    _Inout_ ULONG_PTR* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);
typedef NTSTATUS (*NtFlushInstructionCache_t)(
    HANDLE ProcessHandle,
    LPVOID BaseAddress,
    ULONG NumberOfBytesToFlush);
typedef BOOL (*DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

/*
* Consts.
*/
#define STATUS_SUCCESS 0
#define KERNEL32_HASH 0x6A4ABC5B
#define NTDLL_HASH 0x3CFA685D
#define VIRTUALALLOC_HASH 0x302EBE1C
#define VIRTUALPROTECT_HASH 0x1803B7E3
#define NTPROTECTVIRTUALMEMORY_HASH 0x1255C05B
#define NTALLOCATEVIRTUALMEMORY_HASH 0x5947FD91
#define NTFLUSHINSTRUCTIONCACHE_HASH 0xD95A3B7F
#define LOADLIBRARYA_HASH 0x8A8B4676
#define GETPROCADDRESS_HASH 0x1ACAEE7A
#define VIRTUALALLOC_HASH 0x302EBE1C
#define VIRTUALPROTECT_HASH 0x1803B7E3
#define MESSAGEBOXW_HASH 0x9ACA96AE

/*
* Inline Functions
*/
__forceinline DWORD ror13(DWORD val)
{
    return ((val >> 13 | val << (32 - 13)) & 0xFFFFFFFF);
}


__forceinline DWORD CalcHash(ULONG_PTR pValue, DWORD nLength)
{
    DWORD hash = 0;
    CHAR* pCode = (CHAR*)pValue;

    for (DWORD index = 0; index < nLength; index++)
    {
        hash = ror13(hash);

        if (*((CHAR*)pCode) > 0x60)
            hash += *((CHAR*)pCode) - 0x20;
        else
            hash += *((CHAR*)pCode);

        pCode++;
    }

    return hash;
}

__forceinline void CopyData(ULONG_PTR pDst, ULONG_PTR pSrc, DWORD nSize)
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