#include "pch.h"
#include "ReflectiveLib.h"

ULONG_PTR GetModuleHandleByHash(DWORD moduleHash)
{
    PUNICODE_STRING pBaseDllName;
    PPEB_LDR_DATA pLdrData;
    PLDR_DATA_TABLE_ENTRY pLdrDataTable;
    ULONG_PTR pModule = 0;

#ifdef _WIN64
    pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)((ULONG_PTR)__readgsqword(0x60) + 0x18));
    pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x10);
#elif _WIN32
    pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)((ULONG_PTR)__readfsdword(0x30) + 0xC));
    pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x8);
#else
    return nullptr;
#endif

    while (pLdrDataTable->DllBase != NULL)
    {
#ifdef _WIN64
        pBaseDllName = (PUNICODE_STRING)((ULONG_PTR)pLdrDataTable + 0x58);
#elif _WIN32
        pBaseDllName = (PUNICODE_STRING)((ULONG_PTR)pLdrDataTable + 0x2C);
#else
        break;
#endif

        if (CalcHash((ULONG_PTR)pBaseDllName->Buffer, pBaseDllName->Length) == moduleHash)
        {
            pModule = (ULONG_PTR)pLdrDataTable->DllBase;
            break;
        }

#ifdef _WIN64
        pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrDataTable->InMemoryOrderLinks.Flink - 0x10);
#elif _WIN32
        pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrDataTable->InMemoryOrderLinks.Flink - 0x8);
#else
        break;
#endif
    }

    return pModule;
}


ULONG_PTR GetProcAddressByHash(ULONG_PTR hModule, DWORD procHash)
{
    USHORT machine;
    DWORD e_lfanew;
    DWORD nExportDirectoryOffset;
    DWORD nNumberOfNames;
    DWORD nOrdinal;
    DWORD nStrLen;
    ULONG_PTR pExportDirectory;
    ULONG_PTR pAddressOfFunctions;
    ULONG_PTR pAddressOfNames;
    ULONG_PTR pAddressOfOrdinals;
    LPCSTR procName;
    ULONG_PTR pProc = 0;

    do
    {
        if (*(USHORT*)hModule != 0x5A4D)
            break;

        e_lfanew = *(DWORD*)((ULONG_PTR)hModule + 0x3C);

        if (*(DWORD*)((ULONG_PTR)hModule + e_lfanew) != 0x00004550)
            break;

        machine = *(SHORT*)((ULONG_PTR)hModule + e_lfanew + 0x18);

        if (machine == 0x020B)
            nExportDirectoryOffset = *(DWORD*)((ULONG_PTR)hModule + e_lfanew + 0x88);
        else if (machine == 0x010B)
            nExportDirectoryOffset = *(DWORD*)((ULONG_PTR)hModule + e_lfanew + 0x78);
        else
            break;

        pExportDirectory = (ULONG_PTR)hModule + nExportDirectoryOffset;
        nNumberOfNames = *(DWORD*)((ULONG_PTR)pExportDirectory + 0x18);
        pAddressOfFunctions = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x1C));
        pAddressOfNames = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x20));
        pAddressOfOrdinals = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x24));

        for (DWORD index = 0; index < nNumberOfNames; index++)
        {
            nStrLen = 0;
            procName = (LPCSTR)((ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfNames + ((ULONG_PTR)index * 4))));

            while (procName[nStrLen] != 0)
                nStrLen++;

            if (CalcHash((ULONG_PTR)procName, nStrLen) == procHash)
            {
                nOrdinal = (DWORD)(*(SHORT*)((ULONG_PTR)pAddressOfOrdinals + ((ULONG_PTR)index * 2)));
                pProc = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfFunctions + ((ULONG_PTR)nOrdinal * 4)));
                break;
            }
        }
    } while (FALSE);

    return pProc;
}


extern "C"
_declspec(dllexport)
ULONG_PTR ReflectiveEntry(ULONG_PTR pEnvironment)
{
    NTSTATUS ntstatus;
    ULONG_PTR pKernel32;
    ULONG_PTR pNtdll;
    ULONG_PTR pLoadLibraryA;
    ULONG_PTR pGetProcAddress;
    ULONG_PTR pNtAllocateVirtualMemory;
    ULONG_PTR pNtProtectVirtualMemory;
    ULONG_PTR pNtFlushInstructionCache;
    ULONG_PTR pInstructions;
    ULONG_PTR pImageBase;
    ULONG_PTR pSectionHeadersBase;
    ULONG_PTR pDllBase;
    ULONG_PTR pAddressOfFunctions;
    ULONG_PTR pModuleBuffer;
    ULONG_PTR pSource;
    ULONG_PTR pDestination;
    ULONG_PTR pRelocationBlock;
    ULONG_PTR pEntryPoint;
    ULONG protect;
    SIZE_T nImageSize;
    SIZE_T nDataSize;
    DWORD nSections;
    DWORD nRelocations;
    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;
    PIMAGE_SECTION_HEADER pSectionHeader;
    PIMAGE_DATA_DIRECTORY pImageDataDirectory;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;
    PIMAGE_DATA_DIRECTORY pImageDirectoryImport;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_THUNK_DATA pIntTable;
    PIMAGE_THUNK_DATA pIatTable;
    PIMAGE_IMPORT_BY_NAME pImportByName;
    PIMAGE_BASE_RELOCATION pImageBaseRelocation;
    PIMAGE_RELOC pImageReloc;

    /*
    * Step 1 : Resolve required function pointer
    */
    pKernel32 = GetModuleHandleByHash(KERNEL32_HASH);
    pNtdll = GetModuleHandleByHash(NTDLL_HASH);

    if (!pNtdll || !pKernel32)
        return NULL;

    pLoadLibraryA = GetProcAddressByHash(pKernel32, LOADLIBRARYA_HASH);

    if (!pLoadLibraryA)
        return NULL;

    pGetProcAddress = GetProcAddressByHash(pKernel32, GETPROCADDRESS_HASH);

    if (!pGetProcAddress)
        return NULL;

    pNtAllocateVirtualMemory = GetProcAddressByHash(pNtdll, NTALLOCATEVIRTUALMEMORY_HASH);

    if (!pNtAllocateVirtualMemory)
        return NULL;

    pNtProtectVirtualMemory = GetProcAddressByHash(pNtdll, NTPROTECTVIRTUALMEMORY_HASH);

    if (!pNtProtectVirtualMemory)
        return NULL;

    pNtFlushInstructionCache = GetProcAddressByHash(pNtdll, NTFLUSHINSTRUCTIONCACHE_HASH);

    if (!pNtFlushInstructionCache)
        return NULL;

    /*
    * Step 2 : Search base address of this image data
    */
    pInstructions = NULL;
    nDataSize = sizeof(DWORD);
    ntstatus = ((NtAllocateVirtualMemory_t)pNtAllocateVirtualMemory)(
        (HANDLE)-1,
        &pInstructions,
        NULL,
        &nDataSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (ntstatus != STATUS_SUCCESS)
        return NULL;

    // For 32bit => pop eax; push eax; ret
    // For 64bit => pop rax; push rax; ret
    *(DWORD*)pInstructions = 0x00C35058;
    nDataSize = sizeof(DWORD);

    ((NtProtectVirtualMemory_t)pNtProtectVirtualMemory)(
        (HANDLE)-1,
        &pInstructions,
        &nDataSize,
        PAGE_EXECUTE_READ,
        &protect);

    pImageBase = ((GetCurrentPointer_t)pInstructions)();

    do
    {
        pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;

        if ((pImageDosHeader->e_magic == 0x5A4D) &&
            (pImageDosHeader->e_lfanew < 0x200)) // To avoid false positive
        {
            pImageNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);

            if (pImageNtHeaders->Signature == 0x00004550)
                break;
        }

        pImageBase--;
    } while (TRUE);

    /*
    * Step 3 : Analyze PE header for this DLL
    */
    nImageSize = (SIZE_T)pImageNtHeaders->OptionalHeader.SizeOfImage;
    nSections = pImageNtHeaders->FileHeader.NumberOfSections;
    pSectionHeadersBase = (ULONG_PTR)pImageNtHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pImageNtHeaders->FileHeader.SizeOfOptionalHeader;
    pSectionHeader = (PIMAGE_SECTION_HEADER)pSectionHeadersBase;

    /*
    * Step 4 : Parse this DLL's data to new memory
    */
    pModuleBuffer = NULL;
    ntstatus = ((NtAllocateVirtualMemory_t)pNtAllocateVirtualMemory)(
        (HANDLE)-1,
        &pModuleBuffer,
        NULL,
        &nImageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pModuleBuffer == NULL)
        return NULL;

    // Set header data
    pDestination = pModuleBuffer;
    pSource = pImageBase;
    nDataSize = pImageNtHeaders->OptionalHeader.SizeOfHeaders;
    CopyData(pDestination, pSource, nDataSize);

    // Set section data
    for (DWORD index = 0; index < nSections; index++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)(pSectionHeadersBase + (sizeof(IMAGE_SECTION_HEADER) * index));
        pDestination = pModuleBuffer + pSectionHeader->VirtualAddress;
        pSource = pImageBase + pSectionHeader->PointerToRawData;
        nDataSize = pSectionHeader->SizeOfRawData;
        CopyData(pDestination, pSource, nDataSize);
    }

    /*
    * Step 5 : Build import table
    */
    pImageDirectoryImport = (PIMAGE_DATA_DIRECTORY)(&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pModuleBuffer + pImageDirectoryImport->VirtualAddress);

    while (pImportDescriptor->Name)
    {
        pDllBase = ((LoadLibraryA_t)pLoadLibraryA)((LPCSTR)(pModuleBuffer + pImportDescriptor->Name));
        pIntTable = (PIMAGE_THUNK_DATA)(pModuleBuffer + pImportDescriptor->OriginalFirstThunk);
        pIatTable = (PIMAGE_THUNK_DATA)(pModuleBuffer + pImportDescriptor->FirstThunk);

        while (*(ULONG_PTR*)pIatTable)
        {
            // Get required export function's information from DLL which is imported to this DLL
            if (pIntTable && (pIntTable->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                pImageNtHeaders = (PIMAGE_NT_HEADERS)(pDllBase + ((PIMAGE_DOS_HEADER)pDllBase)->e_lfanew);
                pImageDataDirectory = (PIMAGE_DATA_DIRECTORY)(&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
                pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pDllBase + pImageDataDirectory->VirtualAddress);
                pAddressOfFunctions = pDllBase + pImageExportDirectory->AddressOfFunctions;
                pAddressOfFunctions += (((pIntTable->u1.Ordinal & 0xFFFF) - pImageExportDirectory->Base) * sizeof(DWORD));
                pIatTable->u1.Function = pDllBase + *(DWORD*)(pAddressOfFunctions);
            }
            else
            {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)(pModuleBuffer + *(ULONG_PTR*)pIatTable);
                pIatTable->u1.Function = (ULONG_PTR)((GetProcAddress_t)pGetProcAddress)((HMODULE)pDllBase, (LPCSTR)pImportByName->Name);
            }

            pIatTable = (PIMAGE_THUNK_DATA)((ULONG_PTR)pIatTable + sizeof(ULONG_PTR));

            if (pIntTable)
                pIntTable = (PIMAGE_THUNK_DATA)((ULONG_PTR)pIntTable + sizeof(ULONG_PTR));
        }

        pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    /*
    * Step 6 : Build relocation table
    */
    pImageNtHeaders = (PIMAGE_NT_HEADERS)(pModuleBuffer + ((PIMAGE_DOS_HEADER)pModuleBuffer)->e_lfanew);
    pDllBase = pModuleBuffer - pImageNtHeaders->OptionalHeader.ImageBase;
    pImageDataDirectory = (PIMAGE_DATA_DIRECTORY)&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pImageDataDirectory->Size)
    {
        pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)(pModuleBuffer + pImageDataDirectory->VirtualAddress);

        while (pImageBaseRelocation->SizeOfBlock)
        {
            pRelocationBlock = pModuleBuffer + pImageBaseRelocation->VirtualAddress;
            nRelocations = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
            pImageReloc = (PIMAGE_RELOC)((ULONG_PTR)pImageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

            while (nRelocations--)
            {
                if (pImageReloc->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(pRelocationBlock + pImageReloc->offset) += pDllBase;
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(pRelocationBlock + pImageReloc->offset) += (DWORD)pDllBase;
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGH)
                    *(WORD*)(pRelocationBlock + pImageReloc->offset) += HIWORD(pDllBase);
                else if (pImageReloc->type == IMAGE_REL_BASED_LOW)
                    *(WORD*)(pRelocationBlock + pImageReloc->offset) += LOWORD(pDllBase);

                pImageReloc = (PIMAGE_RELOC)((ULONG_PTR)pImageReloc + sizeof(IMAGE_RELOC));
            }

            pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pImageBaseRelocation + pImageBaseRelocation->SizeOfBlock);
        }
    }

    /*
    * Step 7 : Set section page protection
    */
    for (DWORD index = 0; index < nSections; index++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)(pSectionHeadersBase + (sizeof(IMAGE_SECTION_HEADER) * index));
        pDestination = pModuleBuffer + pSectionHeader->VirtualAddress;
        nDataSize = pSectionHeader->SizeOfRawData;

        if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            protect = PAGE_EXECUTE_READWRITE;
        }
        else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ))
        {
            protect = PAGE_EXECUTE_READ;
        }
        else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) &&
            (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            protect = PAGE_READWRITE;
        }
        else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            protect = PAGE_EXECUTE;
        }
        else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
        {
            protect = PAGE_READONLY;
        }
        else
        {
            continue;
        }

        ((NtProtectVirtualMemory_t)pNtProtectVirtualMemory)(
            (HANDLE)-1,
            &pDestination,
            &nDataSize,
            protect,
            &protect);
    }

    /*
    * Step 8 : Call entry point
    */
    pEntryPoint = pModuleBuffer + pImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
    ((NtFlushInstructionCache_t)pNtFlushInstructionCache)((HANDLE)-1, NULL, 0);
    ((DllMain_t)pEntryPoint)((HINSTANCE)pModuleBuffer, DLL_PROCESS_ATTACH, NULL);

    return pModuleBuffer;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DWORD pid = ::GetCurrentProcessId();
        WCHAR exeName[MAX_PATH] = { 0 };
        WCHAR message[MAX_PATH * 2] = { 0 };

        ::GetModuleFileName(NULL, exeName, MAX_PATH);

        wsprintf(message, TEXT("Injected to %s (PID : %d)."), exeName, pid);

        ::MessageBoxW(NULL, message, TEXT("DLL_PROCESS_ATTACH"), 0);
    }
    return TRUE;
}