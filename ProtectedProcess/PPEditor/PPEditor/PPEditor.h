#pragma once

typedef enum _PS_PROTECTED_TYPE
{
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2,
    PsProtectedTypeMax = 3
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen = 2,
    PsProtectedSignerAntimalware = 3,
    PsProtectedSignerLsa = 4,
    PsProtectedSignerWindows = 5,
    PsProtectedSignerWinTcb = 6,
    PsProtectedSignerWinSystem = 7,
    PsProtectedSignerApp = 8,
    PsProtectedSignerMax = 9
} PS_PROTECTED_SIGNER;

typedef struct _KERNEL_OFFSETS
{
    // nt!_EPROCESS
    ULONG UniqueProcessId;
    ULONG ActiveProcessLinks;
    ULONG ImageFilePointer;
    ULONG ImageFileName;
    ULONG SignatureLevel;
    ULONG SectionSignatureLevel;
    ULONG Protection;
} KERNEL_OFFSETS, * PKERNEL_OFFSETS;

typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION;

typedef struct _PROCESS_CONTEXT
{
    ULONG64 Eprocess;
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    PS_PROTECTION Protection;
    CHAR ProcessName[256];
} PROCESS_CONTEXT, * PPROCESS_CONTEXT;

extern BOOL g_IsInitialized;
extern ULONG64 g_SystemProcess;
extern KERNEL_OFFSETS g_KernelOffsets;