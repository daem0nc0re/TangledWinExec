using System;

namespace PPIDSpoofing.Interop
{
    [Flags]
    internal enum FormatMessageFlags : uint
    {
        FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
        FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
        FORMAT_MESSAGE_FROM_STRING = 0x00000400,
        FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
        FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
        FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
    }

    internal enum PROC_THREAD_ATTRIBUTE_NUM : uint
    {
        ProcThreadAttributeParentProcess = 0, // in HANDLE
        ProcThreadAttributeExtendedFlags = 1, // in ULONG (EXTENDED_PROCESS_CREATION_FLAG_*)
        ProcThreadAttributeHandleList = 2, // in HANDLE[]
        ProcThreadAttributeGroupAffinity = 3, // in GROUP_AFFINITY // since WIN7
        ProcThreadAttributePreferredNode = 4, // in USHORT
        ProcThreadAttributeIdealProcessor = 5, // in PROCESSOR_NUMBER
        ProcThreadAttributeUmsThread = 6, // in UMS_CREATE_THREAD_ATTRIBUTES
        ProcThreadAttributeMitigationPolicy = 7, // in ULONG, ULONG64, or ULONG64[2]
        ProcThreadAttributePackageFullName = 8, // in WCHAR[] // since WIN8
        ProcThreadAttributeSecurityCapabilities = 9, // in SECURITY_CAPABILITIES
        ProcThreadAttributeConsoleReference = 10, // BaseGetConsoleReference (kernelbase.dll)
        ProcThreadAttributeProtectionLevel = 11, // in ULONG (PROTECTION_LEVEL_*) // since WINBLUE
        ProcThreadAttributeOsMaxVersionTested = 12, // in MAXVERSIONTESTED_INFO // since THRESHOLD // (from exe.manifest)
        ProcThreadAttributeJobList = 13, // in HANDLE[]
        ProcThreadAttributeChildProcessPolicy = 14, // in ULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
        ProcThreadAttributeAllApplicationPackagesPolicy = 15, // in ULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
        ProcThreadAttributeWin32kFilter = 16, // in WIN32K_SYSCALL_FILTER
        ProcThreadAttributeSafeOpenPromptOriginClaim = 17, // in SE_SAFE_OPEN_PROMPT_RESULTS
        ProcThreadAttributeDesktopAppPolicy = 18, // in ULONG (PROCESS_CREATION_DESKTOP_APP_*) // since RS2
        ProcThreadAttributeBnoIsolation = 19, // in PROC_THREAD_BNOISOLATION_ATTRIBUTE
        ProcThreadAttributePseudoConsole = 22, // in HANDLE (HPCON) // since RS5
        ProcThreadAttributeIsolationManifest = 23, // in ISOLATION_MANIFEST_PROPERTIES // rev (diversenok) // since 19H2+
        ProcThreadAttributeMitigationAuditPolicy = 24, // in ULONG, ULONG64, or ULONG64[2] // since 21H1
        ProcThreadAttributeMachineType = 25, // in USHORT // since 21H2
        ProcThreadAttributeComponentFilter = 26, // in ULONG
        ProcThreadAttributeEnableOptionalXStateFeatures = 27, // in ULONG64 // since WIN11
        ProcThreadAttributeCreateStore = 28, // ULONG // rev (diversenok)
        ProcThreadAttributeTrustedApp = 29
    }

    internal enum PROC_THREAD_ATTRIBUTES
    {
        GROUP_AFFINITY = 0x00030003,
        HANDLE_LIST = 0x00020002,
        IDEAL_PROCESSOR = 0x00030005,
        MITIGATION_POLICY = 0x00020007,
        PARENT_PROCESS = 0x00020000,
        PREFERRED_NODE = 0x00020004,
        UMS_THREAD = 0x00030006,
        SECURITY_CAPABILITIES = 0x00020009,
        PROTECTION_LEVEL = 0x0002000B,
        CHILD_PROCESS_POLICY = 0x0002000E,
        DESKTOP_APP_POLICY = 0x00020012,
        JOB_LIST = 0x0002000D,
        ENABLE_OPTIONAL_XSTATE_FEATURES = 0x0003001B,

        // Definitions for NtCreateThreadEx
        EXTENDED_FLAGS = 0x00060001, // ProcThreadAttributeValue(ProcThreadAttributeExtendedFlags, FALSE, TRUE, TRUE)
        PACKAGE_FULL_NAME = 0x00020008, // ProcThreadAttributeValue(ProcThreadAttributePackageFullName, FALSE, TRUE, FALSE)
        CONSOLE_REFERENCE = 0x0002000A, // ProcThreadAttributeValue(ProcThreadAttributeConsoleReference, FALSE, TRUE, FALSE)
        OSMAXVERSIONTESTED = 0x0002000C, // ProcThreadAttributeValue(ProcThreadAttributeOsMaxVersionTested, FALSE, TRUE, FALSE)
        SAFE_OPEN_PROMPT_ORIGIN_CLAIM = 0x00020011, // ProcThreadAttributeValue(ProcThreadAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
        BNO_ISOLATION = 0x00020013, // ProcThreadAttributeValue(ProcThreadAttributeBnoIsolation, FALSE, TRUE, FALSE)
        ISOLATION_MANIFEST = 0x00020017, // ProcThreadAttributeValue(ProcThreadAttributeIsolationManifest, FALSE, TRUE, FALSE)
        CREATE_STORE = 0x0002001C // ProcThreadAttributeValue(ProcThreadAttributeCreateStore, FALSE, TRUE, FALSE)
    }

    [Flags]
    internal enum ProcessAccessFlags : uint
    {
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        Terminate = 0x00000001,
        PROCESS_CREATE_THREAD = 0x00000002,
        PROCESS_VM_OPERATION = 0x00000008,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_VM_WRITE = 0x00000020,
        PROCESS_DUP_HANDLE = 0x00000040,
        PROCESS_CREATE_PROCESS = 0x000000080,
        PROCESS_SET_QUOTA = 0x00000100,
        PROCESS_SET_INFORMATION = 0x00000200,
        PROCESS_QUERY_INFORMATION = 0x00000400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
        SYNCHRONIZE = 0x00100000,
        MAXIMUM_ALLOWED = 0x02000000
    }

    [Flags]
    internal enum ProcessCreationFlags : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
    }
}
