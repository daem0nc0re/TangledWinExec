using System;

namespace RemoteForking.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        NO_ACCESS = 0x00000000,

        // Process
        PROCESS_TERMINATE = 0x00000001,
        PROCESS_CREATE_THREAD = 0x00000002,
        PROCESS_SET_SESSIONID = 0x00000004,
        PROCESS_VM_OPERATION = 0x00000008,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_VM_WRITE = 0x00000020,
        PROCESS_DUP_HANDLE = 0x00000040,
        PROCESS_CREATE_PROCESS = 0x00000080,
        PROCESS_SET_QUOTA = 0x00000100,
        PROCESS_SET_INFORMATION = 0x00000200,
        PROCESS_QUERY_INFORMATION = 0x00000400,
        PROCESS_SUSPEND_RESUME = 0x00000800,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
        PROCESS_SET_LIMITED_INFORMATION = 0x00002000,
        PROCESS_ALL_ACCESS = 0x001FFFFF,

        // Thread
        THREAD_TERMINATE = 0x00000001,
        THREAD_SUSPEND_RESUME = 0x00000002,
        THREAD_GET_CONTEXT = 0x00000008,
        THREAD_SET_CONTEXT = 0x00000010,
        THREAD_QUERY_INFORMATION = 0x00000040,
        THREAD_SET_INFORMATION = 0x00000020,
        THREAD_SET_THREAD_TOKEN = 0x00000080,
        THREAD_IMPERSONATE = 0x00000100,
        THREAD_DIRECT_IMPERSONATION = 0x00000200,
        THREAD_SET_LIMITED_INFORMATION = 0x00000400,
        THREAD_QUERY_LIMITED_INFORMATION = 0x00000800,
        THREAD_RESUME = 0x00001000,
        THREAD_ALL_ACCESS = 0x001FFFFF,

        // Generic
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        MAXIMUM_ALLOWED = 0x02000000
    }

    internal enum BOOLEAN : byte
    {
        FALSE,
        TRUE
    }

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

    [Flags]
    internal enum NT_PROCESS_CREATION_FLAGS : uint
    {
        NONE = 0,
        BREAKAWAY = 0x00000001,
        NO_DEBUG_INHERIT = 0x00000002,
        INHERIT_HANDLES = 0x00000004,
        OVERRIDE_ADDRESS_SPACE = 0x00000008,
        LARGE_PAGES = 0x00000010,
        LARGE_PAGE_SYSTEM_DLL = 0x00000020,
        PROTECTED_PROCESS = 0x00000040,
        CREATE_SESSION = 0x00000080,
        INHERIT_FROM_PARENT = 0x00000100,
        SUSPENDED = 0x00000200,
        EXTENDED_UNKNOWN = 0x00000400
    }

    [Flags]
    internal enum OBJECT_ATTRIBUTES_FLAGS : uint
    {
        None = 0x00000000,
        ProtectClose = 0x00000001,
        Inherit = 0x00000002,
        AuditObjectClose = 0x00000004,
        NoEightsUpgrade = 0x00000008,
        Permanent = 0x00000010,
        Exclusive = 0x00000020,
        CaseInsensitive = 0x00000040,
        OpenIf = 0x00000080,
        OpenLink = 0x00000100,
        KernelHandle = 0x00000200,
        ForceAccessCheck = 0x00000400,
        IgnoreImpersonatedDevicemap = 0x00000800,
        DontReparse = 0x00001000,
        ValieAttributes = 0x00001FF2
    }

    internal enum PROCESS_INFORMATION_CLASS
    {
        ProcessBasicInformation = 0x00,
        ProcessQuotaLimits = 0x01,
        ProcessIoCounters = 0x02,
        ProcessVmCounters = 0x03,
        ProcessTimes = 0x04,
        ProcessBasePriority = 0x05,
        ProcessRaisePriority = 0x06,
        ProcessDebugPort = 0x07,
        ProcessExceptionPort = 0x08,
        ProcessAccessToken = 0x09,
        ProcessLdtInformation = 0x0A,
        ProcessLdtSize = 0x0B,
        ProcessDefaultHardErrorMode = 0x0C,
        ProcessIoPortHandlers = 0x0D,
        ProcessPooledUsageAndLimits = 0x0E,
        ProcessWorkingSetWatch = 0x0F,
        ProcessUserModeIOPL = 0x10,
        ProcessEnableAlignmentFaultFixup = 0x11,
        ProcessPriorityClass = 0x12,
        ProcessWx86Information = 0x13,
        ProcessHandleCount = 0x14,
        ProcessAffinityMask = 0x15,
        ProcessPriorityBoost = 0x16,
        ProcessDeviceMap = 0x17,
        ProcessSessionInformation = 0x18,
        ProcessForegroundInformation = 0x19,
        ProcessWow64Information = 0x1A,
        ProcessImageFileName = 0x1B,
        ProcessLUIDDeviceMapsEnabled = 0x1C,
        ProcessBreakOnTermination = 0x1D,
        ProcessDebugObjectHandle = 0x1E,
        ProcessDebugFlags = 0x1F,
        ProcessHandleTracing = 0x20,
        ProcessIoPriority = 0x21,
        ProcessExecuteFlags = 0x22,
        ProcessResourceManagement = 0x23,
        ProcessCookie = 0x24,
        ProcessImageInformation = 0x25,
        ProcessCycleTime = 0x26,
        ProcessPagePriority = 0x27,
        ProcessInstrumentationCallback = 0x28,
        ProcessThreadStackAllocation = 0x29,
        ProcessWorkingSetWatchEx = 0x2A,
        ProcessImageFileNameWin32 = 0x2B,
        ProcessImageFileMapping = 0x2C,
        ProcessAffinityUpdateMode = 0x2D,
        ProcessMemoryAllocationMode = 0x2E,
        ProcessGroupInformation = 0x2F,
        ProcessTokenVirtualizationEnabled = 0x30,
        ProcessConsoleHostProcess = 0x31,
        ProcessWindowInformation = 0x32,
        ProcessHandleInformation = 0x33,
        ProcessMitigationPolicy = 0x34,
        ProcessDynamicFunctionTableInformation = 0x35,
        ProcessHandleCheckingMode = 0x36,
        ProcessKeepAliveCount = 0x37,
        ProcessRevokeFileHandles = 0x38,
        ProcessWorkingSetControl = 0x39,
        ProcessHandleTable = 0x3A,
        ProcessCheckStackExtentsMode = 0x3B,
        ProcessCommandLineInformation = 0x3C,
        ProcessProtectionInformation = 0x3D,
        ProcessMemoryExhaustion = 0x3E,
        ProcessFaultInformation = 0x3F,
        ProcessTelemetryIdInformation = 0x40,
        ProcessCommitReleaseInformation = 0x41,
        ProcessDefaultCpuSetsInformation = 0x42,
        ProcessAllowedCpuSetsInformation = 0x43,
        ProcessSubsystemProcess = 0x44,
        ProcessJobMemoryInformation = 0x45,
        ProcessInPrivate = 0x46,
        ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
        ProcessIumChallengeResponse = 0x48,
        ProcessChildProcessInformation = 0x49,
        ProcessHighGraphicsPriorityInformation = 0x4A,
        ProcessSubsystemInformation = 0x4B,
        ProcessEnergyValues = 0x4C,
        ProcessActivityThrottleState = 0x4D,
        ProcessActivityThrottlePolicy = 0x4E,
        ProcessWin32kSyscallFilterInformation = 0x4F,
        ProcessDisableSystemAllowedCpuSets = 0x50,
        ProcessWakeInformation = 0x51,
        ProcessEnergyTrackingState = 0x52,
        ProcessManageWritesToExecutableMemory = 0x53,
        ProcessCaptureTrustletLiveDump = 0x54,
        ProcessTelemetryCoverage = 0x55,
        ProcessEnclaveInformation = 0x56,
        ProcessEnableReadWriteVmLogging = 0x57,
        ProcessUptimeInformation = 0x58,
        ProcessImageSection = 0x59,
        ProcessDebugAuthInformation = 0x5A,
        ProcessSystemResourceManagement = 0x5B,
        ProcessSequenceNumber = 0x5C,
        ProcessLoaderDetour = 0x5D,
        ProcessSecurityDomainInformation = 0x5E,
        ProcessCombineSecurityDomainsInformation = 0x5F,
        ProcessEnableLogging = 0x60,
        ProcessLeapSecondInformation = 0x61,
        ProcessFiberShadowStackAllocation = 0x62,
        ProcessFreeFiberShadowStackAllocation = 0x63,
        MaxProcessInfoClass = 0x64
    }

    [Flags]
    internal enum RTL_PROCESS_REFLECTION_FLAGS : uint
    {
        INHERIT_HANDLES = 0x00000002,
        NO_SUSPEND = 0x00000004,
        NO_SYNCHRONIZE = 0x00000008,
        NO_CLOSE_EVENT = 0x00000010
    }

    [Flags]
    internal enum SE_PRIVILEGE_ATTRIBUTES : uint
    {
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
        SE_PRIVILEGE_ENABLED = 0x00000002,
        SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    internal enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer,
        SidTypeLabel,
        SidTypeLogonSession
    }

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1, // q: TOKEN_USER
        TokenGroups, // q: TOKEN_GROUPS
        TokenPrivileges, // q: TOKEN_PRIVILEGES
        TokenOwner, // q; s: TOKEN_OWNER
        TokenPrimaryGroup, // q; s: TOKEN_PRIMARY_GROUP
        TokenDefaultDacl, // q; s: TOKEN_DEFAULT_DACL
        TokenSource, // q: TOKEN_SOURCE
        TokenType, // q: TOKEN_TYPE
        TokenImpersonationLevel, // q: SECURITY_IMPERSONATION_LEVEL
        TokenStatistics, // q: TOKEN_STATISTICS // 10
        TokenRestrictedSids, // q: TOKEN_GROUPS
        TokenSessionId, // q; s: ULONG (requires SeTcbPrivilege)
        TokenGroupsAndPrivileges, // q: TOKEN_GROUPS_AND_PRIVILEGES
        TokenSessionReference, // s: ULONG (requires SeTcbPrivilege)
        TokenSandBoxInert, // q: ULONG
        TokenAuditPolicy, // q; s: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
        TokenOrigin, // q; s: TOKEN_ORIGIN (requires SeTcbPrivilege)
        TokenElevationType, // q: TOKEN_ELEVATION_TYPE
        TokenLinkedToken, // q; s: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
        TokenElevation, // q: TOKEN_ELEVATION // 20
        TokenHasRestrictions, // q: ULONG
        TokenAccessInformation, // q: TOKEN_ACCESS_INFORMATION
        TokenVirtualizationAllowed, // q; s: ULONG (requires SeCreateTokenPrivilege)
        TokenVirtualizationEnabled, // q; s: ULONG
        TokenIntegrityLevel, // q; s: TOKEN_MANDATORY_LABEL
        TokenUIAccess, // q; s: ULONG
        TokenMandatoryPolicy, // q; s: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
        TokenLogonSid, // q: TOKEN_GROUPS
        TokenIsAppContainer, // q: ULONG
        TokenCapabilities, // q: TOKEN_GROUPS // 30
        TokenAppContainerSid, // q: TOKEN_APPCONTAINER_INFORMATION
        TokenAppContainerNumber, // q: ULONG
        TokenUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceGroups, // q: TOKEN_GROUPS
        TokenRestrictedDeviceGroups, // q: TOKEN_GROUPS
        TokenSecurityAttributes, // q; s: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION
        TokenIsRestricted, // q: ULONG // 40
        TokenProcessTrustLevel, // q: TOKEN_PROCESS_TRUST_LEVEL
        TokenPrivateNameSpace, // q; s: ULONG
        TokenSingletonAttributes, // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION
        TokenBnoIsolation, // q: TOKEN_BNO_ISOLATION_INFORMATION
        TokenChildProcessFlags, // s: ULONG
        TokenIsLessPrivilegedAppContainer, // q: ULONG
        TokenIsSandboxed, // q: ULONG
        TokenIsAppSilo, // TokenOriginatingProcessTrustLevel // q: TOKEN_PROCESS_TRUST_LEVEL
        MaxTokenInfoClass
    }

    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }


    [Flags]
    internal enum TokenAccessFlags : uint
    {
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_GROUPS = 0x0040,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_EXECUTE = 0x00020000,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY = 0x0008,
        TOKEN_QUERY_SOURCE = 0x0010,
        TOKEN_READ = 0x00020008,
        TOKEN_WRITE = 0x000200E0,
        TOKEN_ALL_ACCESS = 0x000F01FF,
        MAXIMUM_ALLOWED = 0x02000000
    }
}
