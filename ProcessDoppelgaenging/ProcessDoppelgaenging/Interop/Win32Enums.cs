using System;

namespace ProcessDoppelgaenging.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        // For Process
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        PROCESS_TERMINATE = 0x00000001,
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

        // For Thread
        THREAD_ALL_ACCESS = 0x001FFFFF,
        THREAD_TERMINATE = 0x00000001,
        THREAD_SUSPEND_RESUME = 0x00000002,
        THREAD_ALERT = 0x00000004,
        THREAD_GET_CONTEXT = 0x00000008,
        THREAD_SET_CONTEXT = 0x00000010,
        THREAD_SET_INFORMATION = 0x00000020,
        THREAD_SET_LIMITED_INFORMATION = 0x00000400,
        THREAD_QUERY_LIMITED_INFORMATION = 0x00000800,

        // For Files
        FILE_ANY_ACCESS = 0x00000000,
        FILE_READ_ACCESS = 0x00000001,
        FILE_WRITE_ACCESS = 0x00000002,
        FILE_READ_DATA = 0x00000001,
        FILE_LIST_DIRECTORY = 0x00000001,
        FILE_WRITE_DATA = 0x00000002,
        FILE_ADD_FILE = 0x00000002,
        FILE_APPEND_DATA = 0x00000004,
        FILE_ADD_SUBDIRECTORY = 0x00000004,
        FILE_CREATE_PIPE_INSTANCE = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_EXECUTE = 0x00000020,
        FILE_TRAVERSE = 0x00000020,
        FILE_DELETE_CHILD = 0x00000040,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_ALL_ACCESS = 0x001F01FF,
        FILE_GENERIC_READ = 0x00100089,
        FILE_GENERIC_WRITE = 0x00100116,
        FILE_GENERIC_EXECUTE = 0x001000A0,

        // For Transaction
        TRANSACTION_QUERY_INFORMATION = 0x00000001,
        TRANSACTION_SET_INFORMATION = 0x00000002,
        TRANSACTION_ENLIST = 0x00000004,
        TRANSACTION_COMMIT = 0x00000008,
        TRANSACTION_ROLLBACK = 0x00000010,
        TRANSACTION_PROPAGATE = 0x00000020,
        TRANSACTION_RIGHT_RESERVED1 = 0x00000040,
        TRANSACTION_GENERIC_READ = 0x00120001,
        TRANSACTION_GENERIC_WRITE = 0x0012003E,
        TRANSACTION_GENERIC_EXECUTE = 0x00120018,
        TRANSACTION_ALL_ACCESS = 0x001F003F,
        TRANSACTION_RESOURCE_MANAGER_RIGHTS = 0x00120037,

        // Others
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,

        // For section
        SECTION_QUERY = 0x00000001,
        SECTION_MAP_WRITE = 0x00000002,
        SECTION_MAP_READ = 0x00000004,
        SECTION_MAP_EXECUTE = 0x00000008,
        SECTION_EXTEND_SIZE = 0x00000010,
        SECTION_MAP_EXECUTE_EXPLICIT = 0x00000020,
        SECTION_ALL_ACCESS = 0x000F001F
    }


    [Flags]
    internal enum ALLOCATION_TYPE
    {
        COMMIT = 0x1000,
        RESERVE = 0x2000,
        DECOMMIT = 0x4000,
        RELEASE = 0x8000,
        RESET = 0x80000,
        PHYSICAL = 0x400000,
        TOPDOWN = 0x100000,
        WRITEWATCH = 0x200000,
        LARGEPAGES = 0x20000000
    }

    internal enum BOOLEAN : byte
    {
        FALSE,
        TRUE
    }

    [Flags]
    internal enum FILE_ATTRIBUTES : uint
    {
        READONLY = 0x00000001,
        HIDDEN = 0x00000002,
        SYSTEM = 0x00000004,
        DIRECTORY = 0x00000010,
        ARCHIVE = 0x00000020,
        DEVICE = 0x00000040,
        NORMAL = 0x00000080,
        TEMPORARY = 0x00000100,
        SPARSE_FILE = 0x00000200,
        REPARSE_POINT = 0x00000400,
        COMPRESSED = 0x00000800,
        OFFLINE = 0x00001000,
        NOT_CONTENT_INDEXED = 0x00002000,
        ENCRYPTED = 0x00004000,
        INTEGRITY_STREAM = 0x00008000,
        VIRTUAL = 0x00010000,
        NO_SCRUB_DATA = 0x00020000,
        RECALL_ON_OPEN = 0x00040000,
        PINNED = 0x00080000,
        UNPINNED = 0x00100000,
        RECALL_ON_DATA_ACCESS = 0x00400000,
    }

    internal enum FILE_CREATE_DISPOSITION
    {
        CREATE_NEW = 1,
        CREATE_ALWAYS,
        OPEN_EXISTING,
        OPEN_ALWAYS,
        TRUNCATE_EXISTING
    }

    [Flags]
    internal enum FILE_DISPOSITION_FLAGS : uint
    {
        DO_NOT_DELETE = 0x00000000,
        DELETE = 0x00000001,
        POSIX_SEMANTICS = 0x00000002,
        FORCE_IMAGE_SECTION_CHECK = 0x00000004,
        ON_CLOSE = 0x00000008,
        IGNORE_READONLY_ATTRIBUTE = 0x00000010
    }

    internal enum FILE_INFORMATION_CLASS
    {
        FileDirectoryInformation = 1,
        FileFullDirectoryInformation,
        FileBothDirectoryInformation,
        FileBasicInformation,
        FileStandardInformation,
        FileInternalInformation,
        FileEaInformation,
        FileAccessInformation,
        FileNameInformation,
        FileRenameInformation,
        FileLinkInformation,
        FileNamesInformation,
        FileDispositionInformation,
        FilePositionInformation,
        FileFullEaInformation,
        FileModeInformation,
        FileAlignmentInformation,
        FileAllInformation,
        FileAllocationInformation,
        FileEndOfFileInformation,
        FileAlternateNameInformation,
        FileStreamInformation,
        FilePipeInformation,
        FilePipeLocalInformation,
        FilePipeRemoteInformation,
        FileMailslotQueryInformation,
        FileMailslotSetInformation,
        FileCompressionInformation,
        FileObjectIdInformation,
        FileCompletionInformation,
        FileMoveClusterInformation,
        FileQuotaInformation,
        FileReparsePointInformation,
        FileNetworkOpenInformation,
        FileAttributeTagInformation,
        FileTrackingInformation,
        FileIdBothDirectoryInformation,
        FileIdFullDirectoryInformation,
        FileValidDataLengthInformation,
        FileShortNameInformation,
        FileIoCompletionNotificationInformation,
        FileIoStatusBlockRangeInformation,
        FileIoPriorityHintInformation,
        FileSfioReserveInformation,
        FileSfioVolumeInformation,
        FileHardLinkInformation,
        FileProcessIdsUsingFileInformation,
        FileNormalizedNameInformation,
        FileNetworkPhysicalNameInformation,
        FileIdGlobalTxDirectoryInformation,
        FileMaximumInformation,
        FileIdInformation = 59,
        FileHardLinkFullIdInformation = 62,
        FileDispositionInformationEx = 64,
        FileRenameInformationEx = 65,
        FileStatInformation = 68,
        FileStatLxInformation = 70,
        FileCaseSensitiveInformation = 71,
        FileLinkInformationEx = 72,
        FileStorageReserveIdInformation = 74,
    }

    [Flags]
    internal enum FILE_OPEN_OPTIONS : uint
    {
        DIRECTORY_FILE = 0x00000001,
        WRITE_THROUGH = 0x00000002,
        SEQUENTIAL_ONLY = 0x00000004,
        NO_INTERMEDIATE_BUFFERING = 0x00000008,
        SYNCHRONOUS_IO_ALERT = 0x00000010,
        SYNCHRONOUS_IO_NONALERT = 0x00000020,
        NON_DIRECTORY_FILE = 0x00000040,
        CREATE_TREE_CONNECTION = 0x00000080,
        COMPLETE_IF_OPLOCKED = 0x00000100,
        NO_EA_KNOWLEDGE = 0x00000200,
        OPEN_REMOTE_INSTANCE = 0x00000400,
        RANDOM_ACCESS = 0x00000800,
        DELETE_ON_CLOSE = 0x00001000,
        OPEN_BY_FILE_ID = 0x00002000,
        OPEN_FOR_BACKUP_INTENT = 0x00004000,
        NO_COMPRESSION = 0x00008000,
        RESERVE_OPFILTER = 0x00100000,
        OPEN_REPARSE_POINT = 0x00200000,
        OPEN_NO_RECALL = 0x00400000,
        OPEN_FOR_FREE_SPACE_QUERY = 0x00800000,
        COPY_STRUCTURED_STORAGE = 0x00000041,
        STRUCTURED_STORAGE = 0x00000441,
        SUPERSEDE = 0x00000000,
        OPEN = 0x00000001,
        CREATE = 0x00000002,
        OPEN_IF = 0x00000003,
        OVERWRITE = 0x00000004,
        OVERWRITE_IF = 0x00000005,
        MAXIMUM_DISPOSITION = 0x00000005
    }

    [Flags]
    public enum FILE_SHARE_ACCESS : uint
    {
        NONE = 0x00000000,
        READ = 0x00000001,
        WRITE = 0x00000002,
        DELETE = 0x00000004,
        VALID_FLAGS = 0x00000007
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
    internal enum MEMORY_PROTECTION : uint
    {
        NOACCESS = 0x01,
        READONLY = 0x02,
        READWRITE = 0x04,
        WRITECOPY = 0x08,
        EXECUTE = 0x10,
        EXECUTE_READ = 0x20,
        EXECUTE_READWRITE = 0x40,
        EXECUTE_WRITECOPY = 0x80,
        GUARD = 0x100,
        NOCACHE = 0x200,
        WRITECOMBINE = 0x400
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
        OBJ_INHERIT = 0x00000002,
        OBJ_PERMANENT = 0x00000010,
        OBJ_EXCLUSIVE = 0x00000020,
        OBJ_CASE_INSENSITIVE = 0x00000040,
        OBJ_OPENIF = 0x00000080,
        OBJ_OPENLINK = 0x00000100,
        OBJ_KERNEL_HANDLE = 0x00000200,
        OBJ_FORCE_ACCESS_CHECK = 0x00000400,
        OBJ_VALID_ATTRIBUTES = 0x000007f2
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
    internal enum RTL_USER_PROC_FLAGS : uint
    {
        PARAMS_NORMALIZED = 0x00000001,
        PROFILE_USER = 0x00000002,
        PROFILE_KERNEL = 0x00000004,
        PROFILE_SERVER = 0x00000008,
        RESERVE_1MB = 0x00000020,
        RESERVE_16MB = 0x00000040,
        CASE_SENSITIVE = 0x00000080,
        DISABLE_HEAP_DECOMMIT = 0x00000100,
        DLL_REDIRECTION_LOCAL = 0x00001000,
        APP_MANIFEST_PRESENT = 0x00002000,
        IMAGE_KEY_MISSING = 0x00004000,
        OPTIN_PROCESS = 0x00020000
    }

    [Flags]
    internal enum SECTION_ATTRIBUTES : uint
    {
        SEC_IMAGE = 0x01000000,
        SEC_RESERVE = 0x04000000,
        SEC_COMMIT = 0x08000000,
        SEC_IMAGE_NO_EXECUTE = 0x11000000,
        SEC_NOCACHE = 0x10000000,
        SEC_WRITECOMBINE = 0x40000000,
        SEC_LARGE_PAGES = 0x80000000
    }


    [Flags]
    internal enum SECTION_PROTECTIONS : uint
    {
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_EXECUTE = 0x10
    }
}
