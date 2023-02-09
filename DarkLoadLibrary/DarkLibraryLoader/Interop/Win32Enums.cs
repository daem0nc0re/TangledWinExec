using System;

namespace DarkLibraryLoader.Interop
{
    [Flags]
    internal enum ALLOCATION_TYPE : uint
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


    internal enum DLLMAIN_CALL_REASON
    {
        DLL_PROCESS_DETACH,
        DLL_PROCESS_ATTACH,
        DLL_THREAD_ATTACH,
        DLL_THREAD_DETACH
    }

    internal enum IMAGE_REL_BASED_TYPE
    {
        ABSOLUTE = 0,
        HIGH = 1,
        LOW = 2,
        HIGHLOW = 3,
        HIGHADJ = 4,
        MACHINE_SPECIFIC_5 = 5,
        RESERVED = 6,
        MACHINE_SPECIFIC_7 = 7,
        MACHINE_SPECIFIC_8 = 8,
        MACHINE_SPECIFIC_9 = 9,
        DIR64 = 10
    }


    [Flags]
    internal enum LDR_DATA_TABLE_ENTRY_FLAGS : uint
    {
        LDRP_PACKAGED_BINARY = 0x00000001,
        LDRP_MARKED_FOR_REMOVAL = 0x00000002,
        LDRP_IMAGE_DLL = 0x00000004,
        LDRP_LOAD_NOTIFICATIONS_SENT = 0x00000008,
        LDRP_TELEMETRY_ENTRY_PROCESSED = 0x00000010,
        LDRP_PROCESS_STATIC_IMPORT = 0x00000020,
        LDRP_IN_LEGACY_LISTS = 0x00000040,
        LDRP_IN_INDEXES = 0x00000080,
        LDRP_SHIM_DLL = 0x00000100,
        LDRP_IN_EXCEPTION_TABLE = 0x00000200,
        LDRP_LOAD_IN_PROGRESS = 0x00001000,
        LDRP_LOAD_CONFIG_PROCESSED = 0x00002000,
        LDRP_ENTRY_PROCESSED = 0x00004000,
        LDRP_PROTECT_DELAY_LOAD = 0x00008000,
        LDRP_DONT_CALL_FOR_THREADS = 0x00040000,
        LDRP_PROCESS_ATTACH_CALLED = 0x00080000,
        LDRP_PROCESS_ATTACH_FAILED = 0x00100000,
        LDRP_COR_DEFERRED_VALIDATE = 0x00200000,
        LDRP_COR_IMAGE = 0x00400000,
        LDRP_DONT_RELOCATE = 0x00800000,
        LDRP_COR_IL_ONLY = 0x01000000,
        LDRP_CHPE_IMAGE = 0x02000000,
        LDRP_CHPE_EMULATOR_IMAGE = 0x04000000,
        LDRP_REDIRECTED = 0x10000000,
        LDRP_COMPAT_DATABASE_PROCESSED = 0x80000000
    }

    [Flags]
    internal enum LDR_DATA_TABLE_ENTRY_FLAGS_INTERNAL : uint
    {
        PackagedBinary = 0x00000001,
        MarkedForRemoval = 0x00000002,
        ImageDll = 0x00000004,
        LoadNotificationsSent = 0x00000008,
        TelemetryEntryProcessed = 0x00000010,
        ProcessStaticImport = 0x00000020,
        InLegacyLists = 0x00000040,
        InIndexes = 0x00000080,
        ShimDll = 0x00000100,
        InExceptionTable = 0x00000200,
        ReservedFlags1 = 0x00000C00,
        LoadInProgress = 0x00001000,
        LoadConfigProcessed = 0x00002000,
        EntryProcessed = 0x00004000,
        ProtectDelayLoad = 0x00008000,
        ReservedFlags3 = 0x00030000,
        DontCallForThreads = 0x00040000,
        ProcessAttachCalled = 0x00080000,
        ProcessAttachFailed = 0x00100000,
        CorDeferredValidate = 0x00200000,
        CorImage = 0x00400000,
        DontRelocate = 0x00800000,
        CorILOnly = 0x01000000,
        ChpeImage = 0x02000000,
        ReservedFlags5 = 0x0C000000,
        Redirected = 0x10000000,
        ReservedFlags6 = 0x60000000,
        CompatDatabaseProcessed = 0x80000000
    }

    internal enum LDR_DDAG_STATE
    {
        LdrModulesMerged = -5,
        LdrModulesInitError = -4,
        LdrModulesSnapError = -3,
        LdrModulesUnloaded = -2,
        LdrModulesUnloading = -1,
        LdrModulesPlaceHolder = 0,
        LdrModulesMapping = 1,
        LdrModulesMapped = 2,
        LdrModulesWaitingForDependencies = 3,
        LdrModulesSnapping = 4,
        LdrModulesSnapped = 5,
        LdrModulesCondensed = 6,
        LdrModulesReadyToInit = 7,
        LdrModulesInitializing = 8,
        LdrModulesReadyToRun = 9
    }

    internal enum LDR_DLL_LOAD_REASON
    {
        StaticDependency = 0,
        StaticForwarderDependency = 1,
        DynamicForwarderDependency = 2,
        DelayloadDependency = 3,
        DynamicLoad = 4,
        AsImageLoad = 5,
        AsDataLoad = 6,
        EnclavePrimary = 7,
        EnclaveDependency = 8,
        PatchImage = 9,
        Unknown = -1
    }

    internal enum LDR_HOT_PATCH_STATE
    {
        LdrHotPatchBaseImage = 0,
        LdrHotPatchNotApplied = 1,
        LdrHotPatchAppliedReverse = 2,
        LdrHotPatchAppliedForward = 3,
        LdrHotPatchFailedToPatch = 4,
        LdrHotPatchStateMax = 5
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

    internal enum PROCESSINFOCLASS
    {
        ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
        ProcessLdtSize, // s: PROCESS_LDT_SIZE
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
        ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
        ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // q: HANDLE // 30
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
        ProcessIoPriority, // qs: IO_PRIORITY_HINT
        ProcessExecuteFlags, // qs: ULONG
        ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
        ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
        ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
        ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
        ProcessHandleTable, // q: ULONG[] // since WINBLUE
        ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
        ProcessCommandLineInformation, // q: UNICODE_STRING // 60
        ProcessProtectionInformation, // q: PS_PROTECTION
        ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
        ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
        ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
        ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
        ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
        ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
        ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
        ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
        ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
        ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
        ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
        ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
        ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
        ProcessDisableSystemAllowedCpuSets, // 80
        ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
        ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
        ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ProcessCaptureTrustletLiveDump,
        ProcessTelemetryCoverage,
        ProcessEnclaveInformation,
        ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
        ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
        ProcessImageSection, // q: HANDLE
        ProcessDebugAuthInformation, // since REDSTONE4 // 90
        ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
        ProcessSequenceNumber, // q: ULONGLONG
        ProcessLoaderDetour, // since REDSTONE5
        ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
        ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
        ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
        ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
        ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
        ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
        ProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
        ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
        ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
        ProcessCreateStateChange, // since WIN11
        ProcessApplyStateChange,
        ProcessEnableOptionalXStateFeatures,
        ProcessAltPrefetchParam, // since 22H1
        ProcessAssignCpuPartitions,
        ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
        ProcessMembershipInformation,
        ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
        ProcessEffectivePagePriority, // q: ULONG
        MaxProcessInfoClass
    }

    [Flags]
    internal enum SectionFlags : uint
    {
        TYPE_NO_PAD = 0x00000008,
        CNT_CODE = 0x00000020,
        CNT_INITIALIZED_DATA = 0x00000040,
        CNT_UNINITIALIZED_DATA = 0x00000080,
        LNK_INFO = 0x00000200,
        LNK_REMOVE = 0x00000800,
        LNK_COMDAT = 0x00001000,
        NO_DEFER_SPEC_EXC = 0x00004000,
        GPREL = 0x00008000,
        MEM_FARDATA = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000,
        ALIGN_32BYTES = 0x00600000,
        ALIGN_64BYTES = 0x00700000,
        ALIGN_128BYTES = 0x00800000,
        ALIGN_256BYTES = 0x00900000,
        ALIGN_512BYTES = 0x00A00000,
        ALIGN_1024BYTES = 0x00B00000,
        ALIGN_2048BYTES = 0x00C00000,
        ALIGN_4096BYTES = 0x00D00000,
        ALIGN_8192BYTES = 0x00E00000,
        ALIGN_MASK = 0x00F00000,
        LNK_NRELOC_OVFL = 0x01000000,
        MEM_DISCARDABLE = 0x02000000,
        MEM_NOT_CACHED = 0x04000000,
        MEM_NOT_PAGED = 0x08000000,
        MEM_SHARED = 0x10000000,
        MEM_EXECUTE = 0x20000000,
        MEM_READ = 0x40000000,
        MEM_WRITE = 0x80000000
    }
}
