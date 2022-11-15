using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcessDoppelgaenging.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        /*
         * kenel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileTransacted(
            string lpFileName,
            ACCESS_MASK dwDesiredAccess,
            FILE_SHARE_ACCESS dwShareMode,
            SECURITY_ATTRIBUTES lpSecurityAttributes,
            FILE_CREATE_DISPOSITION dwCreationDisposition,
            FILE_ATTRIBUTES dwFlagsAndAttributes,
            IntPtr hTemplateFile,
            IntPtr hTransaction,
            in ushort pusMiniVersion,
            IntPtr lpExtendedParameter);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileTransacted(
            string lpFileName,
            ACCESS_MASK dwDesiredAccess,
            FILE_SHARE_ACCESS dwShareMode,
            SECURITY_ATTRIBUTES lpSecurityAttributes,
            FILE_CREATE_DISPOSITION dwCreationDisposition,
            FILE_ATTRIBUTES dwFlagsAndAttributes,
            IntPtr hTemplateFile,
            IntPtr hTransaction,
            IntPtr pusMiniVersion,
            IntPtr lpExtendedParameter);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileTransacted(
            string lpFileName,
            ACCESS_MASK dwDesiredAccess,
            FILE_SHARE_ACCESS dwShareMode,
            IntPtr lpSecurityAttributes,
            FILE_CREATE_DISPOSITION dwCreationDisposition,
            FILE_ATTRIBUTES dwFlagsAndAttributes,
            IntPtr hTemplateFile,
            IntPtr hTransaction,
            IntPtr pusMiniVersion,
            IntPtr lpExtendedParameter);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(
            IntPtr hProcess,
            out bool Wow64Process);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int SearchPath(
            string lpPath,
            string lpFileName,
            string lpExtension,
            int nBufferLength,
            StringBuilder lpBuffer,
            IntPtr lpFilePart);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            SIZE_T ZeroBits,
            ref SIZE_T RegionSize,
            ALLOCATION_TYPE AllocationType,
            MEMORY_PROTECTION Protect);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateProcessEx(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr ParentProcess,
            NT_PROCESS_CREATION_FLAGS Flags,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            BOOLEAN InJob);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateProcessEx(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr pObjectAttributes,
            IntPtr ParentProcess,
            NT_PROCESS_CREATION_FLAGS Flags,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            BOOLEAN InJob);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateSection(
            out IntPtr SectionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            in LARGE_INTEGER MaximumSize,
            SECTION_PROTECTIONS SectionPageProtection,
            SECTION_ATTRIBUTES AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateSection(
            out IntPtr SectionHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr pObjectAttributes,
            in LARGE_INTEGER MaximumSize,
            SECTION_PROTECTIONS SectionPageProtection,
            SECTION_ATTRIBUTES AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateSection(
            out IntPtr SectionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr pMaximumSize,
            SECTION_PROTECTIONS SectionPageProtection,
            SECTION_ATTRIBUTES AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateSection(
            out IntPtr SectionHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr pObjectAttributes,
            IntPtr pMaximumSize,
            SECTION_PROTECTIONS SectionPageProtection,
            SECTION_ATTRIBUTES AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateTransaction(
            out IntPtr TransactionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr Uow,
            IntPtr TmHandle,
            uint CreateOptions,
            uint IsolationLevel,
            uint IsolationFlags,
            in LARGE_INTEGER Timeout,
            in UNICODE_STRING Description);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateTransaction(
            out IntPtr TransactionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr Uow,
            IntPtr TmHandle,
            uint CreateOptions,
            uint IsolationLevel,
            uint IsolationFlags,
            IntPtr Timeout,
            IntPtr Description);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateTransaction(
            out IntPtr TransactionHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr pObjectAttributes,
            IntPtr Uow,
            IntPtr TmHandle,
            uint CreateOptions,
            uint IsolationLevel,
            uint IsolationFlags,
            IntPtr Timeout,
            IntPtr Description);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateThreadEx(
            out IntPtr ThreadHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr pObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr StartAddress,
            IntPtr Parameter,
            bool inCreateSuspended,
            int StackZeroBits,
            int SizeOfStack,
            int MaximumStackSize,
            IntPtr AttributeList);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            out IO_STATUS_BLOCK IoStatusBlock,
            FILE_SHARE_ACCESS ShareAccess,
            FILE_OPEN_OPTIONS OpenOptions);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr pIoStatusBlock,
            FILE_SHARE_ACCESS ShareAccess,
            FILE_OPEN_OPTIONS OpenOptions);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenProcess(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            in CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref uint NumberOfBytesToProtect,
            MEMORY_PROTECTION NewAccessProtection,
            out MEMORY_PROTECTION OldAccessProtection);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref uint NumberOfBytesToProtect,
            MEMORY_PROTECTION NewAccessProtection,
            IntPtr pOldAccessProtection);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            out uint NumberOfBytesReaded);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            IntPtr NumberOfBytesReaded);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtRollbackTransaction(
            IntPtr TransactionHandle,
            BOOLEAN Wait);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetInformationFile(
            IntPtr FileHandle,
            out IO_STATUS_BLOCK IoStatusBlock,
            in FILE_DISPOSITION_INFORMATION FileInformation,
            uint Length,
            FILE_INFORMATION_CLASS FileInformationClass);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetInformationFile(
            IntPtr FileHandle,
            IntPtr pIoStatusBlock,
            in FILE_DISPOSITION_INFORMATION FileInformation,
            uint Length,
            FILE_INFORMATION_CLASS FileInformationClass);

        // When FileInformationClass is FileDispositionInformationEx 
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetInformationFile(
            IntPtr FileHandle,
            out IO_STATUS_BLOCK IoStatusBlock,
            in FILE_DISPOSITION_INFORMATION_EX FileInformation,
            uint Length,
            FILE_INFORMATION_CLASS FileInformationClass);

        // When FileInformation is FileDispositionInformationEx 
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetInformationFile(
            IntPtr FileHandle,
            IntPtr pIoStatusBlock,
            in FILE_DISPOSITION_INFORMATION_EX FileInformation,
            uint Length,
            FILE_INFORMATION_CLASS FileInformationClass);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtTerminateProcess(
            IntPtr ProcessHandle,
            NTSTATUS ExitStatus);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer,
            uint Length,
            in LARGE_INTEGER ByteOffset,
            IntPtr Key); // Should be null.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            IntPtr pIoStatusBlock,
            IntPtr Buffer,
            uint Length,
            [Optional] in LARGE_INTEGER ByteOffset,
            IntPtr Key); // Should be null.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key); // Should be null.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            IntPtr pIoStatusBlock,
            IntPtr Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key); // Should be null.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            out IO_STATUS_BLOCK IoStatusBlock,
            byte[] Buffer,
            uint Length,
            in LARGE_INTEGER ByteOffset,
            IntPtr Key); // Should be null.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            IntPtr pIoStatusBlock,
            byte[] Buffer,
            uint Length,
            [Optional] in LARGE_INTEGER ByteOffset,
            IntPtr Key); // Should be null.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            out IO_STATUS_BLOCK IoStatusBlock,
            byte[] Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key); // Should be null.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            IntPtr pIoStatusBlock,
            byte[] Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key); // Should be null.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToWrite,
            out uint NumberOfBytesWritten);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToWrite,
            IntPtr NumberOfBytesWritten);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlCreateProcessParametersEx(
            out IntPtr /* PRTL_USER_PROCESS_PARAMETERS */ pProcessParameters,
            in UNICODE_STRING ImagePathName,
            in UNICODE_STRING pDllPath,
            in UNICODE_STRING CurrentDirectory,
            in UNICODE_STRING CommandLine,
            IntPtr Environment,
            in UNICODE_STRING WindowTitle,
            in UNICODE_STRING DesktopInfo,
            IntPtr pShellInfo,
            IntPtr pRuntimeData,
            RTL_USER_PROC_FLAGS Flags); // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlDestroyProcessParameters(
            IntPtr /* PRTL_USER_PROCESS_PARAMETERS */ ProcessParameters);

        /*
         * userenv.dll
         */
        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment,
            IntPtr hToken,
            bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
    }
}
