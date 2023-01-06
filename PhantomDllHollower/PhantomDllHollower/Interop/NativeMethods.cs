using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PhantomDllHollower.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

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

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            out IO_STATUS_BLOCK IoStatusBlock,
            in LARGE_INTEGER AllocationSize,
            FILE_ATTRIBUTES FileAttributes,
            FILE_SHARE_ACCESS ShareAccess,
            NT_FILE_CREATE_DISPOSITION CreateDisposition,
            FILE_OPEN_OPTIONS CreateOptions,
            IntPtr EaBuffer,
            uint EaLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr IoStatusBlock,
            IntPtr AllocationSize,
            FILE_ATTRIBUTES FileAttributes,
            FILE_SHARE_ACCESS ShareAccess,
            NT_FILE_CREATE_DISPOSITION CreateDisposition,
            FILE_OPEN_OPTIONS CreateOptions,
            IntPtr EaBuffer,
            uint EaLength);

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
        public static extern NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            SIZE_T CommitSize,
            ref LARGE_INTEGER SectionOffset,
            ref SIZE_T ViewSize,
            SECTION_INHERIT InheritDisposition,
            ALLOCATION_TYPE AllocationType,
            MEMORY_PROTECTION Win32Protect);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            SIZE_T CommitSize,
            IntPtr pSectionOffset,
            ref SIZE_T ViewSize,
            SECTION_INHERIT InheritDisposition,
            ALLOCATION_TYPE AllocationType,
            MEMORY_PROTECTION Win32Protect);

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
            IntPtr pOldAccessProtection); // Should not be nullptr


        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySecurityObject(
            IntPtr Handle,
            SECURITY_INFORMATION SecurityInformation,
            IntPtr SecurityDescriptor,
            uint Length,
            out uint LengthNeeded);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtRollbackTransaction(
            IntPtr TransactionHandle,
            BOOLEAN Wait);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtTerminateThread(
            IntPtr ThreadHandle,
            NTSTATUS ExitStatus);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            BOOLEAN Alertable,
            in LARGE_INTEGER Timeout);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            BOOLEAN Alertable,
            IntPtr Timeout);

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
            byte[] Buffer,
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
        public static extern NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            uint NumberOfBytesToWrite,
            IntPtr NumberOfBytesWritten);
    }
}
