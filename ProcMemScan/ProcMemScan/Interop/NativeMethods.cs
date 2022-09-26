using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcMemScan.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool GetVolumePathName(
            string lpszFileName,
            StringBuilder lpszVolumePathName,
            int cchBufferLength);

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

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int QueryDosDevice(
            string lpDeviceName,
            StringBuilder lpTargetPath,
            int ucchMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int QueryDosDevice(
            string lpDeviceName,
            IntPtr lpTargetPath,
            int ucchMax);

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
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            out IO_STATUS_BLOCK IoStatusBlock,
            in LARGE_INTEGER AllocationSize,
            FILE_ATTRIBUTE_FLAGS FileAttributes,
            FILE_SHARE_ACCESS ShareAccess,
            FILE_CREATE_DISPOSITION CreateDisposition,
            FILE_CREATE_OPTIONS CreateOptions,
            IntPtr EaBuffer,
            uint EaLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr IoStatusBlock,
            IntPtr AllocationSize,
            FILE_ATTRIBUTE_FLAGS FileAttributes,
            FILE_SHARE_ACCESS ShareAccess,
            FILE_CREATE_DISPOSITION CreateDisposition,
            FILE_CREATE_OPTIONS CreateOptions,
            IntPtr EaBuffer,
            uint EaLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenProcess(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            in CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESS_INFORMATION_CLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESS_INFORMATION_CLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            MEMORY_INFORMATION_CLASS MemoryInformationClass,
            IntPtr MemoryInformation,
            SIZE_T MemoryInformationLength,
            out SIZE_T ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            MEMORY_INFORMATION_CLASS MemoryInformationClass,
            IntPtr MemoryInformation,
            SIZE_T MemoryInformationLength,
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

        /*
         * Psapi.dll
         */
        [DllImport("Psapi.dll", SetLastError = true)]
        public static extern int GetMappedFileName(
            IntPtr hProcess,
            IntPtr fileHandle,
            StringBuilder lpFilename,
            int nSize);
    }
}
