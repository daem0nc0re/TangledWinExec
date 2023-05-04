using System;
using System.Runtime.InteropServices;
using System.Text;

namespace EaDumper.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FileTimeToSystemTime(
            in LARGE_INTEGER lpFileTime,
            out SYSTEMTIME lpSystemTime);

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
        public static extern bool GetCachedSigningLevel(
            IntPtr File,
            out SIGNING_LEVEL_FILE_CACHE_FLAG Flags,
            out SE_SIGNING_LEVEL SigningLevel,
            IntPtr /*out byte*/ Thumbprint,
            ref uint /*IntPtr /* PULONG */ ThumbprintSize,
            out uint ThumbprintAlgorithm);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SystemTimeToTzSpecificLocalTime(
            in TIME_ZONE_INFORMATION lpTimeZoneInformation,
            in SYSTEMTIME lpUniversalTime,
            out SYSTEMTIME lpLocalTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SystemTimeToTzSpecificLocalTime(
            IntPtr lpTimeZoneInformation,
            in SYSTEMTIME lpUniversalTime,
            out SYSTEMTIME lpLocalTime);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            out IO_STATUS_BLOCK IoStatusBlock,
            FILE_SHARE ShareAccess,
            FILE_CREATE_OPTIONS OpenOptions);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryEaFile(
            IntPtr FileHandle,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer,
            uint Length,
            BOOLEAN ReturnSingleEntry,
            IntPtr EaList,
            uint EaListLength,
            in uint EaIndex, // Optional
            BOOLEAN RestartScan);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryEaFile(
            IntPtr FileHandle,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer,
            uint Length,
            BOOLEAN ReturnSingleEntry,
            IntPtr EaList,
            uint EaListLength,
            IntPtr EaIndex, // Optional
            BOOLEAN RestartScan);
    }
}
