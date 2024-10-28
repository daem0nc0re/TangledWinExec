using System;

namespace ProcMemScan.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_MORE_ENTRIES = 0x00000105;
        public static readonly NTSTATUS STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
        public static readonly NTSTATUS STATUS_ACCESS_DENIED = Convert.ToInt32("0xC0000022", 16);
        public static readonly NTSTATUS STATUS_PRIVILEGE_NOT_HELD = Convert.ToInt32("0xC0000061", 16);
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const int ERROR_INSUFFICIENT_BUFFER = 0x7A;
        public const int MAX_PATH = 260;
        public const uint MAX_SYM_NAME = 2000;
    }
}
