using System;

namespace ProcessHerpaderping.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const int MAX_PATH = 260;
    }
}
