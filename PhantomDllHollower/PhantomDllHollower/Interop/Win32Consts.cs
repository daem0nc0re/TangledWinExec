using System;

namespace PhantomDllHollower.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_IMAGE_NOT_AT_BASE = 0x40000003;
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        public static readonly NTSTATUS STATUS_OBJECT_TYPE_MISMATCH = Convert.ToInt32("0xC0000024", 16);
        public static readonly NTSTATUS STATUS_OBJECT_NAME_NOT_FOUND = Convert.ToInt32("0xC0000034", 16);
        public static readonly NTSTATUS STATUS_NOT_SUPPORTED = Convert.ToInt32("0xC00000BB", 16);
        public const int MAX_PATH = 260;
    }
}
