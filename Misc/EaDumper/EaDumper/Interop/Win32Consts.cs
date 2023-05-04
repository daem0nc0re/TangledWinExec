using System;

namespace EaDumper.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_BUFFER_OVERFLOW = Convert.ToInt32("0x80000005", 16);
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        public static readonly NTSTATUS STATUS_OBJECT_PATH_SYNTAX_BAD = Convert.ToInt32("0xC000003B", 16);
    }
}
