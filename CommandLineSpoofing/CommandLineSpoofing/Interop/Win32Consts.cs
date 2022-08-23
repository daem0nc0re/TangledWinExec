using System;

namespace CommandLineSpoofing.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const int MAX_PATH = 260;
    }
}
