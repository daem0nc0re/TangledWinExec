using System;

namespace GetEPROCESSBaseCmdlet.Interop
{
    using NTSTATUS = Int32;

    internal sealed class Win32Consts
    {
        internal const NTSTATUS STATUS_SUCCESS = 0x00000000;
        internal const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = unchecked((NTSTATUS)0xC0000004);
    }
}
