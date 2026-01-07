using System;
using System.Runtime.InteropServices;

namespace GetEPROCESSBase.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("ntdll.dll")]
        internal static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        internal static extern NTSTATUS NtOpenProcess(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            in CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        internal static extern NTSTATUS NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);
    }
}
