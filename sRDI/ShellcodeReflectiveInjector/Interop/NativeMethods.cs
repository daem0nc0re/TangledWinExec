using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ShellcodeReflectiveInjector.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        /*
         * kernel32.dll
         */
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
        public static extern IntPtr OpenProcess(
            ACCESS_MASK dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            SIZE_T dwSize,
            ALLOCATION_TYPE flAllocationType,
            MEMORY_PROTECTION flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            SIZE_T dwSize,
            ALLOCATION_TYPE flAllocationType,
            MEMORY_PROTECTION flProtect);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

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
        public static extern NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref uint NumberOfBytesToProtect,
            MEMORY_PROTECTION NewAccessProtection,
            out MEMORY_PROTECTION OldAccessProtection);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            BOOLEAN Alertable,
            IntPtr Timeout);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            uint NumberOfBytesToWrite,
            out uint NumberOfBytesWritten);
    }
}