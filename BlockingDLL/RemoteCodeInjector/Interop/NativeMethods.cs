using System;
using System.Runtime.InteropServices;
using System.Text;

namespace RemoteCodeInjector.Interop
{
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            SIZE_T dwStackSize,
            DelegateTypes.THREAD_START_ROUTINE lpStartAddress,
            IntPtr lpParameter,
            ThreadCreationFlags dwCreationFlags,
            out int lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            SIZE_T dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            ThreadCreationFlags dwCreationFlags,
            out int lpThreadId);

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
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            ALLOCATION_TYPE flAllocationType,
            MEMORY_PROTECTION flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            SIZE_T dwSize,
            MEMORY_PROTECTION flNewProtect,
            ref MEMORY_PROTECTION lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            SIZE_T nSize,
            out SIZE_T lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            SIZE_T nSize,
            out SIZE_T lpNumberOfBytesWritten);
    }
}
