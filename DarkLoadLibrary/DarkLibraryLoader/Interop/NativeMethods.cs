using System;
using System.Runtime.InteropServices;

namespace DarkLibraryLoader.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(
            IntPtr hProcess,
            out bool Wow64Process);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibraryA(string lpLibFileName);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            SIZE_T ZeroBits,
            ref SIZE_T RegionSize,
            ALLOCATION_TYPE AllocationType,
            MEMORY_PROTECTION Protect);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtFlushInstructionCache(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            uint NumberOfBytesToFlush);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref SIZE_T RegionSize,
            ALLOCATION_TYPE FreeType);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref uint NumberOfBytesToProtect,
            MEMORY_PROTECTION NewAccessProtection,
            out MEMORY_PROTECTION OldAccessProtection);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySystemTime(out LARGE_INTEGER SystemTime);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlHashUnicodeString(
            in UNICODE_STRING String,
            BOOLEAN CaseInSensitive,
            uint HashAlgorithm,
            out uint HashValue);

        [DllImport("ntdll.dll")]
        public static extern void RtlRbInsertNodeEx(
            IntPtr /* RTL_RB_TREE* */ Tree,
            IntPtr /* RTL_BALANCED_NODE* */ Parent,
            BOOLEAN Right,
            IntPtr /* RTL_BALANCED_NODE* */ Node);
    }
}
