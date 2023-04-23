using System;
using System.Runtime.InteropServices;
using System.Text;

namespace RemoteForking.Interop
{
    using NTSTATUS = Int32;

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
            ACCESS_MASK processAccess,
            bool bInheritHandle,
            int processId);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateProcessEx(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr ParentProcess,
            NT_PROCESS_CREATION_FLAGS Flags,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            BOOLEAN InJob);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateProcessEx(
            out IntPtr ProcessHandle,
            ACCESS_MASK DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ParentProcess,
            NT_PROCESS_CREATION_FLAGS Flags,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            BOOLEAN InJob);

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
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESS_INFORMATION_CLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            out uint NumberOfBytesReaded);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtResumeThread(
            IntPtr ThreadHandle,
            out uint SuspendCount);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtTerminateProcess(IntPtr ProcessHandle, NTSTATUS ExitStatus);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            BOOLEAN Alertable,
            in LARGE_INTEGER Timeout);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWaitForSingleObject(
            IntPtr Handle,
            BOOLEAN Alertable,
            IntPtr Timeout); //  NULL means infinite.

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlCreateProcessReflection(
            IntPtr ProcessHandle,
            RTL_PROCESS_REFLECTION_FLAGS Flags,
            IntPtr StartRoutine,
            IntPtr StartContext,
            IntPtr EventHandle,
            out RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation);
    }
}
