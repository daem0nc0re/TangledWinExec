using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SelfDefend.Interop
{
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
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
        public static extern bool GetProcessMitigationPolicy(
            IntPtr hProcess,
            PROCESS_MITIGATION_POLICY MitigationPolicy,
            IntPtr lpBuffer,
            SIZE_T dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetProcessMitigationPolicy(
            PROCESS_MITIGATION_POLICY MitigationPolicy,
            IntPtr lpBuffer,
            SIZE_T dwLength);
    }
}
