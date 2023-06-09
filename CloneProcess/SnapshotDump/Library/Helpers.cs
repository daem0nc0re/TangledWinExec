using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SnapshotDump.Interop;

namespace SnapshotDump.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static bool GetPrivilegeLuid(string privilegeName, out LUID luid)
        {
            return NativeMethods.LookupPrivilegeValue(null, privilegeName, out luid);
        }


        public static bool GetProcessBasicInformation(
            IntPtr hProcess,
            out PROCESS_BASIC_INFORMATION pbi)
        {
            NTSTATUS ntstatus;
            var nSizeBuffer = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nSizeBuffer);

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESS_INFORMATION_CLASS.ProcessBasicInformation,
                pInfoBuffer,
                nSizeBuffer,
                out uint _);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                pbi = new PROCESS_BASIC_INFORMATION();
            }
            else
            {
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetInformationFromToken(
            IntPtr hToken,
            TOKEN_INFORMATION_CLASS tokenInformationClass,
            out IntPtr pTokenInformation)
        {
            bool status;
            NTSTATUS ntstatus;
            int nTokenInformationLength = 4;

            do
            {
                pTokenInformation = Marshal.AllocHGlobal(nTokenInformationLength);

                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    tokenInformationClass,
                    pTokenInformation,
                    (uint)nTokenInformationLength,
                    out uint nReturnLength);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    nTokenInformationLength = (int)nReturnLength;
                    Marshal.FreeHGlobal(pTokenInformation);
                    pTokenInformation = IntPtr.Zero;
                }
            } while (!status && (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL));

            return status;
        }


        public static string GetPrivilegeName(LUID priv)
        {
            int cchName = 255;
            StringBuilder privilegeName = new StringBuilder(255);
            string result = null;

            if (NativeMethods.LookupPrivilegeName(null, ref priv, privilegeName, ref cchName))
            {
                result = privilegeName.ToString();
            }

            return result;
        }


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            var pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (CompareIgnoreCase(Path.GetFileName(module.FileName), "ntdll.dll"))
                    {
                        pNtdll = module.BaseAddress;
                        dwFlags |= FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE;
                        break;
                    }
                }
            }

            nReturnedLength = NativeMethods.FormatMessage(
                dwFlags,
                pNtdll,
                code,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", code.ToString("X8"), message.ToString().Trim());
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            for (var offset = 0; offset < size; offset++)
                Marshal.WriteByte(buffer, offset, 0);
        }
    }
}
