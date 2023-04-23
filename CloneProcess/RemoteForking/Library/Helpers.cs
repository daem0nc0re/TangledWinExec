using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using RemoteForking.Interop;

namespace RemoteForking.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
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


        public static IntPtr GetCurrentEnvironmentAddress()
        {
            int nOffsetEnvironmentPointer;
            int nOffsetProcessParametersPointer;
            IntPtr pProcessParameters;
            var hProcess = Process.GetCurrentProcess().Handle;
            var pEnvironment = IntPtr.Zero;

            if (GetProcessBasicInformation(hProcess, out PROCESS_BASIC_INFORMATION pbi))
            {
                if (Environment.Is64BitProcess)
                {
                    nOffsetEnvironmentPointer = 0x80;
                    nOffsetProcessParametersPointer = 0x20;
                }
                else
                {
                    nOffsetEnvironmentPointer = 0x48;
                    nOffsetProcessParametersPointer = 0x10;
                }

                pProcessParameters = Marshal.ReadIntPtr(pbi.PebBaseAddress, nOffsetProcessParametersPointer);
                pEnvironment = Marshal.ReadIntPtr(pProcessParameters, nOffsetEnvironmentPointer);
            }

            return pEnvironment;
        }


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            ProcessModuleCollection modules;
            FormatMessageFlags dwFlags;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                modules = Process.GetCurrentProcess().Modules;

                foreach (ProcessModule mod in modules)
                {
                    if (string.Compare(
                        Path.GetFileName(mod.FileName),
                        "ntdll.dll",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        pNtdll = mod.BaseAddress;
                        break;
                    }
                }

                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE | FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
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
    }
}
