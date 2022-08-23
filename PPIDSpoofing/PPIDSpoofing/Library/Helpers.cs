using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using PPIDSpoofing.Interop;

namespace PPIDSpoofing.Library
{
    internal class Helpers
    {
        public static bool GetStartupInfoEx(out STARTUPINFOEX startupInfoEx)
        {
            int error;
            bool status;
            int nSizeInfo = 0;
            startupInfoEx = new STARTUPINFOEX();
            startupInfoEx.StartupInfo.cb = Marshal.SizeOf(startupInfoEx);
            startupInfoEx.lpAttributeList = IntPtr.Zero;

            Console.WriteLine("[>] Trying to initialize STARTUPINFOEX structure.");

            do
            {
                status = NativeMethods.InitializeProcThreadAttributeList(
                    startupInfoEx.lpAttributeList,
                    1,
                    0,
                    ref nSizeInfo);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    if (startupInfoEx.lpAttributeList != IntPtr.Zero)
                        Marshal.FreeHGlobal(startupInfoEx.lpAttributeList);

                    startupInfoEx.lpAttributeList = Marshal.AllocHGlobal(nSizeInfo);
                    ZeroMemory(startupInfoEx.lpAttributeList, nSizeInfo);
                }
            } while (!status && error == Win32Const.ERROR_INSUFFICIENT_BUFFER);

            if (!status)
            {
                if (startupInfoEx.lpAttributeList != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(startupInfoEx.lpAttributeList);
                    startupInfoEx.lpAttributeList = IntPtr.Zero;
                }

                Console.WriteLine("[-] Failed to initialize thread attribute list.");
                Console.WriteLine("    |-> {0}\n", GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                Console.WriteLine("[+] STARTUPINFOEX structure is initialized successfully.");

                return true;
            }
        }



        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            ProcessModuleCollection modules;
            FormatMessageFlags dwFlags;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            IntPtr pNtdll = IntPtr.Zero;

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

                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
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
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }
    }
}
