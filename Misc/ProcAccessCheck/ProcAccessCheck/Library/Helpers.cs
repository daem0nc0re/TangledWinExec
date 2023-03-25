using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ProcAccessCheck.Interop;

namespace ProcAccessCheck.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static string ConvertProcessAccessMaskToString(ACCESS_MASK_PROCESS accessMask)
        {
            string result;
            var regexDecimal = new Regex(@"^\d+$");
            var resulgBuilder = new StringBuilder();
            var accessMasks = new List<ACCESS_MASK_PROCESS>
            {
                ACCESS_MASK_PROCESS.PROCESS_TERMINATE,
                ACCESS_MASK_PROCESS.PROCESS_CREATE_THREAD,
                ACCESS_MASK_PROCESS.PROCESS_SET_SESSIONID,
                ACCESS_MASK_PROCESS.PROCESS_VM_OPERATION,
                ACCESS_MASK_PROCESS.PROCESS_VM_READ,
                ACCESS_MASK_PROCESS.PROCESS_VM_WRITE,
                ACCESS_MASK_PROCESS.PROCESS_DUP_HANDLE,
                ACCESS_MASK_PROCESS.PROCESS_CREATE_PROCESS,
                ACCESS_MASK_PROCESS.PROCESS_SET_QUOTA,
                ACCESS_MASK_PROCESS.PROCESS_SET_INFORMATION,
                ACCESS_MASK_PROCESS.PROCESS_QUERY_INFORMATION,
                ACCESS_MASK_PROCESS.PROCESS_SUSPEND_RESUME_SET_PORT,
                ACCESS_MASK_PROCESS.PROCESS_QUERY_LIMITED_INFORMATION,
                ACCESS_MASK_PROCESS.DELETE,
                ACCESS_MASK_PROCESS.READ_CONTROL,
                ACCESS_MASK_PROCESS.WRITE_DAC,
                ACCESS_MASK_PROCESS.WRITE_OWNER,
                ACCESS_MASK_PROCESS.SYNCHRONIZE
            };

            result = accessMask.ToString();

            if (regexDecimal.IsMatch(result))
            {
                do
                {
                    if (accessMask == ACCESS_MASK_PROCESS.PROCESS_ALL_ACCESS)
                    {
                        resulgBuilder.Append("PROCESS_ALL_ACCESS");
                        break;
                    }

                    foreach (var mask in accessMasks)
                    {
                        if ((accessMask & mask) > 0)
                        {
                            if (resulgBuilder.Length > 0)
                                resulgBuilder.Append(", ");

                            resulgBuilder.Append(mask.ToString());
                        }
                    }
                } while (false);

                if (resulgBuilder.Length == 0)
                    resulgBuilder.Append(string.Format("0x{0}", ((int)accessMask).ToString("X8")));
            }
            else
            {
                resulgBuilder.Append(result);
            }

            return resulgBuilder.ToString();
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


        public static bool GetPrivilegeLuid(
            string privilegeName,
            out LUID luid)
        {
            int error;

            if (!NativeMethods.LookupPrivilegeValue(
                null,
                privilegeName,
                out luid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to lookup {0}.", privilegeName);
                Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(error, false));

                return false;
            }

            return true;
        }


        public static string GetPrivilegeName(LUID priv)
        {
            int error;
            int cchName = 255;
            StringBuilder privilegeName = new StringBuilder(255);

            if (!NativeMethods.LookupPrivilegeName(
                null,
                ref priv,
                privilegeName,
                ref cchName))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to lookup privilege name.");
                Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(error, false));

                return null;
            }

            return privilegeName.ToString();
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
