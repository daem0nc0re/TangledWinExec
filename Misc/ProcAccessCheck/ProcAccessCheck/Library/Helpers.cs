using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
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


        public static string GetCurrentTokenIntegrityLevel()
        {
            return GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token);
        }


        public static string GetCurrentTokenUserName()
        {
            return GetTokenUserName(WindowsIdentity.GetCurrent().Token);
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


        public static string GetTokenIntegrityLevel(IntPtr hToken)
        {
            bool status;
            IntPtr pSid;
            string account = null;
            int cchName = 0;
            int cchReferencedDomainName = 0;
            var name = new StringBuilder();
            var domain = new StringBuilder();

            do
            {
                status = GetInformationFromToken(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, out IntPtr pInfo);

                if (status)
                {
                    pSid = Marshal.ReadIntPtr(pInfo);

                    do
                    {
                        name.Capacity = cchName;
                        domain.Capacity = cchReferencedDomainName;

                        status = NativeMethods.LookupAccountSid(
                            null,
                            pSid,
                            name,
                            ref cchName,
                            domain,
                            ref cchReferencedDomainName,
                            out SID_NAME_USE _);

                        if (!status)
                        {
                            name.Clear();
                            domain.Clear();
                        }
                    } while (!status);

                    if ((cchName != 0) && (cchReferencedDomainName != 0))
                        account = string.Format(@"{0}\{1}", domain.ToString(), name.ToString());
                    else if (cchName != 0)
                        account = name.ToString();
                    else if (cchReferencedDomainName != 0)
                        account = domain.ToString();

                    Marshal.FreeHGlobal(pInfo);
                    name.Clear();
                    domain.Clear();
                }
            } while (false);

            return account;
        }


        public static string GetTokenUserName(IntPtr hToken)
        {
            bool status;
            IntPtr pSid;
            string account = null;
            int cchName = 0;
            int cchReferencedDomainName = 0;
            var name = new StringBuilder();
            var domain = new StringBuilder();

            do
            {
                status = GetInformationFromToken(hToken, TOKEN_INFORMATION_CLASS.TokenUser, out IntPtr pInfo);

                if (status)
                {
                    pSid = Marshal.ReadIntPtr(pInfo);

                    do
                    {
                        name.Capacity = cchName;
                        domain.Capacity = cchReferencedDomainName;

                        status = NativeMethods.LookupAccountSid(
                            null,
                            pSid,
                            name,
                            ref cchName,
                            domain,
                            ref cchReferencedDomainName,
                            out SID_NAME_USE _);

                        if (!status)
                        {
                            name.Clear();
                            domain.Clear();
                        }
                    } while (!status);

                    if ((cchName != 0) && (cchReferencedDomainName != 0))
                        account = string.Format(@"{0}\{1}", domain.ToString(), name.ToString());
                    else if (cchName != 0)
                        account = name.ToString();
                    else if (cchReferencedDomainName != 0)
                        account = domain.ToString();

                    Marshal.FreeHGlobal(pInfo);
                    name.Clear();
                    domain.Clear();
                }
            } while (false);

            return account;
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
