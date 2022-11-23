using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using SdDumper.Interop;

namespace SdDumper.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string strSid,
            out string accountName,
            out SID_NAME_USE peUse)
        {
            bool status;
            int error;
            int cchName = 4;
            int cchReferencedDomainName = 4;
            var pName = new StringBuilder();
            var pReferencedDomainName = new StringBuilder();
            strSid = null;
            accountName = null;
            peUse = SID_NAME_USE.SidTypeUnknown;

            if (!NativeMethods.IsValidSid(pSid))
                return false;

            if (!NativeMethods.ConvertSidToStringSid(pSid, out strSid))
            {
                strSid = null;

                return false;
            }

            do
            {
                pName.Capacity = cchName;
                pReferencedDomainName.Capacity = cchReferencedDomainName;

                status = NativeMethods.LookupAccountSid(
                    null,
                    pSid,
                    pName,
                    ref cchName,
                    pReferencedDomainName,
                    ref cchReferencedDomainName,
                    out peUse);
                error = Marshal.GetLastWin32Error();

                if (!status)
                {
                    pName.Clear();
                    pReferencedDomainName.Clear();
                }
            } while (!status && error == Win32Consts.ERROR_INSUFFICIENT_BUFFER);

            if (!status)
            {
                accountName = "N/A";
                peUse = SID_NAME_USE.SidTypeUnknown;
            }
            else
            {
                if ((cchName == 0) && (cchReferencedDomainName > 0))
                    accountName = pReferencedDomainName.ToString();
                else if ((cchName > 0) && (cchReferencedDomainName == 0))
                    accountName = pName.ToString();
                else if ((cchName > 0) && (cchReferencedDomainName > 0))
                    accountName = string.Format(@"{0}\{1}", pReferencedDomainName.ToString(), pName.ToString());
                else
                    accountName = "N/A";
            }

            return true;
        }


        public static bool ConvertSidToTrustLevel(
            IntPtr pTrustLevelSid,
            out string strSid,
            out string strTrustLevel)
        {
            bool status;
            string strDomain = "TRUST LEVEL";

            status = NativeMethods.IsValidSid(pTrustLevelSid);

            if (status)
            {
                status = NativeMethods.ConvertSidToStringSid(pTrustLevelSid, out strSid);

                if (status)
                {
                    if (CompareIgnoreCase(strSid, "S-1-19-512-1024"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "ProtectedLight-Authenticode");
                    else if (CompareIgnoreCase(strSid, "S-1-19-512-1536"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "ProtectedLight-AntiMalware");
                    else if (CompareIgnoreCase(strSid, "S-1-19-512-2048"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "ProtectedLight-App");
                    else if (CompareIgnoreCase(strSid, "S-1-19-512-4096"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "ProtectedLight-Windows");
                    else if (CompareIgnoreCase(strSid, "S-1-19-512-8192"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "ProtectedLight-WinTcb");
                    else if (CompareIgnoreCase(strSid, "S-1-19-1024-1024"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "Protected-Authenticode");
                    else if (CompareIgnoreCase(strSid, "S-1-19-1024-1536"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "Protected-AntiMalware");
                    else if (CompareIgnoreCase(strSid, "S-1-19-1024-2048"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "Protected-App");
                    else if (CompareIgnoreCase(strSid, "S-1-19-1024-4096"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "Protected-Windows");
                    else if (CompareIgnoreCase(strSid, "S-1-19-1024-8192"))
                        strTrustLevel = string.Format(@"{0}\{1}", strDomain, "Protected-WinTcb");
                    else
                        strTrustLevel = "N/A";
                }
                else
                {
                    strSid = null;
                    strTrustLevel = null;
                }
            }
            else
            {
                strSid = null;
                strTrustLevel = null;
            }

            return status;
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
