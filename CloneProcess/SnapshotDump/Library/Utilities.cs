using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using SnapshotDump.Interop;

namespace SnapshotDump.Library
{
    internal class Utilities
    {
        public static bool EnableSinglePrivilege(string privilegeName)
        {
            return EnableSinglePrivilege(WindowsIdentity.GetCurrent().Token, privilegeName);
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, string privilegeName)
        {
            bool status = Helpers.GetPrivilegeLuid(privilegeName, out LUID privilegeLuid);

            if (status)
                status = EnableSinglePrivilege(hToken, privilegeLuid);

            return status;
        }


        public static bool EnableSinglePrivilege(IntPtr hToken, LUID priv)
        {
            bool status;
            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
            var tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED;
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            status = NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            Marshal.FreeHGlobal(pTokenPrivilege);

            return status;
        }


        public static bool EnableMultiplePrivileges(IntPtr hToken, string[] privs)
        {
            bool isEnabled;
            bool enabledAll = true;
            var opt = StringComparison.OrdinalIgnoreCase;
            var results = new Dictionary<string, bool>();
            var privList = new List<string>(privs);
            var availablePrivs = GetAvailablePrivileges(hToken);

            foreach (var name in privList)
                results.Add(name, false);

            foreach (var priv in availablePrivs)
            {
                foreach (var name in privList)
                {
                    if (string.Compare(Helpers.GetPrivilegeName(priv.Key), name, opt) == 0)
                    {
                        isEnabled = ((priv.Value & (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

                        if (isEnabled)
                            results[name] = true;
                        else
                            results[name] = EnableSinglePrivilege(hToken, priv.Key);
                    }
                }
            }

            foreach (var result in results)
            {
                if (!result.Value)
                {
                    Console.WriteLine("[-] {0} is not available.", result.Key);
                    enabledAll = false;
                }
            }

            return enabledAll;
        }


        public static Dictionary<LUID, uint> GetAvailablePrivileges(IntPtr hToken)
        {
            int error;
            bool status;
            int nPriviliegeCount;
            IntPtr pTokenPrivileges;
            IntPtr pPrivilege;
            LUID_AND_ATTRIBUTES luidAndAttributes;
            int nluidAttributesSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
            int bufferLength = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            var availablePrivs = new Dictionary<LUID, uint>();

            do
            {
                pTokenPrivileges = Marshal.AllocHGlobal(bufferLength);
                Helpers.ZeroMemory(pTokenPrivileges, bufferLength);

                status = NativeMethods.GetTokenInformation(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pTokenPrivileges,
                    bufferLength,
                    out bufferLength);
                error = Marshal.GetLastWin32Error();

                if (!status)
                    Marshal.FreeHGlobal(pTokenPrivileges);
            } while (!status && (error == Win32Consts.ERROR_INSUFFICIENT_BUFFER));

            if (!status)
                return availablePrivs;

            nPriviliegeCount = Marshal.ReadInt32(pTokenPrivileges);
            pPrivilege = new IntPtr(pTokenPrivileges.ToInt64() + Marshal.SizeOf(nPriviliegeCount));

            for (var count = 0; count < nPriviliegeCount; count++)
            {
                luidAndAttributes = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    pPrivilege,
                    typeof(LUID_AND_ATTRIBUTES));
                availablePrivs.Add(luidAndAttributes.Luid, luidAndAttributes.Attributes);

                if (Environment.Is64BitProcess)
                    pPrivilege = new IntPtr(pPrivilege.ToInt64() + nluidAttributesSize);
                else
                    pPrivilege = new IntPtr(pPrivilege.ToInt32() + nluidAttributesSize);
            }

            Marshal.FreeHGlobal(pTokenPrivileges);

            return availablePrivs;
        }


        public static string GetOutputFilePath(string baseFilePath)
        {
            string result = Path.GetFullPath(baseFilePath);
            string directory = Path.GetDirectoryName(result);
            string extension = Path.GetExtension(baseFilePath);
            string regexExtension = string.Format("{0}$", extension);
            string baseFileName = Regex.Replace(Path.GetFileName(baseFilePath), regexExtension, string.Empty);

            if (File.Exists(result))
            {
                var count = 0;

                do
                {
                    result = string.Format(@"{0}\{1}_{2}{3}", directory, baseFileName, count.ToString(), extension);
                    count++;
                } while (File.Exists(result));
            }

            return result;
        }


        public static bool ImpersonateAsWinlogon()
        {
            return ImpersonateAsWinlogon(new string[] { });
        }


        public static bool ImpersonateAsWinlogon(string[] privs)
        {
            int error;
            int winlogon;
            bool status;
            IntPtr hProcess;
            IntPtr hToken;
            IntPtr hDupToken = IntPtr.Zero;
            var privileges = new string[] { Win32Consts.SE_DEBUG_NAME, Win32Consts.SE_IMPERSONATE_NAME };

            try
            {
                winlogon = (Process.GetProcessesByName("winlogon")[0]).Id;
            }
            catch
            {
                Console.WriteLine("[-] Failed to get PID of winlogon.exe.");

                return false;
            }

            status = EnableMultiplePrivileges(WindowsIdentity.GetCurrent().Token, privileges);

            if (!status)
            {
                Console.WriteLine("[-] Insufficient privilege.");

                return false;
            }

            hProcess = NativeMethods.OpenProcess(
                ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                true,
                winlogon);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get handle to winlogon.exe process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            do
            {
                status = NativeMethods.OpenProcessToken(
                    hProcess,
                    TokenAccessFlags.TOKEN_DUPLICATE,
                    out hToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to get handle to smss.exe process token.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    hToken = IntPtr.Zero;

                    break;
                }

                status = NativeMethods.DuplicateTokenEx(
                    hToken,
                    TokenAccessFlags.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary,
                    out hDupToken);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to duplicate winlogon.exe process token.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }

                if (privs.Length > 0)
                {
                    status = EnableMultiplePrivileges(hDupToken, privs);

                    if (!status)
                        break;
                }

                status = ImpersonateThreadToken(hDupToken);
            } while (false);

            if (hToken != IntPtr.Zero)
                NativeMethods.NtClose(hToken);

            if (hDupToken != IntPtr.Zero)
                NativeMethods.NtClose(hDupToken);

            NativeMethods.NtClose(hProcess);

            return status;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            int error;
            IntPtr hCurrentToken;
            SECURITY_IMPERSONATION_LEVEL impersonationLevel;

            if (!NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            hCurrentToken = WindowsIdentity.GetCurrent().Token;
            Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                out IntPtr pImpersonationLevel);
            impersonationLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pImpersonationLevel);
            Marshal.FreeHGlobal(pImpersonationLevel);

            return (impersonationLevel != SECURITY_IMPERSONATION_LEVEL.SecurityIdentification);
        }


        public static bool IsPrivilegeAvailable(string privilegeName)
        {
            return IsPrivilegeAvailable(WindowsIdentity.GetCurrent().Token, privilegeName);
        }


        public static bool IsPrivilegeAvailable(IntPtr hToken, string privilegeName)
        {
            string entryName;
            bool isAvailable = false;
            Dictionary<LUID, uint> privs = GetAvailablePrivileges(hToken);

            foreach (var priv in privs)
            {
                entryName = Helpers.GetPrivilegeName(priv.Key);

                if (Helpers.CompareIgnoreCase(entryName, privilegeName))
                {
                    isAvailable = true;

                    break;
                }
            }

            return isAvailable;
        }
    }
}
