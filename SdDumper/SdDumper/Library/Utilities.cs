using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using SdDumper.Interop;

namespace SdDumper.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        /*
         * Enums
         */
        public enum ObjectType
        {
            Unknown = 0,
            Process,
            Thread,
            Token,
            File,
            Registry,
            Service,
        }

        /*
         * private functions
         */
        private static string ConvertAccessMaskToString(uint accessMask, ObjectType objectType)
        {
            string result;

            if (objectType == ObjectType.Process)
                result = ((ACCESS_MASK_PROCESS)accessMask).ToString();
            else
                result = ((ACCESS_MASK_ACE)accessMask).ToString();

            if (Regex.IsMatch(result, @"^\d+$"))
                result = string.Format("0x{0}", accessMask.ToString("X8"));

            return result;
        }

        /*
         * public functions
         */
        public static bool DumpAcl(IntPtr pAcl, ObjectType objectType, int nIndentCount)
        {
            ACL acl;
            IntPtr pAce;
            IntPtr pSid;
            int nSidOffset;
            ACE_HEADER aceHeader;
            uint accessMask;
            var indent = new string(' ', 4 * nIndentCount);

            if (!NativeMethods.IsValidAcl(pAcl))
                return false;

            acl = (ACL)Marshal.PtrToStructure(pAcl, typeof(ACL));

            if (Environment.Is64BitProcess)
                pAce = new IntPtr(pAcl.ToInt64() + Marshal.SizeOf(typeof(ACL)));
            else
                pAce = new IntPtr(pAcl.ToInt32() + Marshal.SizeOf(typeof(ACL)));

            Console.WriteLine("{0}[*] AceCount  : {1}", indent, acl.AceCount);

            for (var idx = 0; idx < acl.AceCount; idx++)
            {
                Console.WriteLine("{0}[*] ACE[0x{1}] :", indent, idx.ToString("X2"));

                aceHeader = (ACE_HEADER)Marshal.PtrToStructure(pAce, typeof(ACE_HEADER));

                Console.WriteLine("{0}    [*] Type   : {1}", indent, aceHeader.AceType.ToString());
                Console.WriteLine("{0}    [*] Flags  : {1}", indent, aceHeader.AceFlags.ToString());

                if (aceHeader.AceType == ACE_TYPE.ACCESS_ALLOWED)
                {
                    var ace = (ACCESS_ALLOWED_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.ACCESS_ALLOWED_CALLBACK)
                {
                    var ace = (ACCESS_ALLOWED_CALLBACK_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_CALLBACK_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_CALLBACK_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT)
                {
                    var ace = (ACCESS_ALLOWED_CALLBACK_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.ACCESS_ALLOWED_OBJECT)
                {
                    var ace = (ACCESS_ALLOWED_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_OBJECT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_OBJECT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.ACCESS_DENIED)
                {
                    var ace = (ACCESS_DENIED_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_DENIED_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_DENIED_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.ACCESS_DENIED_CALLBACK)
                {
                    var ace = (ACCESS_DENIED_CALLBACK_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_DENIED_CALLBACK_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_DENIED_CALLBACK_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT)
                {
                    var ace = (ACCESS_DENIED_CALLBACK_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_DENIED_CALLBACK_OBJECT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_DENIED_CALLBACK_OBJECT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.ACCESS_DENIED_OBJECT)
                {
                    var ace = (ACCESS_DENIED_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_DENIED_OBJECT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_DENIED_OBJECT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_ALARM)
                {
                    var ace = (SYSTEM_ALARM_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ALARM_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ALARM_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_ALARM_CALLBACK)
                {
                    var ace = (SYSTEM_ALARM_CALLBACK_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ALARM_CALLBACK_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ALARM_CALLBACK_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_ALARM_CALLBACK_OBJECT)
                {
                    var ace = (SYSTEM_ALARM_CALLBACK_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ALARM_CALLBACK_OBJECT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ALARM_CALLBACK_OBJECT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_ALARM_OBJECT)
                {
                    var ace = (SYSTEM_ALARM_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_ALARM_OBJECT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_ALARM_OBJECT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_AUDIT)
                {
                    var ace = (SYSTEM_AUDIT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_AUDIT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_AUDIT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_AUDIT_CALLBACK)
                {
                    var ace = (SYSTEM_AUDIT_CALLBACK_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_AUDIT_CALLBACK_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_AUDIT_CALLBACK_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_AUDIT_CALLBACK_OBJECT)
                {
                    var ace = (SYSTEM_AUDIT_CALLBACK_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_AUDIT_OBJECT)
                {
                    var ace = (SYSTEM_AUDIT_OBJECT_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_AUDIT_OBJECT_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_AUDIT_OBJECT_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else if (aceHeader.AceType == ACE_TYPE.SYSTEM_MANDATORY_LABEL)
                {
                    var ace = (SYSTEM_MANDATORY_LABEL_ACE)Marshal.PtrToStructure(pAce, typeof(SYSTEM_MANDATORY_LABEL_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(SYSTEM_MANDATORY_LABEL_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }
                else
                {
                    var ace = (ACCESS_ALLOWED_ACE)Marshal.PtrToStructure(pAce, typeof(ACCESS_ALLOWED_ACE));
                    nSidOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_ACE), "SidStart").ToInt32();
                    accessMask = (uint)ace.Mask;
                }

                if (Environment.Is64BitProcess)
                    pSid = new IntPtr(pAce.ToInt64() + nSidOffset);
                else
                    pSid = new IntPtr(pAce.ToInt32() + nSidOffset);

                Console.WriteLine("{0}    [*] Access : {1}", indent, ConvertAccessMaskToString(accessMask, objectType));

                if (Helpers.ConvertSidToAccountName(pSid, out string strSid, out string accountName, out SID_NAME_USE sidType))
                {
                    Console.WriteLine("{0}    [*] SID    : {1}", indent, strSid);
                    Console.WriteLine("{0}        [*] Account  : {1}", indent, accountName);
                    Console.WriteLine("{0}        [*] SID Type : {1}", indent, sidType.ToString());
                }

                if (Environment.Is64BitProcess)
                    pAce = new IntPtr(pAce.ToInt64() + aceHeader.AceSize);
                else
                    pAce = new IntPtr(pAce.ToInt32() + aceHeader.AceSize);
            }

            return true;
        }


        public static void DumpSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            ObjectType objectType,
            bool isAnalyzeMode)
        {
            SECURITY_DESCRIPTOR sd;
            IntPtr pOwner;
            IntPtr pGroup;
            IntPtr pDacl;
            IntPtr pSacl;
            bool isValidDacl;
            bool isValidSacl;

            if (!NativeMethods.IsValidSecurityDescriptor(pSecurityDescriptor))
            {
                Console.WriteLine("[*] Specified SECURITY_DESCRIPTOR is invalid.");

                return;
            }

            sd = (SECURITY_DESCRIPTOR)Marshal.PtrToStructure(pSecurityDescriptor, typeof(SECURITY_DESCRIPTOR));

            if (Environment.Is64BitProcess)
            {
                pOwner = new IntPtr(pSecurityDescriptor.ToInt64() + sd.Owner);
                pGroup = new IntPtr(pSecurityDescriptor.ToInt64() + sd.Group);
                pDacl = new IntPtr(pSecurityDescriptor.ToInt64() + sd.Dacl);
                pSacl = new IntPtr(pSecurityDescriptor.ToInt64() + sd.Sacl);
            }
            else
            {
                pOwner = new IntPtr(pSecurityDescriptor.ToInt32() + sd.Owner);
                pGroup = new IntPtr(pSecurityDescriptor.ToInt32() + sd.Group);
                pDacl = new IntPtr(pSecurityDescriptor.ToInt32() + sd.Dacl);
                pSacl = new IntPtr(pSecurityDescriptor.ToInt32() + sd.Sacl);
            }

            if (sd.Dacl > 0)
                isValidDacl = NativeMethods.IsValidAcl(pDacl);
            else
                isValidDacl = false;

            if (sd.Sacl > 0)
                isValidSacl = NativeMethods.IsValidAcl(pSacl);
            else
                isValidSacl = false;

            Console.WriteLine("[*] SECURITY_DESCRIPTOR :");

            if (sd.Owner > 0)
            {
                if (Helpers.ConvertSidToAccountName(
                    pOwner,
                    out string strOwner,
                    out string strOwnerAccount,
                    out SID_NAME_USE ownerSidType))
                {
                    Console.WriteLine("    [*] Owner : {0}", strOwner);
                    Console.WriteLine("        [*] Account  : {0}", strOwnerAccount);
                    Console.WriteLine("        [*] SID Type : {0}", ownerSidType.ToString());
                }
                else
                {
                    Console.WriteLine("    [*] Owner : N/A");
                }
            }
            else
            {
                Console.WriteLine("    [*] Owner : N/A");
            }

            if (sd.Group > 0)
            {
                if (Helpers.ConvertSidToAccountName(
                    pGroup,
                    out string strGroup,
                    out string strGroupAccount,
                    out SID_NAME_USE groupSidType))
                {
                    Console.WriteLine("    [*] Group : {0}", strGroup);
                    Console.WriteLine("        [*] Account  : {0}", strGroupAccount);
                    Console.WriteLine("        [*] SID Type : {0}", groupSidType.ToString());
                }
                else
                {
                    Console.WriteLine("    [*] Group : N/A");
                }
            }
            else
            {
                Console.WriteLine("    [*] Group : N/A");
            }

            if (isValidDacl)
            {
                Console.WriteLine("    [*] DACL  :");
                DumpAcl(pDacl, objectType, 2);
            }
            else
            {
                Console.WriteLine("    [*] DACL  : N/A");
            }

            if (isValidSacl)
            {
                Console.WriteLine("    [*] SACL  :");
                DumpAcl(pSacl, objectType, 2);
            }
            else
            {
                if (isAnalyzeMode)
                    Console.WriteLine("    [*] SACL  : N/A");
                else if (IsPrivilegeAvailable(Win32Consts.SE_SECURITY_NAME) && !isAnalyzeMode)
                    Console.WriteLine("    [*] SACL  : N/A (NO_ACCESS_CONTROL)");
                else
                    Console.WriteLine("    [*] SACL  : N/A ({0} is required)", Win32Consts.SE_SECURITY_NAME);
            }
        }


        public static void EnableAllPrivileges(IntPtr hToken)
        {
            bool isEnabled;
            Dictionary<LUID, uint> privs = GetAvailablePrivileges(hToken);

            foreach (var priv in privs)
            {
                isEnabled = ((priv.Value & (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0);

                if (!isEnabled)
                    EnableSinglePrivilege(hToken, priv.Key);
            }
        }


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
            int error;
            var tp = new TOKEN_PRIVILEGES(1);
            tp.Privileges[0].Luid = priv;
            tp.Privileges[0].Attributes = (uint)SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED;

            IntPtr pTokenPrivilege = Marshal.AllocHGlobal(Marshal.SizeOf(tp));
            Marshal.StructureToPtr(tp, pTokenPrivilege, true);

            NativeMethods.AdjustTokenPrivileges(
                hToken,
                false,
                pTokenPrivilege,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            error = Marshal.GetLastWin32Error();

            return (error == Win32Consts.ERROR_SUCCESS);
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


        public static bool GetSecurityDescriptorInformation(
            IntPtr hObject,
            SECURITY_INFORMATION securityInformation,
            out IntPtr pSecurityDescriptor)
        {
            NTSTATUS ntstatus;
            bool status;
            uint nSecurityDescriptorSize = 0;
            pSecurityDescriptor = IntPtr.Zero;

            ntstatus = NativeMethods.NtQuerySecurityObject(
                hObject,
                securityInformation,
                pSecurityDescriptor,
                nSecurityDescriptorSize,
                out nSecurityDescriptorSize);

            if ((ntstatus != Win32Consts.STATUS_BUFFER_TOO_SMALL) || (nSecurityDescriptorSize == 0))
                return false;

            do
            {
                pSecurityDescriptor = Marshal.AllocHGlobal((int)nSecurityDescriptorSize);

                ntstatus = NativeMethods.NtQuerySecurityObject(
                    hObject,
                    securityInformation,
                    pSecurityDescriptor,
                    nSecurityDescriptorSize,
                    out nSecurityDescriptorSize);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                    pSecurityDescriptor = IntPtr.Zero;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            return status;
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
                NativeMethods.CloseHandle(hToken);

            if (hDupToken != IntPtr.Zero)
                NativeMethods.CloseHandle(hDupToken);

            NativeMethods.CloseHandle(hProcess);

            return status;
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


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            int error;
            IntPtr hCurrentToken;
            IntPtr pImpersonationLevel;
            SECURITY_IMPERSONATION_LEVEL impersonationLevel;

            if (!NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to impersonation.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }

            hCurrentToken = WindowsIdentity.GetCurrent().Token;
            pImpersonationLevel = Helpers.GetInformationFromToken(
                hCurrentToken,
                TOKEN_INFORMATION_CLASS.TokenImpersonationLevel);
            impersonationLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pImpersonationLevel);
            Marshal.FreeHGlobal(pImpersonationLevel);

            return (impersonationLevel != SECURITY_IMPERSONATION_LEVEL.SecurityIdentification);
        }
    }
}
