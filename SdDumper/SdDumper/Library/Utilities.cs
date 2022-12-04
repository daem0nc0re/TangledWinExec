using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
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
            IntPtr pApplicationData;
            int nAceSize;
            int nSidLength;
            int nSidOffset;
            int nApplicationDataSize;
            string condition;
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
                nAceSize = aceHeader.AceSize;

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

                if (
                    (aceHeader.AceType == ACE_TYPE.ACCESS_ALLOWED_CALLBACK) ||
                    (aceHeader.AceType == ACE_TYPE.ACCESS_DENIED_CALLBACK) ||
                    (aceHeader.AceType == ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT) ||
                    (aceHeader.AceType == ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT) ||
                    (aceHeader.AceType == ACE_TYPE.SYSTEM_AUDIT_CALLBACK) ||
                    (aceHeader.AceType == ACE_TYPE.SYSTEM_AUDIT_CALLBACK_OBJECT))
                {
                    nSidLength = NativeMethods.GetLengthSid(pSid);

                    if (nAceSize > nSidLength)
                    {
                        nApplicationDataSize = aceHeader.AceSize - nSidOffset - nSidLength;

                        if (Environment.Is64BitProcess)
                            pApplicationData = new IntPtr(pSid.ToInt64() + nSidLength);
                        else
                            pApplicationData = new IntPtr(pSid.ToInt32() + nSidLength);

                        condition = ParseConditionalAceData(pApplicationData, nApplicationDataSize);

                        if (string.IsNullOrEmpty(condition))
                            Console.WriteLine("{0}    [*] Condition : N/A", indent);
                        else
                            Console.WriteLine("{0}    [*] Condition : {1}", indent, condition);
                    }
                    else
                    {
                        Console.WriteLine("{0}    [*] Condition : N/A", indent);
                    }
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
                    Console.WriteLine("    [*] Owner :");
                    Console.WriteLine("        [*] SID      : {0}", strOwner);
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
                    Console.WriteLine("    [*] Group :");
                    Console.WriteLine("        [*] SID      : {0}", strGroup);
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
                Console.WriteLine("    [*] DACL :");
                DumpAcl(pDacl, objectType, 2);
            }
            else
            {
                Console.WriteLine("    [*] DACL : N/A");
            }

            if (isValidSacl)
            {
                Console.WriteLine("    [*] SACL :");
                DumpAcl(pSacl, objectType, 2);
            }
            else
            {
                if (isAnalyzeMode)
                    Console.WriteLine("    [*] SACL : N/A");
                else if (IsPrivilegeAvailable(Win32Consts.SE_SECURITY_NAME) && !isAnalyzeMode)
                    Console.WriteLine("    [*] SACL : N/A (NO_ACCESS_CONTROL)");
                else
                    Console.WriteLine("    [*] SACL : N/A ({0} is required)", Win32Consts.SE_SECURITY_NAME);
            }
        }


        public static void GetTokenAclInformation(IntPtr hToken)
        {
            bool status;
            TOKEN_PROCESS_TRUST_LEVEL tokenProcessTrustLevel;
            TOKEN_OWNER tokenOwner;
            TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
            TOKEN_DEFAULT_DACL tokenDefaultDacl;

            Console.WriteLine("[*] Primary Token Information:");

            status = Helpers.GetInformationFromToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenProcessTrustLevel,
                out IntPtr pTrustLevel);

            if (status)
            {
                tokenProcessTrustLevel = (TOKEN_PROCESS_TRUST_LEVEL)Marshal.PtrToStructure(
                    pTrustLevel,
                    typeof(TOKEN_PROCESS_TRUST_LEVEL));

                if (Helpers.ConvertSidToTrustLevel(
                    tokenProcessTrustLevel.TrustLevelSid,
                    out string strTrustLevelSid,
                    out string strTrustLevel))
                {
                    Console.WriteLine("    [*] TrustLevel :");
                    Console.WriteLine("        [*] SID   : {0}", strTrustLevelSid);
                    Console.WriteLine("        [*] Level : {0}", strTrustLevel);
                }
                else
                {
                    Console.WriteLine("    [*] TrustLevel : N/A");
                }

                Marshal.FreeHGlobal(pTrustLevel);
            }
            else
            {
                Console.WriteLine("    [*] TrustLevel : N/A");
            }

            status = Helpers.GetInformationFromToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenOwner,
                out IntPtr pTokenOwner);

            if (status)
            {
                tokenOwner = (TOKEN_OWNER)Marshal.PtrToStructure(
                    pTokenOwner,
                    typeof(TOKEN_OWNER));

                if (Helpers.ConvertSidToAccountName(
                    tokenOwner.Owner,
                    out string strOwner,
                    out string strOwnerAccount,
                    out SID_NAME_USE ownerSidType))
                {
                    Console.WriteLine("    [*] Owner :");
                    Console.WriteLine("        [*] SID      : {0}", strOwner);
                    Console.WriteLine("        [*] Account  : {0}", strOwnerAccount);
                    Console.WriteLine("        [*] SID Type : {0}", ownerSidType.ToString());
                }
                else
                {
                    Console.WriteLine("    [*] Owner : N/A");
                }

                Marshal.FreeHGlobal(pTokenOwner);
            }
            else
            {
                Console.WriteLine("    [*] Owner : N/A");
            }

            status = Helpers.GetInformationFromToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenPrimaryGroup,
                out IntPtr pTokenPrimaryGroup);

            if (status)
            {
                tokenPrimaryGroup = (TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(
                    pTokenPrimaryGroup,
                    typeof(TOKEN_PRIMARY_GROUP));

                if (Helpers.ConvertSidToAccountName(
                    tokenPrimaryGroup.PrimaryGroup,
                    out string strGroup,
                    out string strGroupAccount,
                    out SID_NAME_USE groupSidType))
                {
                    Console.WriteLine("    [*] Group :");
                    Console.WriteLine("        [*] SID      : {0}", strGroup);
                    Console.WriteLine("        [*] Account  : {0}", strGroupAccount);
                    Console.WriteLine("        [*] SID Type : {0}", groupSidType.ToString());
                }
                else
                {
                    Console.WriteLine("    [*] Group : N/A");
                }

                Marshal.FreeHGlobal(pTokenPrimaryGroup);
            }
            else
            {
                Console.WriteLine("    [*] Group : N/A");
            }

            status = Helpers.GetInformationFromToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenDefaultDacl,
                out IntPtr pTokenDefaultDacl);

            if (status)
            {
                tokenDefaultDacl = (TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(
                    pTokenDefaultDacl,
                    typeof(TOKEN_DEFAULT_DACL));

                Console.WriteLine("    [*] DACL :");
                DumpAcl(tokenDefaultDacl.DefaultDacl, ObjectType.Token, 2);
                Marshal.FreeHGlobal(pTokenDefaultDacl);
            }
            else
            {
                Console.WriteLine("    [*] DACL : N/A");
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


        public static string ParseConditionalAceData(IntPtr pApplicationData, int nApplicationDataSize)
        {
            int nSizeToRead;
            long numberLiteral;
            string code;
            IntPtr pSid;
            string token;
            string operand;
            string lhs;
            string rhs;
            string result;
            CONDITIONAL_ACE_BASE numberBase;
            CONDITIONAL_ACE_SIGN sign;
            CONDITIONAL_ACE_TOKEN tokenType;
            int nCurrentOffset = 0;
            int nCompositBase = 0;
            int nCompositLength = 0;
            int magic = Marshal.ReadInt32(pApplicationData, nCurrentOffset);
            var codeStack = new Stack<string>();
            var compositString = new StringBuilder();
            var numberString = new StringBuilder();
            var octetByteString = new StringBuilder();

            if (magic == Win32Consts.CONDITIONAL_ACE_SIGNATURE)
            {
                nCurrentOffset += 4;

                while (nCurrentOffset < nApplicationDataSize)
                {
                    tokenType = (CONDITIONAL_ACE_TOKEN)Marshal.ReadByte(pApplicationData, nCurrentOffset);
                    nCurrentOffset++;

                    if (
                        (tokenType == CONDITIONAL_ACE_TOKEN.LocalAttribute) ||
                        (tokenType == CONDITIONAL_ACE_TOKEN.UserAttribute) ||
                        (tokenType == CONDITIONAL_ACE_TOKEN.ResourceAttribute) ||
                        (tokenType == CONDITIONAL_ACE_TOKEN.DeviceAttribute))
                    {
                        nSizeToRead = Marshal.ReadInt32(pApplicationData, nCurrentOffset);
                        nCurrentOffset += 4;
                        token = Helpers.ReadUnicodeString(pApplicationData, nCurrentOffset, nSizeToRead);
                        nCurrentOffset += nSizeToRead;
                    }
                    else if (
                        (tokenType == CONDITIONAL_ACE_TOKEN.SignedInt8) ||
                        (tokenType == CONDITIONAL_ACE_TOKEN.SignedInt16) ||
                        (tokenType == CONDITIONAL_ACE_TOKEN.SignedInt32) ||
                        (tokenType == CONDITIONAL_ACE_TOKEN.SignedInt64))
                    {
                        numberLiteral = Marshal.ReadInt64(pApplicationData, nCurrentOffset);
                        nCurrentOffset += 8;
                        sign = (CONDITIONAL_ACE_SIGN)Marshal.ReadByte(pApplicationData, nCurrentOffset);
                        nCurrentOffset += 1;
                        numberBase = (CONDITIONAL_ACE_BASE)Marshal.ReadByte(pApplicationData, nCurrentOffset);
                        nCurrentOffset += 1;

                        if (sign == CONDITIONAL_ACE_SIGN.Plus)
                            numberString.Append("+");
                        else if (sign == CONDITIONAL_ACE_SIGN.Minus)
                            numberString.Append("-");

                        if (numberBase == CONDITIONAL_ACE_BASE.Octal)
                            numberString.Append(Convert.ToString(numberLiteral, 8));
                        else if (numberBase == CONDITIONAL_ACE_BASE.Decimal)
                            numberString.Append(numberLiteral.ToString());
                        else if (numberBase == CONDITIONAL_ACE_BASE.Hexadecimal)
                            numberString.Append(numberLiteral.ToString("X"));

                        token = numberString.ToString();
                        numberString.Clear();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.UnicodeString)
                    {
                        nSizeToRead = Marshal.ReadInt32(pApplicationData, nCurrentOffset);
                        nCurrentOffset += 4;
                        code = Helpers.ReadUnicodeString(pApplicationData, nCurrentOffset, nSizeToRead);
                        nCurrentOffset += nSizeToRead;
                        token = string.Format("\"{0}\"", code);
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.OctetString)
                    {
                        nSizeToRead = Marshal.ReadInt32(pApplicationData, nCurrentOffset);
                        nCurrentOffset += 4;

                        for (var offset = 0; offset < nSizeToRead; offset++)
                        {
                            if (octetByteString.Capacity > 0)
                                octetByteString.Append(" ");

                            octetByteString.Append(Marshal.ReadByte(pApplicationData, nCurrentOffset + offset).ToString("X2"));
                        }

                        nCurrentOffset += nSizeToRead;
                        token = octetByteString.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.Composite)
                    {
                        nCompositLength = Marshal.ReadInt32(pApplicationData, nCurrentOffset);
                        nCurrentOffset += 4;
                        nCompositBase = nCurrentOffset;
                        token = "( ";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.Sid)
                    {
                        nSizeToRead = Marshal.ReadInt32(pApplicationData, nCurrentOffset);
                        nCurrentOffset += 4;

                        if (Environment.Is64BitProcess)
                            pSid = new IntPtr(pApplicationData.ToInt64() + nCurrentOffset);
                        else
                            pSid = new IntPtr(pApplicationData.ToInt32() + nCurrentOffset);

                        NativeMethods.ConvertSidToStringSid(pSid, out string strSid);
                        nCurrentOffset += nSizeToRead;

                        if (string.IsNullOrEmpty(strSid))
                            token = "N/A";
                        else
                            token = strSid;
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.Exists)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.NotEquals)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.LogicalAnd)
                    {
                        token = "&&";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.LogicalOr)
                    {
                        token = "||";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.LogicalNot)
                    {
                        token = "!";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.MemberOf)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.DeviceMemberOf)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.MemberOfAny)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.DeviceMemberOfAny)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.NotMemberOf)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.NotDeviceMemberOf)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.NotMemberOfAny)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.NotDeviceMemberOfAny)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.Equals)
                    {
                        token = "==";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.NotEquals)
                    {
                        token = "!=";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.LesserThan)
                    {
                        token = "<";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.LesserThanEquals)
                    {
                        token = "<=";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.GreaterThan)
                    {
                        token = ">";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.GreaterThanEquals)
                    {
                        token = ">=";
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.Contains)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.AnyOf)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.NotContains)
                    {
                        token = tokenType.ToString();
                    }
                    else if (tokenType == CONDITIONAL_ACE_TOKEN.NotAnyOf)
                    {
                        token = tokenType.ToString();
                    }
                    else
                    {
                        token = string.Empty;
                    }

                    if (nCompositLength > 0)
                    {
                        if ((nCurrentOffset - nCompositBase) < nCompositLength)
                        {
                            compositString.Append(token);

                            if ((nCurrentOffset - nCompositBase) > 0)
                                compositString.Append(", ");
                        }
                        else
                        {
                            compositString.Append(token);
                            compositString.Append(" )");
                            codeStack.Push(compositString.ToString());

                            compositString.Clear();
                            nCompositLength = 0;
                            nCompositBase = 0;
                        }
                    }
                    else
                    {
                        if (
                            (tokenType == CONDITIONAL_ACE_TOKEN.MemberOf) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.DeviceMemberOf) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.MemberOfAny) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.DeviceMemberOfAny) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.NotMemberOf) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.NotDeviceMemberOf) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.NotMemberOfAny) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.NotDeviceMemberOfAny) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.Exists) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.NotExists))
                        {
                            operand = codeStack.Pop();
                            codeStack.Push(string.Format("( {0} {1} )", token, operand));
                        }
                        else if (tokenType == CONDITIONAL_ACE_TOKEN.LogicalNot)
                        {
                            operand = codeStack.Pop();
                            codeStack.Push(string.Format("( {0}( {1} ) )", token, operand));
                        }
                        else if (
                            (tokenType == CONDITIONAL_ACE_TOKEN.Equals) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.NotEquals) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.LesserThan) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.LesserThanEquals) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.GreaterThan) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.GreaterThanEquals) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.Contains) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.AnyOf) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.NotContains) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.NotAnyOf) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.LogicalAnd) ||
                            (tokenType == CONDITIONAL_ACE_TOKEN.LogicalOr))
                        {
                            rhs = codeStack.Pop();
                            lhs = codeStack.Pop();
                            codeStack.Push(string.Format("( {0} {1} {2} )", lhs, token, rhs));
                        }
                        else if (tokenType != CONDITIONAL_ACE_TOKEN.InvalidToken)
                        {
                            codeStack.Push(token);
                        }
                    }
                }
            }

            if (codeStack.Count > 0)
                result = codeStack.Pop();
            else
                result = null;

            return result;
        }
    }
}
