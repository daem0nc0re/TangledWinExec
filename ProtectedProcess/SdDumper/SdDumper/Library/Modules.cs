using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using SdDumper.Interop;

namespace SdDumper.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        /*
         * private functions
         */
        private static bool InitializePrivilegesAndParameters(
            bool asSystem,
            bool debug,
            out bool isImpersonated)
        {
            isImpersonated = false;

            if (asSystem)
            {
                Console.WriteLine("[>] Trying to impersonate as SYSTEM.");

                isImpersonated = Utilities.ImpersonateAsWinlogon();

                if (isImpersonated)
                {
                    Console.WriteLine("[+] Impersonation is successful.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to impersonate as SYSTEM.");

                    return false;
                }
            }

            if (debug)
            {
                Console.WriteLine("[>] Trying to {0}.", Win32Consts.SE_DEBUG_NAME);

                if (Utilities.EnableSinglePrivilege(Win32Consts.SE_DEBUG_NAME))
                {
                    Console.WriteLine("[+] {0} is enabled successfully.", Win32Consts.SE_DEBUG_NAME);
                }
                else
                {
                    Console.WriteLine("[-] Failed to enable {0}.", Win32Consts.SE_DEBUG_NAME);

                    return false;
                }
            }

            return true;
        }


        private static bool InitializePrivilegesAndParameters(
            bool asSystem,
            bool debug,
            out ACCESS_MASK accessMask,
            out SECURITY_INFORMATION securityInformation,
            out bool isImpersonated)
        {
            bool status = false;
            accessMask = ACCESS_MASK.READ_CONTROL;
            securityInformation =
                SECURITY_INFORMATION.ATTRIBUTE_SECURITY_INFORMATION |
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION |
                SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION |
                SECURITY_INFORMATION.LABEL_SECURITY_INFORMATION |
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION |
                SECURITY_INFORMATION.SCOPE_SECURITY_INFORMATION |
                SECURITY_INFORMATION.PROCESS_TRUST_LABEL_SECURITY_INFORMATION;
            isImpersonated = false;

            do
            {
                if (asSystem)
                {
                    Console.WriteLine("[>] Trying to impersonate as SYSTEM.");

                    isImpersonated = Utilities.ImpersonateAsWinlogon();

                    if (isImpersonated)
                    {
                        Console.WriteLine("[+] Impersonation is successful.");
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to impersonate as SYSTEM.");
                        break;
                    }
                }

                if (debug)
                {
                    Console.WriteLine("[>] Trying to {0}.", Win32Consts.SE_DEBUG_NAME);

                    if (Utilities.EnableSinglePrivilege(Win32Consts.SE_DEBUG_NAME))
                    {
                        Console.WriteLine("[+] {0} is enabled successfully.", Win32Consts.SE_DEBUG_NAME);
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to enable {0}.", Win32Consts.SE_DEBUG_NAME);
                        break;
                    }
                }

                if (Utilities.IsPrivilegeAvailable(Win32Consts.SE_SECURITY_NAME))
                {
                    accessMask |= ACCESS_MASK.ACCESS_SYSTEM_SECURITY;
                    securityInformation |= SECURITY_INFORMATION.SACL_SECURITY_INFORMATION;
                    securityInformation |= SECURITY_INFORMATION.BACKUP_SECURITY_INFORMATION;

                    if (!Utilities.EnableSinglePrivilege(Win32Consts.SE_SECURITY_NAME))
                    {
                        // This block should not be reached.
                        Console.WriteLine("[-] Failed to enable {0}.", Win32Consts.SE_SECURITY_NAME);
                        break;
                    }
                }

                status = true;
            } while (false);

            return status;
        }


        private static bool InitializePrivilegesAndParametersBySddl(
            string sddl,
            bool asSystem,
            bool debug,
            out ACCESS_MASK accessMask,
            out SECURITY_INFORMATION securityInformation,
            out IntPtr pSecurityDescriptor,
            out bool isImpersonated)
        {
            SECURITY_DESCRIPTOR sd;
            bool status = false;
            accessMask = 0;
            securityInformation = 0;
            isImpersonated = false;

            do
            {
                Console.WriteLine("[>] Checking the sepecified SDDL.");
                Console.WriteLine("    [*] SDDL : {0}", sddl);

                if (NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl,
                    Win32Consts.SDDL_REVISION_1,
                    out pSecurityDescriptor,
                    out uint nSecurityDescriptorSize))
                {
                    Console.WriteLine("[+] SDDL is valid (Size = {0} Bytes).", nSecurityDescriptorSize);

                    sd = (SECURITY_DESCRIPTOR)Marshal.PtrToStructure(
                        pSecurityDescriptor,
                        typeof(SECURITY_DESCRIPTOR));

                    if (sd.Owner > 0)
                    {
                        accessMask |= ACCESS_MASK.WRITE_OWNER;
                        securityInformation |= SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION;
                    }

                    if (sd.Group > 0)
                    {
                        accessMask |= ACCESS_MASK.WRITE_OWNER;
                        securityInformation |= SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION;
                    }

                    if (sd.Dacl > 0)
                    {
                        accessMask |= ACCESS_MASK.WRITE_DAC;
                        securityInformation |= SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
                    }

                    if (sd.Sacl > 0)
                    {
                        accessMask |= ACCESS_MASK.ACCESS_SYSTEM_SECURITY;
                        securityInformation |= SECURITY_INFORMATION.SACL_SECURITY_INFORMATION;
                    }
                }
                else
                {
                    Console.WriteLine("[-] SDDL is invalid.");
                    pSecurityDescriptor = IntPtr.Zero;
                    break;
                }

                if (asSystem)
                {
                    Console.WriteLine("[>] Trying to impersonate as SYSTEM.");

                    isImpersonated = Utilities.ImpersonateAsWinlogon();

                    if (isImpersonated)
                    {
                        Console.WriteLine("[+] Impersonation is successful.");
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to impersonate as SYSTEM.");
                        break;
                    }
                }

                if (debug)
                {
                    Console.WriteLine("[>] Trying to {0}.", Win32Consts.SE_DEBUG_NAME);

                    if (Utilities.EnableSinglePrivilege(Win32Consts.SE_DEBUG_NAME))
                    {
                        Console.WriteLine("[+] {0} is enabled successfully.", Win32Consts.SE_DEBUG_NAME);
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to enable {0}.", Win32Consts.SE_DEBUG_NAME);
                        break;
                    }
                }

                if ((accessMask & ACCESS_MASK.ACCESS_SYSTEM_SECURITY) == ACCESS_MASK.ACCESS_SYSTEM_SECURITY)
                {
                    if (!Utilities.IsPrivilegeAvailable(Win32Consts.SE_SECURITY_NAME))
                    {
                        Console.WriteLine("[-] Insufficient privilege.");
                        break;
                    }

                    if (!Utilities.EnableSinglePrivilege(Win32Consts.SE_SECURITY_NAME))
                    {
                        Console.WriteLine("[-] Failed to enable {0}.", Win32Consts.SE_SECURITY_NAME);
                        break;
                    }
                }

                status = true;
            } while (false);

            return status;
        }


        /*
         * public functions
         */
        public static bool AnalyzeStringSecurityDescriptor(string sddl)
        {
            int error;
            bool status;

            Console.WriteLine("[>] Trying to analyze SDDL.");
            Console.WriteLine("    [*] SDDL : {0}", sddl);

            status = NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
                sddl,
                Win32Consts.SDDL_REVISION_1,
                out IntPtr pSecurityDescriptor,
                IntPtr.Zero);
            
            if (status)
            {
                Console.WriteLine(Utilities.DumpSecurityDescriptor(pSecurityDescriptor, "Unknown", true));
                NativeMethods.LocalFree(pSecurityDescriptor);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to analyze the specified SDDL.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool DumpFileSecurityDescriptor(string filePath, bool asSystem, bool debug)
        {
            int error;
            bool status;
            IntPtr hFile;
            string objectType;
            FILE_ATTRIBUTE fileAttributes;
            string fullPathName;
            filePath = filePath.Replace('/', '\\');
            fullPathName = Regex.IsMatch(filePath, @"^\\\S+") ? filePath : Path.GetFullPath(filePath);

            fileAttributes = NativeMethods.GetFileAttributes(fullPathName);

            if (fileAttributes == FILE_ATTRIBUTE.INVALID)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open {0}.", fullPathName);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }
            else if (fileAttributes.HasFlag(FILE_ATTRIBUTE.DIRECTORY))
            {
                objectType = "StandardDirectory";
                fileAttributes = FILE_ATTRIBUTE.DIRECTORY | FILE_ATTRIBUTE.BACKUP_SEMANTICS;
            }
            else
            {
                if (Regex.IsMatch(fullPathName, @"\\\\\.\\pipe"))
                    objectType = "Pipe";
                else
                    objectType = "File";

                fileAttributes = FILE_ATTRIBUTE.NORMAL;
            }

            Console.WriteLine("[>] Trying to dump SecurityDescriptor for the specified path.");
            Console.WriteLine("    [*] Path : {0}", fullPathName);
            Console.WriteLine("    [*] Type : {0}", objectType);

            if (!InitializePrivilegesAndParameters(
                asSystem,
                debug,
                out ACCESS_MASK accessMask,
                out SECURITY_INFORMATION securityInformation,
                out bool isImpersonated))
            {
                return false;
            }

            hFile = NativeMethods.CreateFile(
                fullPathName,
                accessMask,
                FILE_SHARE.NONE,
                IntPtr.Zero,
                CREATE_DESPOSITION.OPEN_EXISTING,
                fileAttributes,
                IntPtr.Zero);
            status = (hFile != Win32Consts.INVALID_HANDLE_VALUE);

            if (status)
            {
                if (Utilities.GetSecurityDescriptorInformation(
                    hFile,
                    securityInformation,
                    out IntPtr pSecurityDescriptor))
                {
                    if (NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        pSecurityDescriptor,
                        Win32Consts.SDDL_REVISION_1,
                        securityInformation,
                        out IntPtr pStringSecurityDescriptor,
                        IntPtr.Zero))
                    {
                        Console.WriteLine("[+] Got valid SecuritySescriptor string.");
                        Console.WriteLine("    [*] SDDL : {0}", Marshal.PtrToStringUni(pStringSecurityDescriptor));
                        NativeMethods.LocalFree(pStringSecurityDescriptor);
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to get valid SecurityDescriptor string.");
                    }

                    Console.WriteLine(Utilities.DumpSecurityDescriptor(pSecurityDescriptor, objectType, false));
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                }

                NativeMethods.NtClose(hFile);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open the specified file or directory.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool DumpNtObjectSecurityDescriptor(string ntPath, bool asSystem, bool debug)
        {
            bool status;
            IntPtr hObject;

            if (!ntPath.StartsWith("/") && !ntPath.StartsWith("\\"))
            {
                Console.WriteLine("[-] NT object path should be start with \"/\" or \"\\\" .");

                return false;
            }

            status = Helpers.GetNtObjectType(ref ntPath, out string objectType);

            Console.WriteLine("[>] Trying to dump SecurityDescriptor for the specified NT object path.");
            Console.WriteLine("    [*] Path : {0}", ntPath);
            Console.WriteLine("    [*] Type : {0}", string.IsNullOrEmpty(objectType) ? "N/A" : objectType);

            if (!status)
            {
                Console.WriteLine("[-] The specified NT object is not found, or access is denied.");

                return false;
            }

            if (!InitializePrivilegesAndParameters(
                asSystem,
                debug,
                out ACCESS_MASK accessMask,
                out SECURITY_INFORMATION securityInformation,
                out bool isImpersonated))
            {
                return false;
            }

            hObject = Utilities.GetNtObjectHandle(ntPath, accessMask, objectType);
            status = (hObject != IntPtr.Zero);

            if (status)
            {
                if (Utilities.GetSecurityDescriptorInformation(
                    hObject,
                    securityInformation,
                    out IntPtr pSecurityDescriptor))
                {
                    if (NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        pSecurityDescriptor,
                        Win32Consts.SDDL_REVISION_1,
                        securityInformation,
                        out IntPtr pStringSecurityDescriptor,
                        IntPtr.Zero))
                    {
                        Console.WriteLine("[+] Got valid SecuritySescriptor string.");
                        Console.WriteLine("    [*] SDDL : {0}", Marshal.PtrToStringUni(pStringSecurityDescriptor));
                        NativeMethods.LocalFree(pStringSecurityDescriptor);
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to get valid SecurityDescriptor string.");
                    }

                    Console.WriteLine(Utilities.DumpSecurityDescriptor(pSecurityDescriptor, objectType, false));
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                }

                NativeMethods.NtClose(hObject);
            }
            else if (!Utilities.IsSupportedNtObjectType(objectType))
            {
                Console.WriteLine("[-] The specified NT object is not supported.");
            }
            else
            {
                Console.WriteLine("[-] Failed to open the specified NT object.");
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool DumpPrimaryTokenInformation(int pid, bool asSystem, bool debug)
        {
            int error;
            bool status;
            IntPtr hProcess;
            string processName;

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Specified PID is not found.");

                return false;
            }

            Console.WriteLine("[>] Trying to dump primary token's ACL information for the specified process.");
            Console.WriteLine("    [*] Process ID   : {0}", pid);
            Console.WriteLine("    [*] Process Name : {0}", processName);

            if (!InitializePrivilegesAndParameters(asSystem, debug, out bool isImpersonated))
                return false;

            hProcess = NativeMethods.OpenProcess(
                ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);
            status = (hProcess != IntPtr.Zero);

            if (status)
            {
                if (NativeMethods.OpenProcessToken(
                    hProcess,
                    TokenAccessFlags.TOKEN_QUERY,
                    out IntPtr hToken))
                {
                    Console.WriteLine(Utilities.GetTokenAclInformation(hToken));
                    NativeMethods.NtClose(hToken);
                }
                else
                {
                    Console.WriteLine("[-] Failed to open process token.");
                }

                NativeMethods.NtClose(hProcess);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open the specified process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool DumpProcessSecurityDescriptor(int pid, bool asSystem, bool debug)
        {
            int error;
            bool status;
            IntPtr hProcess;
            string processName;

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Specified PID is not found.");

                return false;
            }

            Console.WriteLine("[>] Trying to dump SecurityDescriptor for the specified process.");
            Console.WriteLine("    [*] Process ID   : {0}", pid);
            Console.WriteLine("    [*] Process Name : {0}", processName);

            if (!InitializePrivilegesAndParameters(
                asSystem,
                debug,
                out ACCESS_MASK accessMask,
                out SECURITY_INFORMATION securityInformation,
                out bool isImpersonated))
            {
                return false;
            }

            hProcess = NativeMethods.OpenProcess(accessMask, false, pid);
            status = (hProcess != IntPtr.Zero);

            if (status)
            {
                if (Utilities.GetSecurityDescriptorInformation(
                    hProcess,
                    securityInformation,
                    out IntPtr pSecurityDescriptor))
                {
                    if (NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        pSecurityDescriptor,
                        Win32Consts.SDDL_REVISION_1,
                        securityInformation,
                        out IntPtr pStringSecurityDescriptor,
                        IntPtr.Zero))
                    {
                        Console.WriteLine("[+] Got valid SecuritySescriptor string.");
                        Console.WriteLine("    [*] SDDL : {0}", Marshal.PtrToStringUni(pStringSecurityDescriptor));
                        NativeMethods.LocalFree(pStringSecurityDescriptor);
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to get valid SecurityDescriptor string.");
                    }

                    Console.WriteLine(Utilities.DumpSecurityDescriptor(pSecurityDescriptor, "Process", false));
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                }

                NativeMethods.NtClose(hProcess);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open the specified process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool DumpRegistrySecurityDescriptor(string key, string subKey, bool asSystem, bool debug)
        {
            int error;
            bool status;
            UIntPtr hKey;

            if (Regex.IsMatch(key, @"(HKCR|HKEY_CLASSES_ROOT)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_CLASSES_ROOT);
            }
            else if (Regex.IsMatch(key, @"(HKCU|HKEY_CURRENT_USER)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_CURRENT_USER);
            }
            else if (Regex.IsMatch(key, @"(HKLM|HKEY_LOCAL_MACHINE)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_LOCAL_MACHINE);
            }
            else if (Regex.IsMatch(key, @"(HKU|HKEY_USERS)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_USERS);
            }
            else if (Regex.IsMatch(key, @"(HKCC|HKEY_CURRENT_CONFIG)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_CURRENT_CONFIG);
            }
            else
            {
                Console.WriteLine("[!] Invalid key is specified.");
                return false;
            }

            Console.WriteLine("[>] Trying to dump SecurityDescriptor for the specified registry key.");
            Console.WriteLine("    [*] Root Key : {0}", ((HKEY)hKey.ToUInt32()).ToString());
            Console.WriteLine("    [*] Sub Key  : {0}", subKey);

            if (!InitializePrivilegesAndParameters(
                asSystem,
                debug,
                out ACCESS_MASK accessMask,
                out SECURITY_INFORMATION securityInformation,
                out bool isImpersonated))
            {
                return false;
            }

            error = NativeMethods.RegOpenKeyEx(
                hKey,
                subKey,
                REG_OPTION.RESERVED,
                (KEY_ACCESS)accessMask,
                out IntPtr hRegistry);
            status = (error == Win32Consts.ERROR_SUCCESS);

            if (status)
            {
                if (Utilities.GetSecurityDescriptorInformation(
                    hRegistry,
                    securityInformation,
                    out IntPtr pSecurityDescriptor))
                {
                    if (NativeMethods.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        pSecurityDescriptor,
                        Win32Consts.SDDL_REVISION_1,
                        securityInformation,
                        out IntPtr pStringSecurityDescriptor,
                        IntPtr.Zero))
                    {
                        Console.WriteLine("[+] Got valid SecuritySescriptor string.");
                        Console.WriteLine("    [*] SDDL : {0}", Marshal.PtrToStringUni(pStringSecurityDescriptor));
                        NativeMethods.LocalFree(pStringSecurityDescriptor);
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to get valid SecurityDescriptor string.");
                    }

                    Console.WriteLine(Utilities.DumpSecurityDescriptor(pSecurityDescriptor, "Key", false));
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                }

                NativeMethods.NtClose(hRegistry);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open the specified registry key.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool EnumerateNtObjectDirectory(string ntPath, bool asSystem, bool debug)
        {
            NTSTATUS ntstatus;
            bool status;
            string lineFormat;
            OBJECT_ATTRIBUTES objectAttributes;
            string typeColumnName = "Object Type";
            string itemColumnName = "Object Name";
            int nMaxTypeLength = typeColumnName.Length;
            int nMaxItemLength = itemColumnName.Length;

            if (!ntPath.StartsWith("/") && !ntPath.StartsWith("\\"))
            {
                Console.WriteLine("[-] NT object path should be start with \"/\" or \"\\\" .");

                return false;
            }

            status = Helpers.GetNtObjectType(ref ntPath, out string objectType);

            if (!status || (string.Compare(objectType, "Directory", true) != 0))
            {
                ntPath = Regex.Replace(ntPath, @"\\[^\\]+$", string.Empty);

                if (string.IsNullOrEmpty(ntPath))
                    ntPath = @"\";

                status = Helpers.GetNtObjectType(ref ntPath, out objectType);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to find the specified NT object.");
                    return false;
                }
                else if (string.Compare(objectType, "Directory", true) != 0)
                {
                    Console.WriteLine("[-] Failed to find parent NT object directory.");
                    return false;
                }
            }

            Console.WriteLine("[>] Trying to enumerate NT object directory.");
            Console.WriteLine("    [*] Path : {0}", ntPath);
            Console.WriteLine("    [*] Type : {0}", string.IsNullOrEmpty(objectType) ? "N/A" : objectType);

            objectAttributes = new OBJECT_ATTRIBUTES(ntPath, OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);

            if (!InitializePrivilegesAndParameters(
                asSystem,
                debug,
                out ACCESS_MASK _,
                out SECURITY_INFORMATION _,
                out bool isImpersonated))
            {
                return false;
            }

            ntstatus = NativeMethods.NtOpenDirectoryObject(
                out IntPtr hObject,
                ACCESS_MASK.DIRECTORY_QUERY,
                in objectAttributes);
            status = (ntstatus == Win32Consts.STATUS_SUCCESS);

            if (status)
            {
                status = Helpers.EnumNtDirectoryItems(
                    hObject,
                    out Dictionary<string, string> items);

                if (status)
                {
                    foreach (var item in items)
                    {
                        if (item.Value.Length > nMaxTypeLength)
                            nMaxTypeLength = item.Value.Length;
                    }

                    lineFormat = string.Format("    {{0,-{0}}} {{1,-{1}}}", nMaxTypeLength, nMaxItemLength);

                    Console.WriteLine();
                    Console.WriteLine(lineFormat, typeColumnName, itemColumnName);
                    Console.WriteLine(lineFormat, new string('=', nMaxTypeLength), new string('=', nMaxItemLength));

                    foreach (var item in items)
                    {
                        Console.WriteLine(lineFormat, item.Value, item.Key);
                    }

                    Console.WriteLine();
                }
                else
                {
                    Console.WriteLine("\n[*] The specified directory is empty.\n");
                }

                NativeMethods.NtClose(hObject);
            }
            else
            {
                Console.WriteLine("[-] Failed to open the specified NT object.");
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool SetFileSecurityDescriptor(string filePath, string sddl, bool asSystem, bool debug)
        {
            NTSTATUS ntstatus;
            int error;
            bool status;
            IntPtr hFile;
            string objectType;
            FILE_ATTRIBUTE fileAttributes;
            string fullPathName;
            filePath = filePath.Replace('/', '\\');
            fullPathName = Regex.IsMatch(filePath, @"^\\\S+") ? filePath : Path.GetFullPath(filePath);

            fileAttributes = NativeMethods.GetFileAttributes(fullPathName);

            if (fileAttributes == FILE_ATTRIBUTE.INVALID)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open {0}.", fullPathName);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, true));

                return false;
            }
            else if (fileAttributes.HasFlag(FILE_ATTRIBUTE.DIRECTORY))
            {
                objectType = "StandardDirectory";
                fileAttributes = FILE_ATTRIBUTE.DIRECTORY | FILE_ATTRIBUTE.BACKUP_SEMANTICS;
            }
            else
            {
                if (Regex.IsMatch(fullPathName, @"\\\\\.\\pipe"))
                    objectType = "Pipe";
                else
                    objectType = "File";

                fileAttributes = FILE_ATTRIBUTE.NORMAL;
            }

            Console.WriteLine("[>] Trying to dump SecurityDescriptor for the specified path.");
            Console.WriteLine("    [*] Path : {0}", fullPathName);
            Console.WriteLine("    [*] Type : {0}", objectType);

            if (!InitializePrivilegesAndParametersBySddl(
                sddl,
                asSystem,
                debug,
                out ACCESS_MASK accessMask,
                out SECURITY_INFORMATION securityInformation,
                out IntPtr pSecurityDescriptor,
                out bool isImpersonated))
            {
                return false;
            }

            hFile = NativeMethods.CreateFile(
                fullPathName,
                accessMask,
                FILE_SHARE.NONE,
                IntPtr.Zero,
                CREATE_DESPOSITION.OPEN_EXISTING,
                fileAttributes,
                IntPtr.Zero);
            status = (hFile != Win32Consts.INVALID_HANDLE_VALUE);

            if (status)
            {
                Console.WriteLine("[>] Trying to set new Security Descriptor to the specfied object.");

                ntstatus = NativeMethods.NtSetSecurityObject(
                    hFile,
                    securityInformation,
                    pSecurityDescriptor);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[+] Security Descriptor is set successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to set new Security Descriptor.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }

                NativeMethods.NtClose(hFile);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open the specified file or directory.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool SetNtObjectSecurityDescriptor(string ntPath, string sddl, bool asSystem, bool debug)
        {
            NTSTATUS ntstatus;
            bool status;
            IntPtr hObject;

            if (!ntPath.StartsWith("/") && !ntPath.StartsWith("\\"))
            {
                Console.WriteLine("[-] NT object path should be start with \"/\" or \"\\\" .");

                return false;
            }

            status = Helpers.GetNtObjectType(ref ntPath, out string objectType);

            Console.WriteLine("[>] Trying to dump SecurityDescriptor for the specified NT object path.");
            Console.WriteLine("    [*] Path : {0}", ntPath);
            Console.WriteLine("    [*] Type : {0}", string.IsNullOrEmpty(objectType) ? "N/A" : objectType);

            if (!status)
            {
                Console.WriteLine("[-] The specified NT object is not found, or access is denied.");

                return false;
            }

            if (!InitializePrivilegesAndParametersBySddl(
                sddl,
                asSystem,
                debug,
                out ACCESS_MASK accessMask,
                out SECURITY_INFORMATION securityInformation,
                out IntPtr pSecurityDescriptor,
                out bool isImpersonated))
            {
                return false;
            }

            hObject = Utilities.GetNtObjectHandle(ntPath, accessMask, objectType);
            status = (hObject != IntPtr.Zero);

            if (status)
            {
                Console.WriteLine("[>] Trying to set new Security Descriptor to the specfied object.");

                ntstatus = NativeMethods.NtSetSecurityObject(
                    hObject,
                    securityInformation,
                    pSecurityDescriptor);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[+] Security Descriptor is set successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to set new Security Descriptor.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }

                NativeMethods.NtClose(hObject);
            }
            else if (!Utilities.IsSupportedNtObjectType(objectType))
            {
                Console.WriteLine("[-] The specified NT object is not supported.");
            }
            else
            {
                Console.WriteLine("[-] Failed to open the specified NT object.");
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool SetRegistrySecurityDescriptor(string key, string subKey, string sddl, bool asSystem, bool debug)
        {
            NTSTATUS ntstatus;
            int error;
            bool status;
            UIntPtr hKey;

            if (Regex.IsMatch(key, @"(HKCR|HKEY_CLASSES_ROOT)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_CLASSES_ROOT);
            }
            else if (Regex.IsMatch(key, @"(HKCU|HKEY_CURRENT_USER)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_CURRENT_USER);
            }
            else if (Regex.IsMatch(key, @"(HKLM|HKEY_LOCAL_MACHINE)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_LOCAL_MACHINE);
            }
            else if (Regex.IsMatch(key, @"(HKU|HKEY_USERS)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_USERS);
            }
            else if (Regex.IsMatch(key, @"(HKCC|HKEY_CURRENT_CONFIG)", RegexOptions.IgnoreCase))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_CURRENT_CONFIG);
            }
            else
            {
                Console.WriteLine("[!] Invalid key is specified.");
                return false;
            }

            Console.WriteLine("[>] Trying to dump SecurityDescriptor for the specified registry key.");
            Console.WriteLine("    [*] Root Key : {0}", ((HKEY)hKey.ToUInt32()).ToString());
            Console.WriteLine("    [*] Sub Key  : {0}", subKey);

            if (!InitializePrivilegesAndParametersBySddl(
                sddl,
                asSystem,
                debug,
                out ACCESS_MASK accessMask,
                out SECURITY_INFORMATION securityInformation,
                out IntPtr pSecurityDescriptor,
                out bool isImpersonated))
            {
                return false;
            }

            error = NativeMethods.RegOpenKeyEx(
                hKey,
                subKey,
                REG_OPTION.RESERVED,
                (KEY_ACCESS)accessMask,
                out IntPtr hRegistry);
            status = (error == Win32Consts.ERROR_SUCCESS);

            if (status)
            {
                Console.WriteLine("[>] Trying to set new Security Descriptor to the specfied object.");

                ntstatus = NativeMethods.NtSetSecurityObject(
                    hRegistry,
                    securityInformation,
                    pSecurityDescriptor);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[+] Security Descriptor is set successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to set new Security Descriptor.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }

                NativeMethods.NtClose(hRegistry);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open the specified registry key.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
