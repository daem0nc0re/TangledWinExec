using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using SdDumper.Interop;

namespace SdDumper.Library
{
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
            accessMask = ACCESS_MASK.READ_CONTROL;
            securityInformation =
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION |
                SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION |
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION;
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

            if (Utilities.IsPrivilegeAvailable(Win32Consts.SE_SECURITY_NAME))
            {
                accessMask |= ACCESS_MASK.ACCESS_SYSTEM_SECURITY;
                securityInformation |= SECURITY_INFORMATION.SACL_SECURITY_INFORMATION;

                Utilities.EnableSinglePrivilege(Win32Consts.SE_SECURITY_NAME);
            }

            return true;
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
                Utilities.DumpSecurityDescriptor(pSecurityDescriptor, Utilities.ObjectType.Unknown, true);
                NativeMethods.LocalFree(pSecurityDescriptor);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to analyze the specified SDDL.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }

            Console.WriteLine("[*] Done");

            return status;
        }


        public static bool DumpFileSecurityDescriptor(string filePath, bool asSystem, bool debug)
        {
            int error;
            bool status;
            IntPtr hFile;
            FILE_ATTRIBUTE fileAttributes;
            string fullPathName = Path.GetFullPath(filePath);

            if (!File.Exists(fullPathName) && !Directory.Exists(fullPathName))
            {
                Console.WriteLine("[-] Specified path is not found.");

                return false;
            }

            if (Directory.Exists(fullPathName))
            {
                fileAttributes = FILE_ATTRIBUTE.DIRECTORY | FILE_ATTRIBUTE.BACKUP_SEMANTICS;
            }
            else
            {
                fileAttributes = FILE_ATTRIBUTE.NORMAL;
            }

            Console.WriteLine("[>] Trying to dump SecurityDescriptor for the specified path.");
            Console.WriteLine("    [*] Path : {0}", fullPathName);

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

                    Utilities.DumpSecurityDescriptor(pSecurityDescriptor, Utilities.ObjectType.File, false);
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                }

                NativeMethods.CloseHandle(hFile);
            }
            else
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open the specified file or directory.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, true));
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
                    Utilities.GetTokenAclInformation(hToken);
                    NativeMethods.CloseHandle(hToken);
                }
                else
                {
                    Console.WriteLine("[-] Failed to open process token.");
                }

                NativeMethods.CloseHandle(hProcess);
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

                    Utilities.DumpSecurityDescriptor(pSecurityDescriptor, Utilities.ObjectType.Process, false);
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                }

                NativeMethods.CloseHandle(hProcess);
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

            if (Helpers.CompareIgnoreCase(key, "HKCR") ||
                Helpers.CompareIgnoreCase(key, "HKEY_CLASSES_ROOT"))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_CLASSES_ROOT);
            }
            else if (Helpers.CompareIgnoreCase(key, "HKCU") ||
                Helpers.CompareIgnoreCase(key, "HKEY_CURRENT_USER"))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_CURRENT_USER);
            }
            else if (Helpers.CompareIgnoreCase(key, "HKLM") ||
                Helpers.CompareIgnoreCase(key, "HKEY_LOCAL_MACHINE"))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_LOCAL_MACHINE);
            }
            else if (Helpers.CompareIgnoreCase(key, "HKU") ||
                Helpers.CompareIgnoreCase(key, "HKEY_USERS"))
            {
                hKey = new UIntPtr((uint)HKEY.HKEY_USERS);
            }
            else if (Helpers.CompareIgnoreCase(key, "HKCC") ||
                Helpers.CompareIgnoreCase(key, "HKEY_CURRENT_CONFIG"))
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

                    Utilities.DumpSecurityDescriptor(pSecurityDescriptor, Utilities.ObjectType.Registry, false);
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                }

                NativeMethods.CloseHandle(hRegistry);
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
