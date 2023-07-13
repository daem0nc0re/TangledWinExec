using System;
using System.Collections.Generic;
using HandleScanner.Interop;

namespace HandleScanner.Library
{
    internal class Modules
    {
        public static bool GetProcessHandleInformation(
            int pid,
            string typeFilter,
            bool verbose,
            bool debug,
            bool asSystem)
        {
            bool status;
            var isImpersonated = false;
            Globals.TypeTable = Helpers.GetObjectTypeTable();

            if (Globals.TypeTable.Count == 0)
            {
                Console.WriteLine("[!] Cannot retrieve type index information.");
                return false;
            }

            if (asSystem)
            {
                Console.WriteLine("[>] Trying to get SYSTEM privileges.");

                status = Utilities.EnableTokenPrivileges(
                    new List<string> { Win32Consts.SE_DEBUG_NAME, Win32Consts.SE_IMPERSONATE_NAME },
                    out Dictionary<string, bool> adjustedPrivs);

                if (status)
                {
                    isImpersonated = Utilities.ImpersonateAsSmss(new List<string> { Win32Consts.SE_DEBUG_NAME });

                    if (isImpersonated)
                    {
                        Console.WriteLine("[+] Got SYSTEM privileges.\n");
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to get SYSTEM privileges.");
                        return false;
                    }
                }
                else
                {
                    foreach (var priv in adjustedPrivs)
                    {
                        if (!priv.Value)
                            Console.WriteLine("[-] Failed to enable {0}", priv.Key);
                    }

                    return false;
                }
            }
            else if (debug)
            {
                Console.WriteLine("[>] Trying to enable {0}.", Win32Consts.SE_DEBUG_NAME);

                if (Utilities.EnableTokenPrivileges(
                    new List<string> { Win32Consts.SE_DEBUG_NAME },
                    out Dictionary<string, bool> _))
                {
                    Console.WriteLine("[+] {0} is enabled successfully.\n", Win32Consts.SE_DEBUG_NAME);
                }
                else
                {
                    Console.WriteLine("[-] Failed to enable {0}", Win32Consts.SE_DEBUG_NAME);
                    return false;
                }
            }

            do
            {
                status = Helpers.GetSystemHandleInformation(
                    out Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>> info);

                if (pid != 0)
                {
                    if (info.ContainsKey(pid))
                    {
                        Utilities.DumpHandleInformation(pid, info[pid], typeFilter, verbose);
                    }
                    else
                    {
                        Console.WriteLine("[!] The specified PID is not found.");
                    }
                }
                else
                {
                    foreach (var entry in info)
                    {
                        Utilities.DumpHandleInformation(entry.Key, entry.Value, typeFilter, verbose);
                    }
                }
            } while (false);

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
