using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ProcAccessCheck.Interop;

namespace ProcAccessCheck.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool GetMaximumAccess(int pid, bool asSystem, bool debug)
        {
            NTSTATUS ntstatus;
            IntPtr hProcess;
            IntPtr pInfoBuffer;
            string processName;
            string currentUser;
            string integrityLevel;
            int nInfoBufferSize = Marshal.SizeOf(typeof(OBJECT_BASIC_INFORMATION));
            var maximumAccess = ACCESS_MASK_PROCESS.NO_ACCESS;
            var droppedAccess = ACCESS_MASK_PROCESS.NO_ACCESS;
            var validMask = ACCESS_MASK_PROCESS.NO_ACCESS;
            var isImpersonated = false;
            var status = false;
            var handles = new Dictionary<ACCESS_MASK, IntPtr>();
            var accessMasks = new List<ACCESS_MASK>
            {
                ACCESS_MASK.PROCESS_TERMINATE,
                ACCESS_MASK.PROCESS_CREATE_THREAD,
                ACCESS_MASK.PROCESS_SET_SESSIONID,
                ACCESS_MASK.PROCESS_VM_OPERATION,
                ACCESS_MASK.PROCESS_VM_READ,
                ACCESS_MASK.PROCESS_VM_WRITE,
                ACCESS_MASK.PROCESS_DUP_HANDLE,
                ACCESS_MASK.PROCESS_CREATE_PROCESS,
                ACCESS_MASK.PROCESS_SET_QUOTA,
                ACCESS_MASK.PROCESS_SET_INFORMATION,
                ACCESS_MASK.PROCESS_QUERY_INFORMATION,
                ACCESS_MASK.PROCESS_SUSPEND_RESUME,
                ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                ACCESS_MASK.PROCESS_SET_LIMITED_INFORMATION,
                ACCESS_MASK.DELETE,
                ACCESS_MASK.READ_CONTROL,
                ACCESS_MASK.WRITE_DAC,
                ACCESS_MASK.WRITE_OWNER,
                ACCESS_MASK.SYNCHRONIZE
            };

            foreach (var accessMask in accessMasks)
                validMask |= (ACCESS_MASK_PROCESS)accessMask;

            do
            {
                if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
                {
                    Console.WriteLine("[-] For 64bit OS, should be built as 64bit program.");
                    break;
                }

                if (asSystem)
                {
                    Console.WriteLine("[>] Trying to impersonate as SYSTEM.");
                    isImpersonated = Utilities.ImpersonateAsWinlogon();

                    if (!isImpersonated)
                        break;
                    else
                        Console.WriteLine("[+] Impersonated as SYSTEM successfully.");
                }

                if (debug)
                {
                    Console.WriteLine("[>] Trying to enable {0},", Win32Consts.SE_DEBUG_NAME);

                    if (!Utilities.EnableSinglePrivilege(Win32Consts.SE_DEBUG_NAME))
                    {
                        Console.WriteLine("[-] {0} is not available.", Win32Consts.SE_DEBUG_NAME);
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] {0} is enabled successfully.", Win32Consts.SE_DEBUG_NAME);
                    }
                }

                try
                {
                    processName = Process.GetProcessById(pid).ProcessName;

                    Console.WriteLine("[*] Trying to check maximum access for the specified process.");
                    Console.WriteLine("    [*] Process ID   : {0}", pid);
                    Console.WriteLine("    [*] Process Name : {0}", processName);
                }
                catch
                {
                    Console.WriteLine("[!] The specified PID is not found.");
                    break;
                }

                currentUser = Helpers.GetCurrentTokenUserName();
                integrityLevel = Helpers.GetCurrentTokenIntegrityLevel();

                Console.WriteLine("[*] Current User Information:");
                Console.WriteLine("    [*] Account Name    : {0}", string.IsNullOrEmpty(currentUser) ? "N/A" : currentUser);
                Console.WriteLine("    [*] Integrity Level : {0}", string.IsNullOrEmpty(integrityLevel) ? "N/A" : integrityLevel);

                Console.WriteLine("[>] Trying to get process handle.");

                hProcess = NativeMethods.OpenProcess(ACCESS_MASK.PROCESS_ALL_ACCESS, false, pid);

                if (hProcess == IntPtr.Zero)
                {
                    foreach (var access in accessMasks)
                    {
                        hProcess = NativeMethods.OpenProcess(access, false, pid);

                        if (hProcess != IntPtr.Zero)
                            handles.Add(access, hProcess);
                    }
                }
                else
                {
                    handles.Add(ACCESS_MASK.PROCESS_ALL_ACCESS, hProcess);
                }

                pInfoBuffer = Marshal.AllocHGlobal(nInfoBufferSize);

                foreach (var handle in handles)
                {
                    Helpers.ZeroMemory(pInfoBuffer, nInfoBufferSize);

                    ntstatus = NativeMethods.NtQueryObject(
                        handle.Value,
                        OBJECT_INFORMATION_CLASS.ObjectBasicInformation,
                        pInfoBuffer,
                        nInfoBufferSize,
                        out int _);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        var info = (OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(OBJECT_BASIC_INFORMATION));

                        if (info.GrantedAccess == handle.Key)
                        {
                            maximumAccess |= (ACCESS_MASK_PROCESS)info.GrantedAccess;
                        }
                        else if (info.GrantedAccess == ACCESS_MASK.NO_ACCESS)
                        {
                            droppedAccess |= (ACCESS_MASK_PROCESS)handle.Key;
                        }
                        else
                        {
                            maximumAccess |= (ACCESS_MASK_PROCESS)info.GrantedAccess;
                            droppedAccess |= (ACCESS_MASK_PROCESS)(handle.Key ^ info.GrantedAccess) & validMask;
                        }
                    }

                    NativeMethods.NtClose(handle.Value);
                }

                Marshal.FreeHGlobal(pInfoBuffer);

                Console.WriteLine("[+] Granted Access : {0}", maximumAccess.ToString());
                Console.WriteLine("[+] Dropped Access : {0}", (droppedAccess == ACCESS_MASK_PROCESS.NO_ACCESS) ? "(NONE)" : droppedAccess.ToString());
                status = true;
            } while (false);

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
