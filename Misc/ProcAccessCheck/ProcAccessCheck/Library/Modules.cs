using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ProcAccessCheck.Interop;

namespace ProcAccessCheck.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool GetMaximumAccessForProcess(int pid, bool asSystem, bool debug)
        {
            NTSTATUS ntstatus;
            int error;
            IntPtr hProcess;
            IntPtr pInfoBuffer;
            string processName;
            PUBLIC_OBJECT_BASIC_INFORMATION info;
            int nInfoBufferSize = Marshal.SizeOf(typeof(PUBLIC_OBJECT_BASIC_INFORMATION));
            var isImpersonated = false;
            var status = false;

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

                Console.WriteLine("[>] Trying to get process handle.");

                hProcess = NativeMethods.OpenProcess(ACCESS_MASK.MAXIMUM_ALLOWED, false, pid);

                if (hProcess == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to get a maximum access handle from the specified process.");
                    Console.WriteLine("   |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got handle 0x{0}.", hProcess.ToString("X"));
                }

                Console.WriteLine("[>] Checking granted access for the opened process handle.");
                pInfoBuffer = Marshal.AllocHGlobal(nInfoBufferSize);
                ntstatus = NativeMethods.NtQueryObject(
                    hProcess,
                    OBJECT_INFORMATION_CLASS.ObjectBasicInformation,
                    pInfoBuffer,
                    nInfoBufferSize,
                    out int _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to get information from the opened process handle.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }
                else
                {
                    info = (PUBLIC_OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(PUBLIC_OBJECT_BASIC_INFORMATION));
                    Console.WriteLine("[+] Granted Access : {0}", ((ACCESS_MASK_PROCESS)info.GrantedAccess).ToString());
                }

                Marshal.FreeHGlobal(pInfoBuffer);
                NativeMethods.NtClose(hProcess);
            } while (false);

            if (isImpersonated)
                NativeMethods.RevertToSelf();

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
