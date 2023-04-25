using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using RemoteForking.Interop;

namespace RemoteForking.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool ForkRemoteProcess(int pid, bool asSystem, bool debug)
        {
            NTSTATUS ntstatus;
            int error;
            int forkedPid;
            string processName;
            var hProcessToFork = IntPtr.Zero;
            var pInfoBuffer = IntPtr.Zero;
            var status = false;

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;

                Console.WriteLine("[*] Target process information:");
                Console.WriteLine("    [*] Process ID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);
            }
            catch
            {
                Console.WriteLine("[!] The specified PID is not found.");
                return false;
            }

            do
            {
                if (asSystem)
                {
                    Console.WriteLine("[>] Trying to impersonate as SYSTEM.");
                    asSystem = Utilities.ImpersonateAsWinlogon();

                    if (!asSystem)
                    {
                        Console.WriteLine("Failed to impoersonate as winlogon");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[*] Impersonation is successful.");
                    }
                }

                if (debug)
                {
                    Console.WriteLine("[>] Trying to enable {0}.", Win32Consts.SE_DEBUG_NAME);

                    if (!Utilities.EnableSinglePrivilege(Win32Consts.SE_DEBUG_NAME))
                    {
                        Console.WriteLine("[-] Failed to enable {0}.", Win32Consts.SE_DEBUG_NAME);
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] {0} is enabled successfully.", Win32Consts.SE_DEBUG_NAME);
                    }
                }

                Console.WriteLine("[>] Trying to get a target process handle.");

                hProcessToFork = NativeMethods.OpenProcess(ACCESS_MASK.PROCESS_CREATE_PROCESS, false, pid);

                if (hProcessToFork == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to get process handle.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a process handle.");
                    Console.WriteLine("    [*] Handle : 0x{0}", hProcessToFork.ToString("X"));
                }

                Console.WriteLine("[>] Trying to fork the target process.");

                ntstatus = NativeMethods.NtCreateProcessEx(
                    out IntPtr hForkedProcess,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    hProcessToFork,
                    NT_PROCESS_CREATION_FLAGS.NONE,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    BOOLEAN.TRUE);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Console.WriteLine("[-] Process forking is failed.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }
                else
                {
                    status = Helpers.GetProcessBasicInformation(hForkedProcess, out PROCESS_BASIC_INFORMATION pbi);

                    if (!status)
                        forkedPid = 0;
                    else
                        forkedPid = (int)pbi.UniqueProcessId.ToUInt32();

                    Console.WriteLine("[+] The target process is forked successfully.");
                    Console.WriteLine("    [*] Process ID : {0}", (forkedPid == 0) ? "N/A" : forkedPid.ToString());
                    Console.WriteLine("    [*] Handle     : 0x{0}", hForkedProcess.ToString("X"));
                    Console.WriteLine("[*] To exit this program, hit [ENTER] key.");
                    Console.ReadLine();

                    ntstatus = NativeMethods.NtTerminateProcess(hForkedProcess, Win32Consts.STATUS_SUCCESS);
                    status = (ntstatus == Win32Consts.STATUS_SUCCESS);
                }
            } while (false);

            if (pInfoBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pInfoBuffer);

            if (hProcessToFork != IntPtr.Zero)
                NativeMethods.NtClose(hProcessToFork);

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
