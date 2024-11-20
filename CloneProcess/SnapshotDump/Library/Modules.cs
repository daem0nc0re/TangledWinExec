using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using SnapshotDump.Interop;

namespace SnapshotDump.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool DumpRemoteProcess(int pid, string outputPath, bool asSystem, bool debug)
        {
            NTSTATUS ntstatus;
            bool gotPeb;
            int error;
            int forkedPid;
            string processName;
            OBJECT_ATTRIBUTES objectAttributes;
            var hProcessToFork = IntPtr.Zero;
            var hForkedProcess = IntPtr.Zero;
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

                Console.WriteLine("[>] Trying to get snapshot process.");

                ntstatus = NativeMethods.NtCreateProcessEx(
                    out hForkedProcess,
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
                    Console.WriteLine("[-] Failed to get process snapshot.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    gotPeb = Helpers.GetProcessBasicInformation(hForkedProcess, out PROCESS_BASIC_INFORMATION pbi);

                    if (gotPeb)
                        forkedPid = (int)pbi.UniqueProcessId.ToUInt32();
                    else
                        forkedPid = 0;

                    Console.WriteLine("[+] Got a target process snapshot successfully.");
                    Console.WriteLine("    [*] Process ID : {0}", (forkedPid == 0) ? "N/A" : forkedPid.ToString());
                    Console.WriteLine("    [*] Handle     : 0x{0}", hForkedProcess.ToString("X"));
                }

                if (forkedPid == 0)
                {
                    Console.WriteLine("[-] Failed to get snapshot Process ID.");
                    break;
                }

                if (string.IsNullOrEmpty(outputPath))
                    outputPath = Utilities.GetOutputFilePath(string.Format(@"{0}_{1}.dmp", processName, pid.ToString()));
                else
                    outputPath = Utilities.GetOutputFilePath(outputPath);

                objectAttributes = new OBJECT_ATTRIBUTES(
                    string.Format(@"\??\{0}", outputPath),
                    OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);

                Console.WriteLine("[>] Dumping snapshot process.");
                Console.WriteLine("    [*] Output Path : {0}", outputPath);

                ntstatus = NativeMethods.NtCreateFile(
                    out IntPtr hOutputFile,
                    ACCESS_MASK.FILE_ALL_ACCESS,
                    in objectAttributes,
                    out IO_STATUS_BLOCK _,
                    IntPtr.Zero,
                    FILE_ATTRIBUTE_FLAGS.NORMAL,
                    FILE_SHARE_ACCESS.NONE,
                    FILE_CREATE_DISPOSITION.OPEN_IF,
                    FILE_CREATE_OPTIONS.NON_DIRECTORY_FILE | FILE_CREATE_OPTIONS.SYNCHRONOUS_IO_NONALERT,
                    IntPtr.Zero,
                    0u);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to create output file.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                
                status = NativeMethods.MiniDumpWriteDump(
                    hForkedProcess,
                    forkedPid,
                    hOutputFile,
                    MINIDUMP_TYPE.MiniDumpWithFullMemory,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);
                NativeMethods.NtClose(hOutputFile);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to dump snapshot process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    File.Delete(outputPath);
                }
                else
                {
                    Console.WriteLine("[+] Snapshot process is dumped successfully.");
                }
            } while (false);

            if (asSystem)
                NativeMethods.RevertToSelf();

            if (hForkedProcess != IntPtr.Zero)
                NativeMethods.NtClose(hForkedProcess);

            if (hProcessToFork != IntPtr.Zero)
                NativeMethods.NtClose(hProcessToFork);

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
