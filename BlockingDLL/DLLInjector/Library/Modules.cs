using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using DLLInjector.Interop;

namespace DLLInjector.Library
{
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static bool InjectLibraryToRemoteProcess(int pid, string pathToDll)
        {
            int error;
            bool status;
            IntPtr hProcess;
            IntPtr hThread;
            IntPtr pKernel32;
            IntPtr pLoadLibraryA;
            IntPtr pStringBuffer;
            string processName;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
            string fullPathToDll = Path.GetFullPath(pathToDll);

            if (!File.Exists(fullPathToDll))
            {
                Console.WriteLine("[-] Specified DLL is not found.");

                return false;
            }

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Target process is not found.");

                return false;
            }

            Console.WriteLine("[*] Trying to inject DLL.");
            Console.WriteLine("    [*] Process Name : {0}", processName);
            Console.WriteLine("    [*] Process ID   : {0}", pid);
            Console.WriteLine("    [*] DLL Path     : {0}", fullPathToDll);
            Console.WriteLine("[>] Trying to resolve the base address of LoadLibraryA API.");

            pKernel32 = Helpers.SearchDllBase("kernel32.dll");

            if (pKernel32 == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to search base address of kernel32.dll");

                return false;
            }
            else
            {
                Console.WriteLine("[+] The base address of kernel32.dll is 0x{0}.", pKernel32.ToString(addressFormat));
            }

            pLoadLibraryA = NativeMethods.GetProcAddress(pKernel32, "LoadLibraryA");

            if (pLoadLibraryA == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to search base address of LoadLibraryA API.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                Console.WriteLine("[+] The base address of LoadLibrarA API is 0x{0}.", pLoadLibraryA.ToString(addressFormat));
            }

            do
            {
                Console.WriteLine("[>] Trying to get a target process handle.");

                hProcess = NativeMethods.OpenProcess(
                    ProcessAccessFlags.PROCESS_CREATE_PROCESS | ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION | ProcessAccessFlags.PROCESS_VM_OPERATION | ProcessAccessFlags.PROCESS_VM_WRITE,
                    false,
                    pid);

                if (hProcess == IntPtr.Zero)
                {
                    status = false;
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to search base address of LoadLibraryA API.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got a target process handle.");
                    Console.WriteLine("    [*] hProcess : 0x{0}", hProcess.ToString("X"));
                }

                if (Environment.Is64BitOperatingSystem)
                {
                    NativeMethods.IsWow64Process(hProcess, out bool isWow64);

                    if (isWow64 && Environment.Is64BitProcess)
                    {
                        status = false;
                        Console.WriteLine("[-] For 32bit process, should be built as 32bit binary.");

                        break;
                    }
                    else if (!isWow64 && !Environment.Is64BitProcess)
                    {
                        status = false;
                        Console.WriteLine("[-] For 64bit process, should be built as 64bit binary.");

                        break;
                    }
                }

                Console.WriteLine("[>] Trying to allocate memory in the target process.");

                pStringBuffer = NativeMethods.VirtualAllocEx(
                    hProcess,
                    IntPtr.Zero,
                    new SIZE_T((uint)fullPathToDll.Length + 1u),
                    ALLOCATION_TYPE.COMMIT,
                    MEMORY_PROTECTION.READWRITE);

                if (pStringBuffer == IntPtr.Zero)
                {
                    status = false;
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to allocate memory in the target process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }
                else
                {
                    Console.WriteLine("[+] Memory is allocated at 0x{0} in the target process.", pStringBuffer.ToString(addressFormat));
                }

                Console.WriteLine("[>] Trying to write the path to DLL in the target process.");

                status = NativeMethods.WriteProcessMemory(
                    hProcess,
                    pStringBuffer,
                    Encoding.ASCII.GetBytes(fullPathToDll),
                    new SIZE_T((uint)fullPathToDll.Length),
                    IntPtr.Zero);

                if (!status)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to write DLL path in the target process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }
                else
                {
                    Console.WriteLine("[+] DLL path is written successfully.");
                }

                Console.WriteLine("[>] Trying to call LoadLibraryA API from the target process.");

                hThread = NativeMethods.CreateRemoteThread(
                    hProcess,
                    IntPtr.Zero,
                    SIZE_T.Zero,
                    pLoadLibraryA,
                    pStringBuffer,
                    ThreadCreationFlags.IMMEDIATE,
                    out int threadId);

                if (hProcess == IntPtr.Zero)
                {
                    status = false;
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to call LoadLibraryA API from the target process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    break;
                }
                else
                {
                    Console.WriteLine("[+] LoadLibraryA API is called successfully (TID : {0}).", threadId);
                    NativeMethods.CloseHandle(hThread);
                }
            } while (false);

            if (hProcess != IntPtr.Zero)
                NativeMethods.CloseHandle(hProcess);

            return status;
        }
    }
}
