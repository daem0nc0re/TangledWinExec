using GetEPROCESSBase.Interop;
using GetEPROCESSBase.Library;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace GetEPROCESSBase
{
    using NTSTATUS = Int32;

    internal class GetEPROCESSBase
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: {0} <pid>", AppDomain.CurrentDomain.FriendlyName);
                return;
            }
            else if (!Environment.Is64BitProcess && Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("[-] In 64bit OS, must be built as 64bit program.");
                return;
            }

            IntPtr pEprocess;
            string processName;
            var pid = Convert.ToInt32(args[0]);
            var objattr = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var cid = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.QueryLimitedInformation,
                in objattr,
                in cid);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get a handle from the specified process (NTSTATUS = 0x{0})",
                    ntstatus.ToString("X8"));
                return;
            }

            do
            {
                pEprocess = Helpers.GetHandleAddress(
                    Process.GetCurrentProcess().Id,
                    hProcess);

                try
                {
                    processName = Process.GetProcessById(pid).ProcessName.Trim();
                }
                catch
                {
                    processName = null;
                }
            } while (false);

            NativeMethods.NtClose(hProcess);

            if (pEprocess == new IntPtr(-1))
            {
                Console.WriteLine("[-] Failed to get EPROCESS for {0} (PID: {1})",
                    string.IsNullOrEmpty(processName) ? "N/A" : processName,
                    cid.UniqueProcess);
            }
            else
            {
                Console.WriteLine("[+] EPROCESS for {0} (PID: {1}) is at 0x{2}",
                    string.IsNullOrEmpty(processName) ? "N/A" : processName,
                    cid.UniqueProcess,
                    pEprocess.ToString(Environment.Is64BitProcess ? "X16" : "X8"));

                if (pEprocess == IntPtr.Zero)
                    Console.WriteLine("[!] Since Win11 24H2, SeDebugPrivilege is required to get EPROCESS address.");
            }
        }
    }
}
