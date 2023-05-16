using System;
using System.IO;
using System.Text.RegularExpressions;
using ProcMemScan.Library;

namespace ProcMemScan.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int pid;
            IntPtr pBaseAddress;
            uint nRange;
            var decimalPattern = new Regex(@"^[0-9]+$");
            var hexPattern = new Regex(@"^(0x)?[0-9A-Fa-f]{1,16}$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (string.IsNullOrEmpty(options.GetValue("pid")))
            {
                Console.WriteLine("\n[!] PID should be specified.\n");

                return;
            }
            else
            {
                if (!decimalPattern.IsMatch(options.GetValue("pid")))
                {
                    Console.WriteLine("\n[-] PID should be specfied as positive integer in decimal format.\n");

                    return;
                }

                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"), 10);
                }
                catch
                {
                    Console.WriteLine("\n[-] Failed to parse PID.\n");

                    return;
                }
            }

            if (string.IsNullOrEmpty(options.GetValue("base")))
            {
                pBaseAddress = IntPtr.Zero;
            }
            else
            {
                if (!hexPattern.IsMatch(options.GetValue("base")))
                {
                    Console.WriteLine("\n[-] Base address should be specfied in hex format.\n");

                    return;
                }

                try
                {
                    pBaseAddress = new IntPtr(Convert.ToInt64(options.GetValue("base"), 16));
                }
                catch
                {
                    Console.WriteLine("\n[-] Failed to parse base address.\n");

                    return;
                }
            }

            if (string.IsNullOrEmpty(options.GetValue("range")))
            {
                nRange = 0;
            }
            else
            {
                if (!hexPattern.IsMatch(options.GetValue("range")))
                {
                    Console.WriteLine("\n[-] Memory range should be specfied in hex format.\n");

                    return;
                }

                try
                {
                    nRange = (uint)Convert.ToInt32(options.GetValue("range"), 16);
                }
                catch
                {
                    Console.WriteLine("\n[-] Failed to parse memory range.\n");

                    return;
                }
            }

            if (pid == 0)
            {
                Console.WriteLine("\n[-] PID should be non-zero value.\n");

                return;
            }
            else if (options.GetFlag("list"))
            {
                Console.WriteLine();
                Modules.GetProcessMemoryInformation(pid);
                Console.WriteLine();
            }
            else if (options.GetFlag("dump"))
            {
                Console.WriteLine();
                Modules.DumpMemory(pid, pBaseAddress, nRange);
                Console.WriteLine();
            }
            else if (options.GetFlag("exports"))
            {
                Console.WriteLine();
                Modules.DumpExportItems(pid, pBaseAddress);
                Console.WriteLine();
            }
            else if (options.GetFlag("extract"))
            {
                Console.WriteLine();

                if (options.GetFlag("image"))
                    Modules.ExtractPeImageFile(pid, pBaseAddress);
                else
                    Modules.ExtractMemory(pid, pBaseAddress, nRange);

                Console.WriteLine();
            }
            else if (options.GetFlag("scan"))
            {
                Console.WriteLine();

                Modules.ScanSuspiciousProcess(pid);

                Console.WriteLine();
            }
            else
                    {
                Console.WriteLine();
                Modules.GetProcessInformation(pid);
                Console.WriteLine();
            }
        }
    }
}
