using System;
using System.Text.RegularExpressions;
using ProcMemScan.Library;

namespace ProcMemScan.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            do
            {
                int pid;
                IntPtr pBaseAddress;
                uint nRange;
                var decimalPattern = new Regex(@"^[0-9]+$");
                var hexPattern = new Regex(@"^(0x)?[0-9A-Fa-f]{1,16}$");
                bool bSystem = options.GetFlag("system");

                if (string.IsNullOrEmpty(options.GetValue("pid")))
                {
                    pid = 0;
                }
                else
                {
                    if (!decimalPattern.IsMatch(options.GetValue("pid")))
                    {
                        Console.WriteLine("[-] PID should be specfied as positive integer in decimal format.");
                        break;
                    }

                    try
                    {
                        pid = Convert.ToInt32(options.GetValue("pid"), 10);
                    }
                    catch
                    {
                        Console.WriteLine("[-] Failed to parse PID.");
                        break;
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
                        Console.WriteLine("[-] Base address should be specfied in hex format.");
                        break;
                    }

                    try
                    {
                        if (Environment.Is64BitProcess)
                            pBaseAddress = new IntPtr(Convert.ToInt64(options.GetValue("base"), 16));
                        else
                            pBaseAddress = new IntPtr(Convert.ToInt32(options.GetValue("base"), 16));
                    }
                    catch
                    {
                        Console.WriteLine("[-] Failed to parse base address.");
                        break;
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
                        Console.WriteLine("[-] Memory range should be specfied in hex format.");
                        break;
                    }

                    try
                    {
                        nRange = (uint)Convert.ToInt32(options.GetValue("range"), 16);
                    }
                    catch
                    {
                        Console.WriteLine("[-] Failed to parse memory range.");
                        break;
                    }
                }

                if (options.GetFlag("list") && (pid != 0))
                    Modules.GetProcessMemoryInformation(pid, bSystem);
                else if (options.GetFlag("dump") && (pid != 0))
                    Modules.DumpMemory(pid, pBaseAddress, nRange, bSystem);
                else if (options.GetFlag("exports") && (pid != 0))
                    Modules.DumpExportItems(pid, pBaseAddress, bSystem);
                else if (options.GetFlag("extract") && options.GetFlag("image") && (pid != 0))
                    Modules.ExtractPeImageFile(pid, pBaseAddress, bSystem);
                else if (options.GetFlag("extract") && (pid != 0))
                    Modules.ExtractMemory(pid, pBaseAddress, nRange, bSystem);
                else if (options.GetFlag("scan") && (pid != 0))
                    Modules.ScanProcess(pid, bSystem);
                else if (options.GetFlag("scan"))
                    Modules.ScanAllProcesses(bSystem);
                else if (pid != 0)
                    Modules.GetProcessInformation(pid, bSystem);
            } while (false);

            Console.WriteLine();
        }
    }
}
