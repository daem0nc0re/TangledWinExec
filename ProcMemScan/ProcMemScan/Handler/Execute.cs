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
                var hexPattern = new Regex(@"^(0x)[0-9A-Fa-f]{1,16}$");
                bool bSystem = options.GetFlag("system");

                if (string.IsNullOrEmpty(options.GetValue("pid")))
                {
                    pid = 0;
                }
                else
                {
                    try
                    {
                        if (hexPattern.IsMatch(options.GetValue("pid")))
                            pid = Convert.ToInt32(options.GetValue("pid"), 16);
                        else
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
                    try
                    {
                        if (Environment.Is64BitProcess)
                        {
                            if (hexPattern.IsMatch(options.GetValue("base")))
                                pBaseAddress = new IntPtr(Convert.ToInt64(options.GetValue("base"), 16));
                            else
                                pBaseAddress = new IntPtr(Convert.ToInt64(options.GetValue("base"), 10));
                        }
                        else
                        {
                            if (hexPattern.IsMatch(options.GetValue("base")))
                                pBaseAddress = new IntPtr(Convert.ToInt32(options.GetValue("base"), 16));
                            else
                                pBaseAddress = new IntPtr(Convert.ToInt32(options.GetValue("base"), 10));
                        }
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
                    try
                    {
                        if (hexPattern.IsMatch(options.GetValue("range")))
                            nRange = (uint)Convert.ToInt32(options.GetValue("range"), 16);
                        else
                            nRange = (uint)Convert.ToInt32(options.GetValue("range"), 10);
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
                else
                    Console.WriteLine("[-] No options. Try -h flag.");
            } while (false);

            Console.WriteLine();
        }
    }
}
