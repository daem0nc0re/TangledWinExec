using System;
using System.Collections.Generic;
using ProcMemScan.Handler;

namespace ProcMemScan
{
    internal class ProcMemScan
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive = new List<string> { "list", "dump", "exports", "extract", "scan" };

            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                Console.WriteLine("\n[!] Must be built as 64bit binary in 64bit OS\n");
                return;
            }

            try
            {
                options.SetTitle("ProcMemScan - Process Diagnostic Tool.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "l", "list", "Flag to list memory layout.");
                options.AddFlag(false, "d", "dump", "Flag to get hexdump or verbose information of a specific memory region.");
                options.AddFlag(false, "e", "exports", "Flag to dump export items.");
                options.AddFlag(false, "x", "extract", "Flag to extract memory as binary files.");
                options.AddFlag(false, "i", "image", "Flag to extract PE file from memory. Use with -x flag.");
                options.AddFlag(false, "s", "scan", "Flag to find PE injected process.");
                options.AddFlag(false, "S", "system", "Flag to act as SYSTEM.");
                options.AddParameter(false, "p", "pid", null, "Specifies target process's PID in decimal format.");
                options.AddParameter(false, "b", "base", null, "Specifies memory address in hex format. Use with -d or -x flag.");
                options.AddParameter(false, "r", "range", null, "Specifies memory range in hex format. Use with -d or -x flag.");
                options.AddExclusive(exclusive);
                options.Parse(args);

                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);
            }
        }
    }
}
