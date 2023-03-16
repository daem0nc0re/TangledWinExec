using System;
using System.Collections.Generic;
using ShellcodeReflectiveInjector.Handler;

namespace ShellcodeReflectiveInjector
{
    internal class ShellcodeReflectiveInjector
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive = new List<string> { "convert", "inject" };

            try
            {
                options.SetTitle("ShellcodeReflectiveInjector - Tool to test sRDI (Shellcode Reflective DLL Injection).");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "c", "convert", "Flag to convert PE to shellcode.");
                options.AddFlag(false, "i", "inject", "Flag to inject or load shellcode.");
                options.AddParameter(false, "f", "format", null, "Specifies output format of dump data. \"cs\", \"c\" and \"py\" are allowed.");
                options.AddParameter(true, "m", "module", null, "Specifies a PE file to generate shellcode.");
                options.AddParameter(false, "p", "pid", null, "Specifies PID to inject shellcode.");
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
