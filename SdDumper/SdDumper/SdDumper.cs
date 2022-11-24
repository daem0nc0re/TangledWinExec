using System;
using System.Collections.Generic;
using SdDumper.Handler;

namespace SdDumper
{
    internal class SdDumper
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive = new List<string> { "analyze", "filepath", "ntdir", "pid", "registry" };

            try
            {
                options.SetTitle("SdDumper - SecurityDescriptor utilitiy.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "a", "analyze", null, "Specifies SDDL to analyze.");
                options.AddParameter(false, "f", "filepath", null, "Specifies file or directory path.");
                options.AddParameter(false, "n", "ntdir", null, "Specifies NT directory path.");
                options.AddParameter(false, "p", "pid", null, "Specifies process ID.");
                options.AddParameter(false, "r", "registry", null, "Specifies registry key.");
                options.AddFlag(false, "t", "token", "Flag to get primary token's information. Use with -p flag.");
                options.AddFlag(false, "S", "system", "Flag to act as SYSTEM.");
                options.AddFlag(false, "d", "debug", "Flag to enable SeDebugPrivilege.");
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
