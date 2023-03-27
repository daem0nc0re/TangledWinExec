using System;
using ProcAccessCheck.Handler;

namespace ProcAccessCheck
{
    internal class ProcAccessCheck
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("ProcAccessCheck - Tool to check maximum access rights for process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "p", "pid", null, "Specifies process ID.");
                options.AddFlag(false, "s", "system", "Flag to act as SYSTEM.");
                options.AddFlag(false, "d", "debug", "Flag to enable SeDebugPrivilege.");
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
