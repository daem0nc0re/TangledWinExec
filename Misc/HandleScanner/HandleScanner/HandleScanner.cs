using System;
using System.Security.Principal;
using HandleScanner.Interop;
using HandleScanner.Handler;

namespace HandleScanner
{
    internal class HandleScanner
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("HandleScanner - Tool to scan handles from process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "f", "filter", null, "Specifies string to filter handle type.");
                options.AddParameter(false, "p", "pid", null, "Specifies PID to scan. Default is all processes.");
                options.AddFlag(false, "d", "debug", "Flag to enable SeDebugPrivilege.");
                options.AddFlag(true, "s", "scan", "Flag to scan handle.");
                options.AddFlag(false, "S", "system", "Flag to act as SYSTEM.");
                options.AddFlag(false, "v", "verbose", "Flag to output verbose information.");
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
