using System;
using HandleScanner.Handler;

namespace HandleScanner
{
    internal class HandleScanner
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                Console.WriteLine("\n[!] For 64 bit OS, must be built as 64 bit process binary.\n");
                return;
            }

            try
            {
                options.SetTitle("HandleScanner - Tool to scan handles from process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "n", "name", null, "Specifies string to filter handle name.");
                options.AddParameter(false, "p", "pid", null, "Specifies PID to scan. Default is all processes.");
                options.AddParameter(false, "t", "type", null, "Specifies string to filter handle type.");
                options.AddFlag(false, "d", "debug", "Flag to enable SeDebugPrivilege.");
                options.AddFlag(true, "s", "scan", "Flag to scan handle.");
                options.AddFlag(false, "S", "system", "Flag to act as SYSTEM.");
                options.AddFlag(false, "v", "verbose", "Flag to output verbose information.");
                options.Parse(args);

                Execute.Run(options);

                // Some Named Pipe File object name lookup cause program freeze.
                // I don't know why it happens, but this issue should be fixed later.
                Environment.Exit(0);
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
