using System;
using SnapshotDump.Handler;

namespace SnapshotDump
{
    internal class SnapshotDump
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("SnapshotDump - Tool to get process dump with snapshot techniques.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "o", "output", null, "Specifies output file path. Default will be based on process name and PID.");
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