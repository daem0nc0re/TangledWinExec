using System;
using RemoteForking.Handler;

namespace RemoteForking
{
    internal class RemoteForking
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("RemoteForking - PoC to test process snapshotting.");
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
