using System;
using ProcessHerpaderping.Handler;

namespace ProcessHerpaderping
{
    internal class ProcessHerpaderping
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("ProcessHerpaderping - PoC for Process Herpaderping.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "f", "fake", null, "Specifies fake command line.");
                options.AddParameter(false, "r", "real", null, "Specifies image path you want to execute.");
                options.AddParameter(false, "p", "ppid", null, "Specifies PPID for PPID Spoofing.");
                options.AddParameter(false, "w", "window", "Process Herpaderping!!", "Specifies window title. Default value is \"Process Herpaderping!!\".");
                options.Parse(args);

                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);

                return;
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);

                return;
            }
        }
    }
}
