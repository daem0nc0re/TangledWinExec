using System;
using GhostlyHollowing.Handler;

namespace GhostlyHollowing
{
    internal class GhostlyHollowing
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();

            try
            {
                options.SetTitle("GhostlyHollowing - PoC for Ghostly Hollowing.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "f", "fake", null, "Specifies fake image path.");
                options.AddParameter(false, "r", "real", null, "Specifies image path you want to execute.");
                options.AddParameter(false, "p", "ppid", null, "Specifies PPID for PPID Spoofing.");
                options.AddParameter(false, "w", "window", "Ghostly Hollowing!!", "Specifies window title. Default value is \"Ghostly Hollowing!!\".");
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
