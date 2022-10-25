using System;
using PPIDSpoofing.Handler;

namespace PPIDSpoofing
{
    internal class PPIDSpoofing
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("PPIDSpoofing - PoC for PPID Spoofing.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "p", "ppid", null, "Specifies PPID for PPID Spoofing process.");
                options.AddParameter(false, "c", "command", null, "Specifies command for PPID Spoofing.");
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
