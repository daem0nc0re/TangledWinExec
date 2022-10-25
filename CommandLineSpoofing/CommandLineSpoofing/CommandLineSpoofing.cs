using System;
using CommandLineSpoofing.Handler;

namespace CommandLineSpoofing
{
    internal class CommandLineSpoofing
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("CommandLineSpoofing - PoC for Command Line Spoofing.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "f", "fake", null, "Specifies fake command line.");
                options.AddParameter(false, "r", "real", null, "Specifies command line you want to execute.");
                options.AddParameter(false, "w", "window", "Command Line Spoofing!!", "Specifies window title. Default value is \"Command Line Spoofing!!\".");
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
