using System;
using TransactedHollowing.Handler;

namespace TransactedHollowing
{
    internal class TransactedHollowing
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("TransactedHollowing - PoC for Transacted Hollowing.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "f", "fake", null, "Specifies fake command line.");
                options.AddParameter(false, "r", "real", null, "Specifies image path you want to execute.");
                options.AddParameter(false, "p", "ppid", null, "Specifies PPID for PPID Spoofing.");
                options.AddFlag(false, "b", "blocking", "Flag to make process as blocking DLL process.");
                options.AddParameter(false, "w", "window", "Transacted Hollowing!!", "Specifies window title. Default value is \"Transacted Hollowing!!\".");
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
