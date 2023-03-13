using System;
using HashResolveTester.Handler;

namespace HashResolveTester
{
    internal class HashResolveTester
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("HashResolveTester - Test GetProcAddress with ROR13 hash.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "l", "library", null, "Specifies DLL name.");
                options.AddParameter(true, "H", "hash", null, "Specifies ROR13 hash for the target function. Must be specified in hex format.");
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
