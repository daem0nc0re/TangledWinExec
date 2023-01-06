using System;
using PhantomDllHollower.Handler;

namespace PhantomDllHollower
{
    internal class PhantomDllHollower
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("PhantomDllHollower - Tool for testing Phantom DLL Hollowing.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "p", "payload", null, "Specifies shellcode to execute.");
                options.AddFlag(false, "t", "txf", "Flag to use TxF. This option requires administrative privilege.");
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
