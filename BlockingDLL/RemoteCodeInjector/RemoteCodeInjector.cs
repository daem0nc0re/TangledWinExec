using System;
using RemoteCodeInjector.Handler;

namespace RemoteCodeInjector
{
    internal class RemoteCodeInjector
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("DLLInjector - Tool for testing DLL Injection.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "p", "pid", null, "Specifies pid of the target process.");
                options.AddParameter(true, "i", "inject", null, "Specifies shellcode file path to inject.");
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
