using System;
using BlockingDLLProcessSpawn.Handler;

namespace BlockingDLLProcessSpawn
{
    internal class BlockingDLLProcessSpawn
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("BlockingDLLProcessSpawn - Tool for spawning blocking DLL process.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "c", "command", null, "Specifies command for spawning blocing DLL process.");
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
