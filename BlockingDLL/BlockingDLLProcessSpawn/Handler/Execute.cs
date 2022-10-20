using System;
using BlockingDLLProcessSpawn.Library;

namespace BlockingDLLProcessSpawn.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (string.IsNullOrEmpty(options.GetValue("command")))
            {
                options.GetHelp();
                Console.WriteLine("\n[!] Missing --command option.\n");

                return;
            }

            Console.WriteLine();

            Modules.CreateBlockingDllProcess(options.GetValue("command"));

            Console.WriteLine();
        }
    }
}
