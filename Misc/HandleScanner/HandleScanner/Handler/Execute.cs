using System;
using HandleScanner.Library;

namespace HandleScanner.Handler
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

            int pid;

            Console.WriteLine();

            try
            {
                pid = Convert.ToInt32(options.GetValue("pid"));
            }
            catch
            {
                pid = 0;
            }

            if (options.GetFlag("scan"))
            {
                Modules.GetProcessHandleInformation(
                    pid,
                    options.GetValue("type"),
                    options.GetValue("name"),
                    options.GetFlag("verbose"),
                    options.GetFlag("debug"),
                    options.GetFlag("system"));
            }
            else
            {
                Console.WriteLine("[-] No options are specified. Check -h option.");
            }

            Console.WriteLine();
        }
    }
}