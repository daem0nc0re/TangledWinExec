using System;
using System.Text.RegularExpressions;
using DLLInjector.Library;

namespace DLLInjector.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int pid;
            var regex = new Regex(@"^\d+$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (!regex.IsMatch(options.GetValue("pid")))
            {
                Console.WriteLine("\n[!] --pid option's value should be decimal format.\n");

                return;
            }

            try
            {
                pid = Convert.ToInt32(options.GetValue("pid"), 10);
            }
            catch
            {
                Console.WriteLine("\n[-] Failed to parse PID from command line.\n");

                return;
            }

            Console.WriteLine();

            Modules.InjectLibraryToRemoteProcess(pid, options.GetValue("dll"));

            Console.WriteLine();
        }
    }
}
