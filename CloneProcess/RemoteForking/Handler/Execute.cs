using System;
using System.Text.RegularExpressions;
using RemoteForking.Library;

namespace RemoteForking.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int pid;
            bool asSystem = options.GetFlag("system");
            bool debug = options.GetFlag("debug");
            var regexPositiveInteger = new Regex(@"^\d+$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            if (!string.IsNullOrEmpty(options.GetValue("pid")))
            {
                if (regexPositiveInteger.IsMatch(options.GetValue("pid")))
                {
                    try
                    {
                        pid = Convert.ToInt32(options.GetValue("pid"), 10);
                        Modules.ForkRemoteProcess(pid, asSystem, debug);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to parse PID.");
                    }
                }
                else
                {
                    Console.WriteLine("[!] PID should be specified as positive integer.");
                }
            }
            else
            {
                Console.WriteLine("[-] No options are specified. See help message with -h option.");
            }

            Console.WriteLine();
        }
    }
}
