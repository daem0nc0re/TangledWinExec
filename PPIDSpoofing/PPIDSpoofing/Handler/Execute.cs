using System;
using System.Text.RegularExpressions;
using PPIDSpoofing.Library;

namespace PPIDSpoofing.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int ppid;
            var regex = new Regex(@"^\d+$");

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

            if (string.IsNullOrEmpty(options.GetValue("ppid")))
            {
                options.GetHelp();
                Console.WriteLine("\n[!] Missing --ppid option.\n");

                return;
            }
            else if (!regex.IsMatch(options.GetValue("ppid")))
            {
                options.GetHelp();
                Console.WriteLine("\n[!] Specified --ppid option value is invalid.\n");

                return;
            }
            else
            {
                try
                {
                    ppid = Convert.ToInt32(options.GetValue("ppid"), 10);
                }
                catch
                {
                    options.GetHelp();
                    Console.WriteLine("\n[!] Failed to parse the specified --ppid option value.\n");

                    return;
                }

                Console.WriteLine();
                Modules.CreateChildProcess(options.GetValue("command"), ppid);
                Console.WriteLine();
            }
        }
    }
}
