using System;
using System.Text.RegularExpressions;
using WmiSpawn.Library;

namespace WmiSpawn.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            uint timeout;
            var regex = new Regex(@"^\d+$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (regex.IsMatch(options.GetValue("timeout")))
            {
                try
                {
                    timeout = Convert.ToUInt32(options.GetValue("timeout"));
                }
                catch
                {
                    Console.WriteLine();
                    Console.WriteLine("[!] Failed to parse timeout.");
                    Console.WriteLine();

                    return;
                }
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[!] Invalid timeout value is specifed.");
                Console.WriteLine();

                return;
            }

            if (!string.IsNullOrEmpty(options.GetValue("server")) &&
                (!options.GetFlag("kerberos") && !options.GetFlag("ntlm")))
            {
                Console.WriteLine();
                Console.WriteLine("[!] Should be -k or -n flag specified to execute process in remote machine.");
                Console.WriteLine();

                return;
            }

            if (options.GetFlag("kerberos") &&
                !string.IsNullOrEmpty(options.GetValue("command")))
            {
                Console.WriteLine();

                Modules.CreateWmiProcessKerberos(
                    options.GetValue("domain"),
                    options.GetValue("server"),
                    options.GetValue("username"),
                    options.GetValue("password"),
                    options.GetValue("command"),
                    options.GetFlag("full"),
                    options.GetFlag("visible"),
                    timeout);

                Console.WriteLine();
            }
            else if (options.GetFlag("ntlm") &&
                !string.IsNullOrEmpty(options.GetValue("command")))
            {
                Console.WriteLine();

                Modules.CreateWmiProcessNtlm(
                    options.GetValue("server"),
                    options.GetValue("username"),
                    options.GetValue("password"),
                    options.GetValue("command"),
                    options.GetFlag("full"),
                    options.GetFlag("visible"),
                    timeout);

                Console.WriteLine();
            }
            else if (!string.IsNullOrEmpty(options.GetValue("command")))
            {
                Console.WriteLine();

                Modules.CreateWmiProcessLocal(
                    options.GetValue("command"),
                    options.GetFlag("full"),
                    options.GetFlag("visible"),
                    timeout);

                Console.WriteLine();
            }
            else
            {
                options.GetHelp();
            }
        }
    }
}
