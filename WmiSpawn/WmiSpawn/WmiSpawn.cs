using System;
using System.Collections.Generic;
using WmiSpawn.Handler;

namespace WmiSpawn
{
    internal class WmiSpawn
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("WmiSpawn - PoC for WMI process execution.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "d", "domain", null, "Specifies domain name. Used with -k flag.");
                options.AddParameter(false, "u", "username", null, "Specifies username. Used with -k or -n flag");
                options.AddParameter(false, "p", "password", null, "Specifies password. Used with -k or -n flag");
                options.AddParameter(false, "s", "server", null, "Specifies remote server. Used with -k or -n flag");
                options.AddParameter(false, "c", "command", null, "Specifies command to execute.");
                options.AddParameter(false, "t", "timeout", "3", "Specifies timeout in seconds. Defualt is 3 seconds.");
                options.AddFlag(false, "k", "kerberos", "Flag for Kerberos authentication.");
                options.AddFlag(false, "n", "ntlm", "Flag for NTLM authentication.");
                options.AddFlag(false, "v", "visible", "Flag to show GUI. Effective in local process execution.");
                options.AddFlag(false, "f", "full", "Flag to enable all available privileges.");
                options.AddExclusive(new List<string> { "kerberos", "ntlm" });
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
