using System;
using System.IO;
using System.Text.RegularExpressions;
using ShellcodeReflectiveInjector.Library;

namespace ShellcodeReflectiveInjector.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int pid;
            string modulePath;
            byte[] moduleBytes;
            var regex = new Regex(@"^[0-9]+$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (string.IsNullOrEmpty(options.GetValue("pid")))
            {
                pid = 0;
            }
            else if (!regex.IsMatch(options.GetValue("pid")))
            {
                options.GetHelp();
                Console.WriteLine("\n[!] Specified --pid option value is invalid.\n");
                return;
            }
            else
            {
                try
                {
                    pid = Convert.ToInt32(options.GetValue("pid"), 10);
                }
                catch
                {
                    options.GetHelp();
                    Console.WriteLine("\n[!] Failed to parse the specified --pid option value.\n");

                    return;
                }
            }

            try
            {
                modulePath = Path.GetFullPath(options.GetValue("module"));

                Console.WriteLine();
                Console.WriteLine("[>] Reading module file.");
                Console.WriteLine("    [*] Path : {0}", modulePath);

                moduleBytes = File.ReadAllBytes(modulePath);

                Console.WriteLine("[+] {0} bytes module data is read successfully", moduleBytes.Length);

                if (options.GetFlag("inject"))
                {
                    if (pid == 0)
                        Modules.LoadShellcode(moduleBytes);
                    else
                        Modules.InjectShellcode(pid, moduleBytes);
                }
                else if (options.GetFlag("convert"))
                {
                    Modules.GetShellcode(moduleBytes, options.GetValue("format"));
                }
                else
                {
                    Console.WriteLine("[!] -i or -c flag must be specified.");
                }

                Console.WriteLine();
            }
            catch
            {
                options.GetHelp();
                Console.WriteLine("\n[!] Failed to read the specified DLL.\n");
            }
        }
    }
}
