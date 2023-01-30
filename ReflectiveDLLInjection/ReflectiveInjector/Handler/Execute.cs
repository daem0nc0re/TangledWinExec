using System;
using System.IO;
using System.Text.RegularExpressions;
using ReflectiveInjector.Library;

namespace ReflectiveInjector.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int pid;
            string imagePath;
            byte[] imageData;
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
                imagePath = Path.GetFullPath(options.GetValue("dll"));

                Console.WriteLine();
                Console.WriteLine("[>] Reading reflective DLL.");
                Console.WriteLine("    [*] Path : {0}", imagePath);
                imageData = File.ReadAllBytes(imagePath);

                if (pid == 0)
                    Modules.LoadReflectiveDll(imageData, options.GetValue("entry"));
                else
                    Modules.ReflectiveDllInjection(pid, imageData, options.GetValue("entry"));

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
