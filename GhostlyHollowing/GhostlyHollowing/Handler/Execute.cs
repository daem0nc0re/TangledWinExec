using System;
using System.IO;
using System.Text.RegularExpressions;
using GhostlyHollowing.Library;

namespace GhostlyHollowing.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int ppid;
            string imagePath;
            byte[] imageData;
            var regex = new Regex(@"^\d+$");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            if (string.IsNullOrEmpty(options.GetValue("fake")))
            {
                options.GetHelp();
                Console.WriteLine("\n[!] Missing --fake option.\n");

                return;
            }

            if (string.IsNullOrEmpty(options.GetValue("real")))
            {
                options.GetHelp();
                Console.WriteLine("\n[!] Missing --real option.\n");

                return;
            }

            if (string.IsNullOrEmpty(options.GetValue("ppid")))
            {
                ppid = 0;
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
            }

            try
            {
                imagePath = Helpers.ResolveImagePathName(options.GetValue("real"));

                if (string.IsNullOrEmpty(imagePath))
                {
                    Console.WriteLine("[-] Failed to resolve image path.");

                    return;
                }

                imageData = File.ReadAllBytes(imagePath);
            }
            catch
            {
                Console.WriteLine("[!] Failed to read the specified image.");

                return;
            }

            Console.WriteLine();
            Modules.CreateGhostlyHollowingProcess(
                imageData,
                options.GetValue("fake"),
                ppid,
                options.GetFlag("blocking"),
                options.GetValue("window"));
            Console.WriteLine();
        }
    }
}
