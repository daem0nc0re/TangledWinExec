using System;
using System.Text.RegularExpressions;
using CommandLineSpoofing.Library;

namespace CommandLineSpoofing.Handler
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

            Console.WriteLine();

            Modules.CreateCommandLineSpoofedProcess(
                options.GetValue("fake"),
                options.GetValue("real"),
                options.GetValue("window"));

            Console.WriteLine();
        }
    }
}