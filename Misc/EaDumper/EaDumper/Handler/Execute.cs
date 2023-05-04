using System;
using System.Text.RegularExpressions;
using EaDumper.Library;

namespace EaDumper.Handler
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

            Console.WriteLine();

            if (!string.IsNullOrEmpty(options.GetValue("file")))
            {
                Modules.DumpEaInformation(options.GetValue("file"));
            }
            else
            {
                Console.WriteLine("[-] No options are specified. See help message with -h option.");
            }

            Console.WriteLine();
        }
    }
}
