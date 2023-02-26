using System;
using CalcRor13Hash.Library;

namespace CalcRor13Hash.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            uint hash;
            string input;

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            if (!string.IsNullOrEmpty(options.GetValue("ascii")))
            {
                input = options.GetValue("ascii");
                hash = Helpers.GetHashFromAsciiString(input);

                Console.WriteLine("[*] Input (ASCII) : {0}", input);
                Console.WriteLine("[*] ROR13 Hash    : 0x{0}", hash.ToString("X8"));
            }
            else if (!string.IsNullOrEmpty(options.GetValue("unicode")))
            {
                input = options.GetValue("unicode");
                hash = Helpers.GetHashFromUnicodeString(input);

                Console.WriteLine("[*] Input (Unicode) : {0}", input);
                Console.WriteLine("[*] ROR13 Hash      : 0x{0}", hash.ToString("X8"));
            }
            else
            {
                Console.WriteLine("[!] -a or -u option is required.");
            }

            Console.WriteLine();
        }
    }
}