using System;
using HashResolveTester.Library;

namespace HashResolveTester.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            uint hash;

            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            do
            {
                if (string.IsNullOrEmpty(options.GetValue("hash")))
                {
                    Console.WriteLine("[-] Target hash is not specified.");
                    break;
                }

                try
                {
                    hash = (uint)Convert.ToInt32(options.GetValue("hash"), 16);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to convert hash value.");
                    break;
                }

                Modules.ResolveFunctionAddress(options.GetValue("library"), hash);
            } while (false);

            Console.WriteLine();
        }
    }
}
