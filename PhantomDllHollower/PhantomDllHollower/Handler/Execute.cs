using System;
using System.IO;
using PhantomDllHollower.Library;

namespace PhantomDllHollower.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            byte[] payload;
            string payloadPath = options.GetValue("payload");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            if (!string.IsNullOrEmpty(payloadPath))
            {
                try
                {
                    payloadPath = Path.GetFullPath(payloadPath);

                    Console.WriteLine("[>] Trying to read payload from {0}.", payloadPath);
                    payload = File.ReadAllBytes(payloadPath);
                    Console.WriteLine("[+] Payload is read successfully ({0} bytes).", payload.Length);

                    Modules.PhantomShellcodeLoad(payload, options.GetFlag("txf"));
                }
                catch
                {
                    Console.WriteLine("[-] Failed to read payload.");
                }
            }
            else
            {
                Console.WriteLine("[-] No options are specified. Check -h option.");
            }

            Console.WriteLine();
        }
    }
}