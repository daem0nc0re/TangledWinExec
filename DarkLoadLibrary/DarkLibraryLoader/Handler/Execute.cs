using System;
using System.IO;
using DarkLibraryLoader.Library;

namespace DarkLibraryLoader.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            byte[] dllData;
            string filePath = Path.GetFullPath(options.GetValue("dll"));

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            try
            {
                Console.WriteLine("[>] Reading the specified file.");
                Console.WriteLine("    [*] File Path : {0}", filePath);

                dllData = File.ReadAllBytes(filePath);

                Console.WriteLine("[+] The file is read successfully.");

                Modules.LoadLibrary(dllData, options.GetFlag("nolink"));
            }
            catch
            {
                Console.WriteLine("[!] Failed to read the specified file.");
            }

            Console.WriteLine();
        }
    }
}