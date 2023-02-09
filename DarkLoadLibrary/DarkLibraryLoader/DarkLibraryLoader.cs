using System;
using DarkLibraryLoader.Handler;

namespace DarkLibraryLoader
{
    internal class DarkLibraryLoader
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("\n[-] Currently, 32bit mode is not supported. Sorry.\n");
                return;
            }

            try
            {
                options.SetTitle("DarkLibraryLoad - PoC for testing Dark Load Library technique.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "d", "dll", null, "Specifies DLL to load.");
                options.AddFlag(false, "n", "nolink", "Flag to not link DLL.");
                options.Parse(args);

                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);
            }
        }
    }
}
