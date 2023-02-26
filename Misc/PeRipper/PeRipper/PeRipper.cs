using System;
using System.Collections.Generic;
using PeRipper.Handler;

namespace PeRipper
{
    internal class PeRipper
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive_1 = new List<string> { "analyze", "dump", "export" };
            var exclusive_2 = new List<string> { "rawoffset", "virtualaddress" };

            try
            {
                options.SetTitle("PeRipper - Tool to get byte data from PE file.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "a", "analyze", "Flag to get PE file's information.");
                options.AddFlag(false, "d", "dump", "Flag to dump data bytes.");
                options.AddFlag(false, "e", "export", "Flag to export raw data bytes to a file.");
                options.AddParameter(false, "f", "format", null, "Specifies output format of dump data. \"cs\", \"c\" and \"py\" are allowed.");
                options.AddParameter(false, "s", "size", null, "Specifies data size to rip.");
                options.AddParameter(true, "p", "pe", null, "Specifies a PE file to load.");
                options.AddParameter(false, "r", "rawoffset", null, "Specifies base address to rip with PointerToRawData.");
                options.AddParameter(false, "v", "virtualaddress", null, "Specifies base address to rip with VirtualAddress.");
                options.AddExclusive(exclusive_1);
                options.AddExclusive(exclusive_2);
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