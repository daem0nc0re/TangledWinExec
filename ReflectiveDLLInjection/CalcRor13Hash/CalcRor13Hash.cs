using System;
using System.Collections.Generic;
using CalcRor13Hash.Handler;

namespace CalcRor13Hash
{
    internal class CalcRor13Hash
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive = new List<string> { "ascii", "unicode" };

            try
            {
                options.SetTitle("CalcRor13Hash - ROR13 calculator for shellcoding.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(false, "a", "ascii", null, "Specifies ascii string to calculate hash.");
                options.AddParameter(false, "u", "unicode", null, "Specifies unicode string to calculate hash.");
                options.AddExclusive(exclusive);
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
