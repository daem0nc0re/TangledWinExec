using System;
using ReflectiveInjector.Handler;

namespace ReflectiveInjector
{
    internal class ReflectiveInjector
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("ReflectiveInjector - PoC for Reflective DLL Injection.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "d", "dll", null, "Specifies reflective DLL to inject.");
                options.AddParameter(true, "e", "entry", null, "Specifies loader function in your reflective DLL.");
                options.AddParameter(false, "p", "pid", null, "Specifies PID to inject. Default is this PoC's process");
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
