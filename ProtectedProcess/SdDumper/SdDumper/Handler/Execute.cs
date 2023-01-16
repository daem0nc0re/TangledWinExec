using System;
using System.Text.RegularExpressions;
using SdDumper.Library;

namespace SdDumper.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            int pid;
            string key;
            string subKey;
            var regexPositiveInteger = new Regex(@"^\d+$");
            bool asSystem = options.GetFlag("system");
            bool debug = options.GetFlag("debug");

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            if (!string.IsNullOrEmpty(options.GetValue("analyze")))
            {
                Modules.AnalyzeStringSecurityDescriptor(options.GetValue("analyze"));
            }
            else if (!string.IsNullOrEmpty(options.GetValue("filepath")))
            {
                if (string.IsNullOrEmpty(options.GetValue("edit")))
                    Modules.DumpFileSecurityDescriptor(options.GetValue("filepath"), asSystem, debug);
                else
                    Modules.SetFileSecurityDescriptor(options.GetValue("filepath"), options.GetValue("edit"), asSystem, debug);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("ntobj")))
            {
                if (options.GetFlag("list"))
                    Modules.EnumerateNtObjectDirectory(options.GetValue("ntobj"), asSystem, debug);
                else if (!string.IsNullOrEmpty(options.GetValue("edit")))
                    Modules.SetNtObjectSecurityDescriptor(options.GetValue("ntobj"), options.GetValue("edit"), asSystem, debug);
                else
                    Modules.DumpNtObjectSecurityDescriptor(options.GetValue("ntobj"), asSystem, debug);
            }
            else if (!string.IsNullOrEmpty(options.GetValue("pid")))
            {
                if (regexPositiveInteger.IsMatch(options.GetValue("pid")))
                {
                    try
                    {
                        pid = Convert.ToInt32(options.GetValue("pid"), 10);

                        if (options.GetFlag("token"))
                            Modules.DumpPrimaryTokenInformation(pid, asSystem, debug);
                        else
                            Modules.DumpProcessSecurityDescriptor(pid, asSystem, debug);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to parse PID.");
                    }
                }
                else
                {
                    Console.WriteLine("[!] PID should be specified as positive integer.");
                }
            }
            else if (!string.IsNullOrEmpty(options.GetValue("registry")))
            {
                key = Regex.Split(options.GetValue("registry"), @"(\\|/)")[0].TrimEnd(':');
                subKey = Regex.Replace(options.GetValue("registry"), @"^[^\\]+", "").TrimStart('\\');

                if (string.IsNullOrEmpty(options.GetValue("edit")))
                    Modules.DumpRegistrySecurityDescriptor(key, subKey, asSystem, debug);
                else
                    Modules.SetRegistrySecurityDescriptor(key, subKey, options.GetValue("edit"), asSystem, debug);
            }
            else
            {
                Console.WriteLine("[-] No options are specified. See help message with -h option.");
            }

            Console.WriteLine();
        }
    }
}
