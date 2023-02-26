using System;
using System.IO;
using PeRipper.Library;

namespace PeRipper.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            byte[] data;
            string filePath;
            uint nOffset;
            int nSize;

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            do
            {
                if (string.IsNullOrEmpty(options.GetValue("pe")))
                {
                    Console.WriteLine("[-] File to dump is required.");
                    break;
                }

                try
                {
                    filePath = Path.GetFullPath(options.GetValue("pe"));
                    data = File.ReadAllBytes(filePath);
                }
                catch
                {
                    Console.WriteLine("[-] Failed to read the specified file.");
                    break;
                }

                if (options.GetFlag("analyze"))
                {
                    Modules.GetModuleInformation(data);
                }
                else if (options.GetFlag("dump") || options.GetFlag("export"))
                {
                    try
                    {
                        if (!string.IsNullOrEmpty(options.GetValue("virtualaddress")))
                            nOffset = (uint)Convert.ToInt32(options.GetValue("virtualaddress"), 16);
                        else if (!string.IsNullOrEmpty(options.GetValue("rawoffset")))
                            nOffset = (uint)Convert.ToInt32(options.GetValue("rawoffset"), 16);
                        else
                            throw new InvalidDataException();
                    }
                    catch
                    {
                        Console.WriteLine("[-] Offset value must be specified in hex format.");
                        break;
                    }

                    try
                    {
                        if (!string.IsNullOrEmpty(options.GetValue("size")))
                            nSize = Convert.ToInt32(options.GetValue("size"), 16);
                        else
                            throw new InvalidDataException();
                    }
                    catch
                    {
                        Console.WriteLine("[-] Size value must be specified in hex format.");
                        break;
                    }

                    if (options.GetFlag("dump"))
                    {
                        if (!string.IsNullOrEmpty(options.GetValue("virtualaddress")))
                            Modules.DumpBytes(data, nOffset, nSize, true, options.GetValue("format"));
                        else
                            Modules.DumpBytes(data, nOffset, nSize, false, options.GetValue("format"));
                    }
                    else if (options.GetFlag("export"))
                    {
                        if (!string.IsNullOrEmpty(options.GetValue("virtualaddress")))
                            Modules.ExportDataBytes(data, nOffset, nSize, true);
                        else
                            Modules.ExportDataBytes(data, nOffset, nSize, false);
                    }
                }
                else
                {
                    Console.WriteLine("[-] Must be specified -a, -d or -e flag.");
                }
            } while (false);

            Console.WriteLine();
        }
    }
}