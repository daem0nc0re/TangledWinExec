using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ShellcodeReflectiveInjector.Interop;

namespace ShellcodeReflectiveInjector.Library
{
    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static string DumpDataAsClanguageFormat(byte[] data)
        {
            var builder = new StringBuilder();

            if (data.Length > 0)
            {
                builder.Append(@"unsigned char data[] = {");

                for (var offset = 0; offset < data.Length; offset++)
                {
                    if ((offset % 12) == 0)
                    {
                        if (offset != 0)
                            builder.Append(",");

                        builder.Append("\n    ");
                    }
                    else
                        builder.Append(", ");

                    builder.AppendFormat("0x{0}", data[offset].ToString("X2"));
                }

                builder.Append("\n};\n");
            }

            return builder.ToString();
        }


        public static string DumpDataAsCsharpFormat(byte[] data)
        {
            var builder = new StringBuilder();

            if (data.Length > 0)
            {
                builder.Append(@"var data = new byte[] {");

                for (var offset = 0; offset < data.Length; offset++)
                {
                    if ((offset % 12) == 0)
                    {
                        if (offset != 0)
                            builder.Append(",");

                        builder.Append("\n    ");
                    }
                    else
                        builder.Append(", ");

                    builder.AppendFormat("0x{0}", data[offset].ToString("X2"));
                }

                builder.Append("\n};\n");
            }

            return builder.ToString();
        }


        public static string DumpDataAsPythonFormat(byte[] data)
        {
            var builder = new StringBuilder();

            if (data.Length > 0)
            {
                builder.Append(@"data = bytearray(");

                for (var offset = 0; offset < data.Length; offset++)
                {
                    if ((offset % 12) == 0)
                    {
                        if (offset != 0)
                            builder.Append("\"");

                        builder.Append("\n    b\"");
                    }

                    builder.AppendFormat("\\x{0}", data[offset].ToString("X2"));
                }

                builder.Append("\"\n)\n");
            }

            return builder.ToString();
        }


        public static string GetOutputFilePath(string outputPath)
        {
            string directory;
            string fileName;
            string extension;
            int count = 0;
            outputPath = Path.GetFullPath(outputPath);
            directory = Path.GetDirectoryName(outputPath).TrimEnd('\\');
            extension = Path.GetExtension(outputPath);
            fileName = Regex.Replace(Path.GetFileName(outputPath), @"\.\S+$", string.Empty);

            while (File.Exists(outputPath) || Directory.Exists(outputPath))
            {
                outputPath = string.Format(@"{0}\{1}_{2}{3}", directory, fileName, count, extension);
                count++;
            }

            return outputPath;
        }


        public static IMAGE_FILE_MACHINE GetPeArchitecture(byte[] moduleBytes)
        {
            IntPtr pModuleBase;
            IMAGE_FILE_MACHINE machine = 0;

            if (moduleBytes.Length > 0x400)
            {
                pModuleBase = Marshal.AllocHGlobal(0x400);
                Marshal.Copy(moduleBytes, 0, pModuleBase, 0x400);

                machine = GetPeArchitecture(pModuleBase);

                Marshal.FreeHGlobal(pModuleBase);
            }

            return machine;
        }


        public static IMAGE_FILE_MACHINE GetPeArchitecture(IntPtr pModuleBase)
        {
            int e_lfanew;
            IMAGE_FILE_MACHINE machine = 0;

            do
            {
                if (Marshal.ReadInt16(pModuleBase) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);

                // Avoid memory access violation
                if (e_lfanew > 0x800)
                    break;

                if (Marshal.ReadInt32(pModuleBase, e_lfanew) != 0x00004550)
                    break;

                machine = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pModuleBase, e_lfanew + 4);
            } while (false);

            return machine;
        }


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            var pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (CompareIgnoreCase(Path.GetFileName(module.FileName), "ntdll.dll"))
                    {
                        pNtdll = module.BaseAddress;
                        dwFlags |= FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE;
                        break;
                    }
                }
            }

            nReturnedLength = NativeMethods.FormatMessage(
                dwFlags,
                pNtdll,
                code,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", code.ToString("X8"), message.ToString().Trim());
        }


        public static bool IsValidPe(byte[] moduleBytes)
        {
            IntPtr pModule;
            var status = false;

            if (moduleBytes.Length > 0x400)
            {
                pModule = Marshal.AllocHGlobal(0x400);
                Marshal.Copy(moduleBytes, 0, pModule, 0x400);

                status = IsValidPe(pModule);

                Marshal.FreeHGlobal(pModule);
            }

            return status;
        }


        public static bool IsValidPe(IntPtr pModule)
        {
            int e_lfanew;
            bool status = false;

            do
            {
                if (Marshal.ReadInt16(pModule) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pModule, 0x3C);

                // Avoid memory access violation
                if (e_lfanew > 0x400)
                    break;

                if (Marshal.ReadInt32(pModule, e_lfanew) != 0x00004550)
                    break;

                status = true;
            } while (false);

            return status;
        }
    }
}
