using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using PeRipper.Interop;

namespace PeRipper.Library
{
    internal class Modules
    {
        public static bool DumpBytes(
            byte[] moduleData,
            uint nOffset,
            int nSize,
            bool isVirtualAddress,
            string format)
        {
            int nHeaderSize;
            IntPtr pDataBuffer;
            IntPtr pBufferOffset;
            uint nVirtualAddress;
            uint nPointerToRawData;
            IMAGE_SECTION_HEADER sectionHeader;
            string output = Helpers.GetOutputFilePath(@"bytes_from_module.bin");
            IntPtr pModuleBuffer = Marshal.AllocHGlobal(moduleData.Length);
            var data = new byte[nSize];
            var status = false;
            Marshal.Copy(moduleData, 0, pModuleBuffer, moduleData.Length);

            Console.WriteLine("[*] Raw Data Size : {0} bytes", moduleData.Length);

            do
            {
                if (!Helpers.IsValidPe(pModuleBuffer))
                {
                    Console.WriteLine("[-] Not valid PE file data.");
                    break;
                }

                nHeaderSize = Helpers.GetHeaderSize(pModuleBuffer);
                Console.WriteLine("[*] Architecture  : {0}", Helpers.GetPeArchitecture(pModuleBuffer).ToString());
                Console.WriteLine("[*] Header Size   : 0x{0} bytes", nHeaderSize.ToString("X"));

                status = Helpers.GetSectionHeaders(
                    pModuleBuffer,
                    out List<IMAGE_SECTION_HEADER> sections);

                if (!status)
                {
                    Console.WriteLine("[-] No sections are found.");
                    break;
                }

                if (isVirtualAddress)
                {
                    nVirtualAddress = nOffset;
                    nPointerToRawData = Helpers.ConvertRvaToRawDataOffset(pModuleBuffer, nOffset);
                }
                else
                {
                    nVirtualAddress = Helpers.ConvertRawDataOffsetToRva(pModuleBuffer, nOffset);
                    nPointerToRawData = nOffset;
                }

                if ((nVirtualAddress > Int32.MaxValue) || (nPointerToRawData > Int32.MaxValue))
                {
                    Console.WriteLine("[-] The specified address is out of raw data range.");
                    break;
                }

                if (nOffset < nHeaderSize)
                {
                    Console.WriteLine("[*] The specified base address is in header region.");
                }
                else
                {
                    if (isVirtualAddress)
                    {
                        status = Helpers.GetSectionHeaderForVirtualAddress(pModuleBuffer, nVirtualAddress, out sectionHeader);

                        if (status)
                            Console.WriteLine("[*] VirtualAddress (0x{0}) is in {1} section.", nVirtualAddress.ToString("X8"), sectionHeader.Name.ToString());
                    }
                    else
                    {
                        status = Helpers.GetSectionHeaderForRawOffset(pModuleBuffer, nPointerToRawData, out sectionHeader);

                        if (status)
                            Console.WriteLine("[*] PointerToRawData (0x{0}) is in {1} section.", nPointerToRawData.ToString("X8"), sectionHeader.Name.ToString());
                    }

                    if (!status)
                    {
                        Console.WriteLine("[-] The specified address is not in section.");
                        break;
                    }
                }

                if ((nPointerToRawData + nSize) > moduleData.Length)
                {
                    Console.WriteLine("[-] Data size is out of data boundary.");
                    break;
                }

                if (Environment.Is64BitProcess)
                {
                    pDataBuffer = new IntPtr(pModuleBuffer.ToInt64() + nPointerToRawData);

                    if (isVirtualAddress)
                        pBufferOffset = new IntPtr(nVirtualAddress);
                    else
                        pBufferOffset = new IntPtr(nPointerToRawData);
                }
                else
                {
                    pDataBuffer = new IntPtr(pModuleBuffer.ToInt32() + (int)nPointerToRawData);

                    if (isVirtualAddress)
                        pBufferOffset = new IntPtr((int)nVirtualAddress);
                    else
                        pBufferOffset = new IntPtr((int)nPointerToRawData);
                }

                Marshal.Copy(pDataBuffer, data, 0, nSize);

                if (Helpers.CompareIgnoreCase(format, "cs"))
                {
                    Console.WriteLine("[*] Dump 0x{0} bytes in CSharp format:\n", nSize.ToString("X"));
                    Console.WriteLine(Helpers.DumpDataAsCsharpFormat(data));
                }
                else if (Helpers.CompareIgnoreCase(format, "c"))
                {
                    Console.WriteLine("[*] Dump 0x{0} bytes in C Language format:\n", nSize.ToString("X"));
                    Console.WriteLine(Helpers.DumpDataAsClanguageFormat(data));
                }
                else if (Helpers.CompareIgnoreCase(format, "py"))
                {
                    Console.WriteLine("[*] Dump 0x{0} bytes in Python format:\n", nSize.ToString("X"));
                    Console.WriteLine(Helpers.DumpDataAsPythonFormat(data));
                }
                else
                {
                    Console.WriteLine("[*] Dump 0x{0} bytes in Hex Dump format:\n", nSize.ToString("X"));
                    HexDump.Dump(data, pBufferOffset, (uint)nSize, 1);
                    Console.WriteLine();
                }
            } while (false);

            Marshal.FreeHGlobal(pModuleBuffer);

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool ExportDataBytes(
            byte[] moduleData,
            uint nOffset,
            int nSize,
            bool isVirtualAddress)
        {
            int nHeaderSize;
            IntPtr pDataBuffer;
            uint nVirtualAddress;
            uint nPointerToRawData;
            IMAGE_SECTION_HEADER sectionHeader;
            string output = Helpers.GetOutputFilePath(@"bytes_from_module.bin");
            IntPtr pModuleBuffer = Marshal.AllocHGlobal(moduleData.Length);
            var data = new byte[nSize];
            var status = false;
            Marshal.Copy(moduleData, 0, pModuleBuffer, moduleData.Length);

            Console.WriteLine("[*] Raw Data Size : {0} bytes", moduleData.Length);

            do
            {
                if (!Helpers.IsValidPe(pModuleBuffer))
                {
                    Console.WriteLine("[-] Not valid PE file data.");
                    break;
                }

                nHeaderSize = Helpers.GetHeaderSize(pModuleBuffer);
                Console.WriteLine("[*] Architecture  : {0}", Helpers.GetPeArchitecture(pModuleBuffer).ToString());
                Console.WriteLine("[*] Header Size   : 0x{0} bytes", nHeaderSize.ToString("X"));

                status = Helpers.GetSectionHeaders(
                    pModuleBuffer,
                    out List<IMAGE_SECTION_HEADER> sections);

                if (!status)
                {
                    Console.WriteLine("[-] No sections are found.");
                    break;
                }

                if (isVirtualAddress)
                {
                    nVirtualAddress = nOffset;
                    nPointerToRawData = Helpers.ConvertRvaToRawDataOffset(pModuleBuffer, nOffset);
                }
                else
                {
                    nVirtualAddress = Helpers.ConvertRawDataOffsetToRva(pModuleBuffer, nOffset);
                    nPointerToRawData = nOffset;
                }

                if ((nVirtualAddress > Int32.MaxValue) || (nPointerToRawData > Int32.MaxValue))
                {
                    Console.WriteLine("[-] The specified address is out of raw data range.");
                    break;
                }

                if (nOffset < nHeaderSize)
                {
                    Console.WriteLine("[*] The specified base address is in header region.");
                }
                else
                {
                    if (isVirtualAddress)
                    {
                        status = Helpers.GetSectionHeaderForVirtualAddress(pModuleBuffer, nVirtualAddress, out sectionHeader);

                        if (status)
                            Console.WriteLine("[*] VirtualAddress (0x{0}) is in {1} section.", nVirtualAddress.ToString("X8"), sectionHeader.Name.ToString());
                    }
                    else
                    {
                        status = Helpers.GetSectionHeaderForRawOffset(pModuleBuffer, nPointerToRawData, out sectionHeader);

                        if (status)
                            Console.WriteLine("[*] PointerToRawData (0x{0}) is in {1} section.", nPointerToRawData.ToString("X8"), sectionHeader.Name.ToString());
                    }

                    if (!status)
                    {
                        Console.WriteLine("[-] The specified address is not in section.");
                        break;
                    }
                }

                if ((nPointerToRawData + nSize) > moduleData.Length)
                {
                    Console.WriteLine("[-] Data size is out of data boundary.");
                    break;
                }

                if (Environment.Is64BitProcess)
                    pDataBuffer = new IntPtr(pModuleBuffer.ToInt64() + nPointerToRawData);
                else
                    pDataBuffer = new IntPtr(pModuleBuffer.ToInt32() + (int)nPointerToRawData);

                Marshal.Copy(pDataBuffer, data, 0, nSize);

                Console.WriteLine("[*] Export 0x{0} bytes raw data to {1}.", nSize.ToString("X"), output);
                File.WriteAllBytes(output, data);
            } while (false);

            Marshal.FreeHGlobal(pModuleBuffer);

            Console.WriteLine("[*] Done.");

            return status;
        }


        public static bool GetModuleInformation(byte[] moduleData)
        {
            uint nAddressOfEntryPoint;
            IntPtr pModuleBuffer = Marshal.AllocHGlobal(moduleData.Length);
            var status = false;
            Marshal.Copy(moduleData, 0, pModuleBuffer, moduleData.Length);

            Console.WriteLine("[*] Raw Data Size : {0} bytes", moduleData.Length);

            do
            {
                if (!Helpers.IsValidPe(pModuleBuffer))
                {
                    Console.WriteLine("[-] Not valid PE file data.");
                    break;
                }

                nAddressOfEntryPoint = Helpers.GetAddressOfEntryPoint(pModuleBuffer);
                Console.WriteLine("[*] Architecture  : {0}", Helpers.GetPeArchitecture(pModuleBuffer).ToString());
                Console.WriteLine("[*] Header Size   : 0x{0} bytes", Helpers.GetHeaderSize(pModuleBuffer).ToString("X"));
                Console.WriteLine("[*] EntryPoint:");
                Console.WriteLine("    [*] VirtualAddress   : 0x{0}", nAddressOfEntryPoint.ToString("X8"));
                Console.WriteLine("    [*] PointerToRawData : 0x{0}", Helpers.ConvertRvaToRawDataOffset(pModuleBuffer, nAddressOfEntryPoint).ToString("X8"));

                status = Helpers.GetSectionHeaders(
                    pModuleBuffer,
                    out List<IMAGE_SECTION_HEADER> sections);

                if (!status)
                {
                    Console.WriteLine("[-] No sections are found.");
                    break;
                }

                Console.WriteLine("[*] Sections (Count = {0}):", sections.Count);

                foreach (var section in sections)
                {
                    Console.WriteLine("    [*] {0} Section:", section.Name.ToString());
                    Console.WriteLine("        [*] VirtualAddress   : 0x{0}", section.VirtualAddress.ToString("X8"));
                    Console.WriteLine("        [*] PointerToRawData : 0x{0}", section.PointerToRawData.ToString("X8"));
                    Console.WriteLine("        [*] SizeOfRawData    : 0x{0}", section.SizeOfRawData.ToString("X"));
                }

                status = Helpers.GetExportFunctionRvaFromRawData(
                    pModuleBuffer,
                    out Dictionary<string, int> exports);

                if (!status)
                {
                    Console.WriteLine("[-] Not supported architecture.");
                    break;
                }

                Console.WriteLine("[*] Export functions (Count = {0}):", exports.Count);

                foreach (var export in exports)
                {
                    Console.WriteLine("    [*] {0} function:", export.Key);
                    Console.WriteLine("        [*] VirtualAddress   : 0x{0}", export.Value.ToString("X8"));
                    Console.WriteLine("        [*] PointerToRawData : 0x{0}", Helpers.ConvertRvaToRawDataOffset(pModuleBuffer, (uint)export.Value).ToString("X8"));
                }

                status = true;
            } while (false);

            Marshal.FreeHGlobal(pModuleBuffer);

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
