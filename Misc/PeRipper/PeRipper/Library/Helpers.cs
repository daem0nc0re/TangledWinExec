using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using PeRipper.Interop;

namespace PeRipper.Library
{
    internal class Helpers
    {
        public static uint ConvertRawDataOffsetToRva(IntPtr pModuleBase, uint nPointerToRawData)
        {
            var nVirtualAddress = UInt32.MaxValue;

            do
            {
                if (!IsValidPe(pModuleBase))
                    break;

                if (nPointerToRawData < GetHeaderSize(pModuleBase))
                {
                    nVirtualAddress = nPointerToRawData;
                    break;
                }

                if (GetSectionHeaders(pModuleBase, out List<IMAGE_SECTION_HEADER> headers))
                {
                    foreach (var header in headers)
                    {
                        if ((nPointerToRawData >= header.PointerToRawData) &&
                            (nPointerToRawData < (header.PointerToRawData + header.SizeOfRawData)))
                        {
                            uint nDifference = header.VirtualAddress - header.PointerToRawData;
                            nVirtualAddress = nPointerToRawData + nDifference;
                            break;
                        }
                    }
                }
            } while (false);

            return nVirtualAddress;
        }


        public static uint ConvertRvaToRawDataOffset(IntPtr pModuleBase, uint nVirtualAddress)
        {
            var nPointerToRawData = UInt32.MaxValue;

            do
            {
                if (!IsValidPe(pModuleBase))
                    break;

                if (nVirtualAddress < (uint)GetHeaderSize(pModuleBase))
                {
                    nPointerToRawData = nVirtualAddress;
                    break;
                }

                if (GetSectionHeaders(pModuleBase, out List<IMAGE_SECTION_HEADER> headers))
                {
                    foreach (var header in headers)
                    {
                        if ((nVirtualAddress >= header.VirtualAddress) &&
                            (nVirtualAddress < (header.VirtualAddress + header.SizeOfRawData)))
                        {
                            uint nDifference = header.VirtualAddress - header.PointerToRawData;
                            nPointerToRawData = nVirtualAddress - nDifference;
                            break;
                        }
                    }
                }
            } while (false);

            return nPointerToRawData;
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


        public static string DumpFunctionTable(
            IntPtr pModuleBase,
            Dictionary<int, int> imageRuntimeFunctionEntries,
            Dictionary<string, int> exportTable)
        {
            string outputFormat;
            var columnName = new string[] { "Offset (Raw)", "Offset (VA)", "Size", "Export Name" };
            var nSizeFormatWidth = columnName[2].Length;
            var outputBuilder = new StringBuilder();
            var exportNameBuilder = new StringBuilder();

            if ((imageRuntimeFunctionEntries.Count == 0) && (exportTable.Count == 0))
                return null;

            foreach (var nRegionSize in imageRuntimeFunctionEntries.Values)
            {
                var regionSizeOutput = string.Format("0x{0}", nRegionSize.ToString("X"));

                if (regionSizeOutput.Length > nSizeFormatWidth)
                    nSizeFormatWidth = regionSizeOutput.Length;
            }

            outputFormat = string.Format("{{0, {0}}} {{1, {1}}} {{2, {2}}} {{3}}\n",
                columnName[0].Length,
                columnName[1].Length,
                nSizeFormatWidth);
            outputBuilder.AppendFormat("[Function Table ({0} entries)]\n\n", imageRuntimeFunctionEntries.Count);
            outputBuilder.AppendFormat(outputFormat, columnName[0], columnName[1], columnName[2], columnName[3]);
            outputBuilder.AppendFormat(outputFormat,
                new string('=', columnName[0].Length),
                new string('=', columnName[1].Length),
                new string('=', nSizeFormatWidth),
                new string('=', columnName[3].Length));

            foreach (var entry in imageRuntimeFunctionEntries)
            {
                foreach (var info in exportTable)
                {
                    if (entry.Key == info.Value)
                    {
                        if (exportNameBuilder.Length == 0)
                            exportNameBuilder.AppendFormat("{0}", info.Key);
                        else
                            exportNameBuilder.AppendFormat(", {0}", info.Key);
                    }
                }

                if (exportNameBuilder.Length == 0)
                    exportNameBuilder.Append("(N/A)");

                outputBuilder.AppendFormat(outputFormat,
                    string.Format("0x{0}", ConvertRvaToRawDataOffset(pModuleBase, (uint)entry.Key).ToString("X8")),
                    string.Format("0x{0}", entry.Key.ToString("X8")),
                    string.Format("0x{0}", entry.Value.ToString("X")),
                    exportNameBuilder.ToString());

                exportNameBuilder.Clear();
            }

            return outputBuilder.ToString();
        }


        public static string DumpSectionTable(List<IMAGE_SECTION_HEADER> sectionHeaders)
        {
            string outputFormat;
            var columnName = new string[] { "Name", "Offset (Raw)", "Offset (VA)", "SizeOfRawData", "VirtualSize", "Flags" };
            var nNameFormatWidth = columnName[0].Length;
            var outputBuilder = new StringBuilder();

            foreach (var header in sectionHeaders)
            {
                if (header.Name.TrimEnd('\0').Length > nNameFormatWidth)
                    nNameFormatWidth = header.Name.TrimEnd('\0').Length;
            }

            outputFormat = string.Format("{{0, {0}}} {{1, {1}}} {{2, {2}}} {{3, {3}}} {{4, {4}}} {{5}}\n",
                nNameFormatWidth,
                columnName[1].Length,
                columnName[2].Length,
                columnName[3].Length,
                columnName[4].Length);
            outputBuilder.AppendFormat("[Section Information ({0} sections)]\n\n", sectionHeaders.Count);
            outputBuilder.AppendFormat(outputFormat,
                columnName[0],
                columnName[1],
                columnName[2],
                columnName[3],
                columnName[4],
                columnName[5]);
            outputBuilder.AppendFormat(outputFormat,
                new string('=', nNameFormatWidth),
                new string('=', columnName[1].Length),
                new string('=', columnName[2].Length),
                new string('=', columnName[3].Length),
                new string('=', columnName[4].Length),
                new string('=', columnName[5].Length));

            foreach (var header in sectionHeaders)
            {
                outputBuilder.AppendFormat(outputFormat,
                    header.Name.TrimEnd('\0'),
                    string.Format("0x{0}", header.PointerToRawData.ToString("X8")),
                    string.Format("0x{0}", header.VirtualAddress.ToString("X8")),
                    string.Format("0x{0}", header.SizeOfRawData.ToString("X")),
                    string.Format("0x{0}", header.VirtualSize.ToString("X")),
                    header.Characteristics.ToString());
            }

            return outputBuilder.ToString();
        }


        public static uint GetAddressOfEntryPoint(IntPtr pModuleBase)
        {
            var nAddressOfEntryPoint = 0u;

            if (IsValidPe(pModuleBase))
            {
                var e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);
                nAddressOfEntryPoint = (uint)Marshal.ReadInt32(pModuleBase, e_lfanew + 0x28);
            }

            return nAddressOfEntryPoint;
        }


        public static bool GetExportFunctionRvaFromRawData(
            IntPtr pModuleData,
            out Dictionary<string, int> exports)
        {
            var status = false;
            exports = new Dictionary<string, int>();

            do
            {
                uint nExportDirectoryOffset;
                int nFunctionOffset;
                int nNameOffset;
                int nOrdinalOffset;
                IMAGE_EXPORT_DIRECTORY exportDirectory;
                IntPtr pExportDirectory;

                if (!IsValidPe(pModuleData))
                    break;

                var e_lfanew = Marshal.ReadInt32(pModuleData, 0x3C);
                IMAGE_FILE_MACHINE machine = GetPeArchitecture(pModuleData);

                if ((machine == IMAGE_FILE_MACHINE.AMD64) || (machine == IMAGE_FILE_MACHINE.ARM64))
                    nExportDirectoryOffset = (uint)Marshal.ReadInt32(pModuleData, e_lfanew + 0x88);
                else if (machine == IMAGE_FILE_MACHINE.I386)
                    nExportDirectoryOffset = (uint)Marshal.ReadInt32(pModuleData, e_lfanew + 0x78);
                else
                    break;

                if (nExportDirectoryOffset != 0u)
                {
                    nExportDirectoryOffset = ConvertRvaToRawDataOffset(pModuleData, nExportDirectoryOffset);

                    if (Environment.Is64BitProcess)
                        pExportDirectory = new IntPtr(pModuleData.ToInt64() + nExportDirectoryOffset);
                    else
                        pExportDirectory = new IntPtr(pModuleData.ToInt32() + (int)nExportDirectoryOffset);

                    exportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                        pExportDirectory,
                        typeof(IMAGE_EXPORT_DIRECTORY));
                    nFunctionOffset = (int)ConvertRvaToRawDataOffset(
                        pModuleData,
                        (uint)exportDirectory.AddressOfFunctions);
                    nNameOffset = (int)ConvertRvaToRawDataOffset(
                        pModuleData,
                        (uint)exportDirectory.AddressOfNames);
                    nOrdinalOffset = (int)ConvertRvaToRawDataOffset(
                        pModuleData,
                        (uint)exportDirectory.AddressOfNameOrdinals);

                    for (var index = 0; index < exportDirectory.NumberOfNames; index++)
                    {
                        IntPtr pAnsiString;
                        int nOrdinal;
                        int nFunctionRva;
                        int nAnsiStringOffset = Marshal.ReadInt32(pModuleData, nNameOffset + (4 * index));

                        nAnsiStringOffset = (int)ConvertRvaToRawDataOffset(pModuleData, (uint)nAnsiStringOffset);
                        nOrdinal = Marshal.ReadInt16(pModuleData, nOrdinalOffset + (2 * index));
                        nFunctionRva = Marshal.ReadInt32(pModuleData, nFunctionOffset + (4 * nOrdinal));

                        if (Environment.Is64BitProcess)
                            pAnsiString = new IntPtr(pModuleData.ToInt64() + nAnsiStringOffset);
                        else
                            pAnsiString = new IntPtr(pModuleData.ToInt32() + nAnsiStringOffset);

                        exports.Add(Marshal.PtrToStringAnsi(pAnsiString), nFunctionRva);
                    }
                }

                status = true;
            } while (false);

            return status;
        }


        public static bool GetFunctionRegionData(
            IntPtr pModuleBase,
            in List<IMAGE_SECTION_HEADER> headers,
            out Dictionary<int, int> regions)
        {
            var index = 0;
            var nUnitSize = Marshal.SizeOf(typeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
            var pPdataSection = IntPtr.Zero;
            regions = new Dictionary<int, int>(); // Key: VirtualAddress for Function Entry, Value: Function Size

            if (headers.Count == 0)
                return false;

            foreach (var header in headers)
            {
                if (string.Compare(header.Name, ".pdata", true) == 0)
                {
                    if (Environment.Is64BitProcess)
                        pPdataSection = new IntPtr(pModuleBase.ToInt64() + header.PointerToRawData);
                    else
                        pPdataSection = new IntPtr(pModuleBase.ToInt32() + header.PointerToRawData);

                    break;
                }
            }

            if (pPdataSection == IntPtr.Zero)
                return false;

            while (true)
            {
                var nBeginRva = Marshal.ReadInt32(pPdataSection, index * nUnitSize);
                var nEndRva = Marshal.ReadInt32(pPdataSection, (index * nUnitSize) + 4);

                if (nBeginRva == 0)
                    break;

                if (!regions.ContainsKey(nBeginRva))
                    regions.Add(nBeginRva, nEndRva - nBeginRva);

                index++;
            }

            return true;
        }


        public static int GetHeaderSize(IntPtr pModuleBase)
        {
            int nHeaderSize = 0;

            if (IsValidPe(pModuleBase))
            {
                var e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);
                nHeaderSize = Marshal.ReadInt32(pModuleBase, e_lfanew + 0x54);
            }

            return nHeaderSize;
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


        public static IMAGE_FILE_MACHINE GetPeArchitecture(IntPtr pModuleBase)
        {
            var machine = IMAGE_FILE_MACHINE.UNKNOWN;

            do
            {
                if (Marshal.ReadInt16(pModuleBase) != 0x5A4D)
                    break;

                var e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);

                // Avoid memory access violation
                if (e_lfanew > 0x800)
                    break;

                if (Marshal.ReadInt32(pModuleBase, e_lfanew) != 0x00004550)
                    break;

                machine = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pModuleBase, e_lfanew + 4);
            } while (false);

            return machine;
        }


        public static bool GetSectionHeaders(
            IntPtr pModuleBase,
            out List<IMAGE_SECTION_HEADER> headers)
        {
            int e_lfanew;
            int nSectionOffset;
            ushort nNumberOfSections;
            ushort nSizeOfOptionalHeader;
            IntPtr pSectionHeader;
            IntPtr pSectionHeaderBase;
            IMAGE_SECTION_HEADER sectionHeader;
            int nSectionHeaderSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            var status = false;
            headers = new List<IMAGE_SECTION_HEADER>();

            do
            {
                if (!IsValidPe(pModuleBase))
                    break;

                e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);
                nNumberOfSections = (ushort)Marshal.ReadInt16(pModuleBase, e_lfanew + 0x6);
                nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pModuleBase, e_lfanew + 0x14);
                nSectionOffset = e_lfanew + 0x18 + nSizeOfOptionalHeader;

                if (Environment.Is64BitProcess)
                    pSectionHeaderBase = new IntPtr(pModuleBase.ToInt64() + nSectionOffset);
                else
                    pSectionHeaderBase = new IntPtr(pModuleBase.ToInt32() + nSectionOffset);

                for (var index = 0; index < nNumberOfSections; index++)
                {
                    if (Environment.Is64BitProcess)
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt64() + (index * nSectionHeaderSize));
                    else
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt32() + (index * nSectionHeaderSize));

                    sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pSectionHeader,
                        typeof(IMAGE_SECTION_HEADER));

                    headers.Add(sectionHeader);
                }

                status = (headers.Count > 0);
            } while (false);

            return status;
        }


        public static bool GetSectionHeaderForVirtualAddress(
            IntPtr pModuleBase,
            uint nVirtualAddress,
            out IMAGE_SECTION_HEADER sectionHeader)
        {
            bool status;
            sectionHeader = new IMAGE_SECTION_HEADER();

            do
            {
                status = GetSectionHeaders(pModuleBase, out List<IMAGE_SECTION_HEADER> headers);

                if (status)
                {
                    foreach (var header in headers)
                    {
                        if ((nVirtualAddress >= header.VirtualAddress) &&
                            (nVirtualAddress < header.VirtualAddress + header.VirtualSize))
                        {
                            sectionHeader = header;
                            status = true;
                            break;
                        }
                    }
                }
            } while (false);

            return status;
        }


        public static bool GetSectionHeaderForRawOffset(
            IntPtr pModuleBase,
            uint nPointerToRawData,
            out IMAGE_SECTION_HEADER sectionHeader)
        {
            bool status;
            sectionHeader = new IMAGE_SECTION_HEADER();

            do
            {
                status = GetSectionHeaders(pModuleBase, out List<IMAGE_SECTION_HEADER> headers);

                if (status)
                {
                    foreach (var header in headers)
                    {
                        if ((nPointerToRawData >= header.PointerToRawData) &&
                            (nPointerToRawData < header.PointerToRawData + header.SizeOfRawData))
                        {
                            sectionHeader = header;
                            status = true;
                            break;
                        }
                    }
                }
            } while (false);

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
                if (e_lfanew > 0x800)
                    break;

                if (Marshal.ReadInt32(pModule, e_lfanew) != 0x00004550)
                    break;

                status = true;
            } while (false);

            return status;
        }
    }
}
