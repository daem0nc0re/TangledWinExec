using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ReflectiveInjector.Interop;

namespace ReflectiveInjector.Library
{
    internal class Utilities
    {
        public static int ConvertVirtualAddressToRawOffset(
            int nVirtualAddress,
            List<IMAGE_SECTION_HEADER> sections)
        {
            int nPointerToRawData = 0;

            foreach (var section in sections)
            {
                if ((section.VirtualAddress <= nVirtualAddress) &&
                    ((section.VirtualAddress + section.VirtualSize) > nVirtualAddress))
                {
                    nPointerToRawData = (int)(nVirtualAddress - section.VirtualAddress + section.PointerToRawData);
                    break;
                }
            }

            return nPointerToRawData;
        }


        public static IMAGE_FILE_MACHINE GetArchitectureOfImage(IntPtr pModuleDataBase)
        {
            int e_lfanew;

            if (Marshal.ReadInt16(pModuleDataBase) != 0x5A4D)
                return IMAGE_FILE_MACHINE.UNKNOWN;

            e_lfanew = Marshal.ReadInt32(pModuleDataBase, 0x3C);

            if (e_lfanew > 0x200)
                return IMAGE_FILE_MACHINE.UNKNOWN;

            if (Marshal.ReadInt32(pModuleDataBase, e_lfanew) != 0x00004550)
                return IMAGE_FILE_MACHINE.UNKNOWN;

            return (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pModuleDataBase, e_lfanew + 4);
        }


        public static int GetProcOffsetFromRawData(IntPtr pModuleData, string procName)
        {
            IntPtr pPeHeader;
            IntPtr pExportDirectory;
            IntPtr pAddressOfFunctions;
            IntPtr pAddressOfNames;
            IntPtr pAddressOfOrdinals;
            IntPtr pNameString;
            int nVirtualAddress;
            int nNumberOfNames;
            short magic;
            short nOrdinal;
            List<IMAGE_SECTION_HEADER> sections;
            int nPointerToRawData;
            int nOffset = 0;

            do
            {
                if (Marshal.ReadInt16(pModuleData) != 0x5A4D)
                    break;

                if (Environment.Is64BitProcess)
                    pPeHeader = new IntPtr(pModuleData.ToInt64() + Marshal.ReadInt32(pModuleData, 0x3C));
                else
                    pPeHeader = new IntPtr(pModuleData.ToInt32() + Marshal.ReadInt32(pModuleData, 0x3C));

                if (Marshal.ReadInt32(pPeHeader) != 0x00004550)
                    break;

                magic = Marshal.ReadInt16(pPeHeader, 0x18);

                if (magic == 0x020B)
                    nVirtualAddress = Marshal.ReadInt32(pPeHeader, 0x88);
                else if (magic == 0x010B)
                    nVirtualAddress = Marshal.ReadInt32(pPeHeader, 0x78);
                else
                    break;

                sections = Helpers.GetSectionHeaders(pModuleData);
                nPointerToRawData = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);

                if (Environment.Is64BitProcess)
                {
                    pExportDirectory = new IntPtr(pModuleData.ToInt64() + nPointerToRawData);
                    nNumberOfNames = Marshal.ReadInt32(pExportDirectory, 0x18);

                    nVirtualAddress = Marshal.ReadInt32(pExportDirectory, 0x1C);
                    nPointerToRawData = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);
                    pAddressOfFunctions = new IntPtr(pModuleData.ToInt64() + nPointerToRawData);

                    nVirtualAddress = Marshal.ReadInt32(pExportDirectory, 0x20);
                    nPointerToRawData = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);
                    pAddressOfNames = new IntPtr(pModuleData.ToInt64() + nPointerToRawData);

                    nVirtualAddress = Marshal.ReadInt32(pExportDirectory, 0x24);
                    nPointerToRawData = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);
                    pAddressOfOrdinals = new IntPtr(pModuleData.ToInt64() + nPointerToRawData);
                }
                else
                {
                    pExportDirectory = new IntPtr(pModuleData.ToInt32() + nPointerToRawData);
                    nNumberOfNames = Marshal.ReadInt32(pExportDirectory, 0x18);

                    nVirtualAddress = Marshal.ReadInt32(pExportDirectory, 0x1C);
                    nPointerToRawData = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);
                    pAddressOfFunctions = new IntPtr(pModuleData.ToInt32() + nPointerToRawData);

                    nVirtualAddress = Marshal.ReadInt32(pExportDirectory, 0x20);
                    nPointerToRawData = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);
                    pAddressOfNames = new IntPtr(pModuleData.ToInt32() + nPointerToRawData);

                    nVirtualAddress = Marshal.ReadInt32(pExportDirectory, 0x24);
                    nPointerToRawData = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);
                    pAddressOfOrdinals = new IntPtr(pModuleData.ToInt32() + nPointerToRawData);
                }

                for (var index = 0; index < nNumberOfNames; index++)
                {
                    nVirtualAddress = Marshal.ReadInt32(pAddressOfNames, 4 * index);
                    nPointerToRawData = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);

                    if (Environment.Is64BitProcess)
                        pNameString = new IntPtr(pModuleData.ToInt64() + nPointerToRawData);
                    else
                        pNameString = new IntPtr(pModuleData.ToInt32() + nPointerToRawData);

                    if (Helpers.CompareIgnoreCase(Marshal.PtrToStringAnsi(pNameString), procName))
                    {
                        nOrdinal = Marshal.ReadInt16(pAddressOfOrdinals, 2 * index);
                        nVirtualAddress = Marshal.ReadInt32(pAddressOfFunctions, 4 * nOrdinal);
                        nOffset = ConvertVirtualAddressToRawOffset(nVirtualAddress, sections);
                        break;
                    }
                }
            } while (false);

            return nOffset;
        }
    }
}
