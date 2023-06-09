using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using ReflectiveInjector.Interop;

namespace ReflectiveInjector.Library
{
    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static List<IMAGE_SECTION_HEADER> GetSectionHeaders(IntPtr pModule)
        {
            IntPtr pPeHeader;
            IntPtr pFileHeader;
            IntPtr pSectionHeaders;
            IntPtr pCurrent;
            int nSectionCount;
            int nSizeOfOptionalHeader;
            short magic;
            IMAGE_FILE_HEADER fileHeader;
            int nSizeOfSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            var sections = new List<IMAGE_SECTION_HEADER>();

            do
            {
                if (Marshal.ReadInt16(pModule) != 0x5A4D)
                    break;

                if (Environment.Is64BitProcess)
                {
                    pPeHeader = new IntPtr(pModule.ToInt64() + Marshal.ReadInt32(pModule, 0x3C));
                    pFileHeader = new IntPtr(pPeHeader.ToInt64() + 4);
                }
                else
                {
                    pPeHeader = new IntPtr(pModule.ToInt32() + Marshal.ReadInt32(pModule, 0x3C));
                    pFileHeader = new IntPtr(pPeHeader.ToInt32() + 4);
                }

                if (Marshal.ReadInt32(pPeHeader) != 0x00004550)
                    break;

                magic = Marshal.ReadInt16(pPeHeader, 0x18);

                if ((magic != 0x010B) && (magic != 0x020B))
                    break;

                fileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(
                    pFileHeader,
                    typeof(IMAGE_FILE_HEADER));
                nSectionCount = (int)fileHeader.NumberOfSections;
                nSizeOfOptionalHeader = (int)fileHeader.SizeOfOptionalHeader;

                if (Environment.Is64BitProcess)
                    pSectionHeaders = new IntPtr(pPeHeader.ToInt64() + 0x18 + nSizeOfOptionalHeader);
                else
                    pSectionHeaders = new IntPtr(pPeHeader.ToInt32() + 0x18 + nSizeOfOptionalHeader);

                for (var index = 0; index < nSectionCount; index++)
                {
                    if (Environment.Is64BitProcess)
                        pCurrent = new IntPtr(pSectionHeaders.ToInt64() + (nSizeOfSectionHeader * index));
                    else
                        pCurrent = new IntPtr(pSectionHeaders.ToInt32() + (nSizeOfSectionHeader * index));

                    sections.Add((IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pCurrent,
                        typeof(IMAGE_SECTION_HEADER)));
                }
            } while (false);

            return sections;
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
    }
}
