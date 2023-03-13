using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HashResolveTester.Library
{
    internal class Helpers
    {
        public static uint CalcRor13(uint code)
        {
            return (((code >> 13) | (code << (32 - 13))) & 0xFFFFFFFF);
        }


        public static uint GetHashFromAsciiString(string asciiString)
        {
            uint hash = 0;
            var asciiBytes = Encoding.ASCII.GetBytes(asciiString);

            for (var index = 0; index < asciiBytes.Length; index++)
                hash = CalcRor13(hash) + asciiBytes[index];

            return hash;
        }


        public static IntPtr GetProcAddressByHash(IntPtr pModule, uint hash, out string functionName)
        {
            var pProc = IntPtr.Zero;
            int e_lfanew;
            int nExportDirectoryOffset;
            int nNumberOfNames;
            int nOrdinal;
            ushort machine;
            IntPtr pExportDirectory;
            IntPtr pAddressOfFunctions;
            IntPtr pAddressOfNames;
            IntPtr pAddressOfOrdinals;
            IntPtr pAnsiString;
            functionName = null;

            do
            {
                if (Marshal.ReadInt16(pModule) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pModule, 0x3C);

                if (e_lfanew > 0x1000)
                    break;

                if (Marshal.ReadInt32(pModule, e_lfanew) != 0x00004550)
                    break;

                machine = (ushort)Marshal.ReadInt16(pModule, e_lfanew + 0x18);

                if ((machine == (ushort)0x020B) || (machine == (ushort)0xAA64))
                    nExportDirectoryOffset = Marshal.ReadInt32(pModule, e_lfanew + 0x88);
                else if (machine == (ushort)0x010B)
                    nExportDirectoryOffset = Marshal.ReadInt32(pModule, e_lfanew + 0x78);
                else
                    break;

                if (Environment.Is64BitProcess)
                {
                    pExportDirectory = new IntPtr(pModule.ToInt64() + nExportDirectoryOffset);
                    pAddressOfFunctions = new IntPtr(pModule.ToInt64() + Marshal.ReadInt32(pExportDirectory, 0x1C));
                    pAddressOfNames = new IntPtr(pModule.ToInt64() + Marshal.ReadInt32(pExportDirectory, 0x20));
                    pAddressOfOrdinals = new IntPtr(pModule.ToInt64() + Marshal.ReadInt32(pExportDirectory, 0x24));
                }
                else
                {
                    pExportDirectory = new IntPtr(pModule.ToInt32() + nExportDirectoryOffset);
                    pAddressOfFunctions = new IntPtr(pModule.ToInt32() + Marshal.ReadInt32(pExportDirectory, 0x1C));
                    pAddressOfNames = new IntPtr(pModule.ToInt32() + Marshal.ReadInt32(pExportDirectory, 0x20));
                    pAddressOfOrdinals = new IntPtr(pModule.ToInt32() + Marshal.ReadInt32(pExportDirectory, 0x24));
                }

                nNumberOfNames = Marshal.ReadInt32(pExportDirectory, 0x18);

                for (var index = 0; index < nNumberOfNames; index++)
                {
                    nOrdinal = Marshal.ReadInt16(pAddressOfOrdinals, index * 2);

                    if (Environment.Is64BitProcess)
                    {
                        pAnsiString = new IntPtr(pModule.ToInt64() + Marshal.ReadInt32(pAddressOfNames, index * 4));
                        pProc = new IntPtr(pModule.ToInt64() + Marshal.ReadInt32(pAddressOfFunctions, nOrdinal * 4));
                    }
                    else
                    {
                        pAnsiString = new IntPtr(pModule.ToInt32() + Marshal.ReadInt32(pAddressOfNames, index * 4));
                        pProc = new IntPtr(pModule.ToInt32() + Marshal.ReadInt32(pAddressOfFunctions, nOrdinal * 4));
                    }

                    functionName = Marshal.PtrToStringAnsi(pAnsiString);

                    if (GetHashFromAsciiString(functionName.ToUpper()) == hash)
                        break;

                    pProc = IntPtr.Zero;
                }
            } while (false);

            return pProc;
        }
    }
}
