using System;
using System.IO;
using System.Runtime.InteropServices;
using EaDumper.Interop;

namespace EaDumper.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool DumpEaInformation(string filePath)
        {
            NTSTATUS ntstatus;
            IntPtr pEntry;
            int index = 0;
            filePath = Path.GetFullPath(filePath);

            Console.WriteLine("[>] Trying to dump EA information.");
            Console.WriteLine("    [*] File Path : {0}", filePath);

            ntstatus = Helpers.GetEaInformationFromFile(filePath, out IntPtr pEaInfoBuffer);
            pEntry = pEaInfoBuffer;

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get EA information from the specified file.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return false;
            }

            do
            {
                Helpers.ParseFileFullEaInformation(
                    pEntry,
                    out EA_INFORMATION_FLAGS flags,
                    out string eaName,
                    out byte[] eaValue,
                    out pEntry);

                Console.WriteLine("[*] Entries[0x{0}]", index.ToString("X2"));
                Console.WriteLine("    [*] Flags    : {0}", flags.ToString());
                Console.WriteLine("    [*] EA Name  : {0}", eaName);
                Console.WriteLine("    [*] EA Value :");
                Console.WriteLine();
                HexDump.Dump(eaValue, 2);
                Console.WriteLine();

                if (Helpers.CompareIgnoreCase(eaName, "$KERNEL.PURGE.ESBCACHE"))
                     Helpers.ParseEsbCache(eaValue);

                index++;
            } while (pEntry != IntPtr.Zero);

            Marshal.FreeHGlobal(pEaInfoBuffer);

            Console.WriteLine("[*] Done.");

            return true;
        }
    }
}
