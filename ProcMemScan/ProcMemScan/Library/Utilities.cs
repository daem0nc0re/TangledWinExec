using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ProcMemScan.Interop;

namespace ProcMemScan.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static Dictionary<IntPtr, string> DumpInMemoryOrderModuleList(
            IntPtr hProcess,
            List<LDR_DATA_TABLE_ENTRY> tableEntries,
            int nIndentCount)
        {
            string line;
            string lineFormat;
            string imagePathName;
            string dllLoadedTime;
            string addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";
            string headerBase = "Base";
            string headerReason = "Reason";
            string headerLoaded = "Loaded";
            string headerModule = "Module";
            int nMaxBaseStringLength = headerBase.Length;
            int nMaxReasonStringLength = headerReason.Length;
            int nMaxLoadedStringLength = headerLoaded.Length;
            int nMaxModuleStringLength = headerModule.Length;
            var dictionaryDll = new Dictionary<IntPtr, string>();

            if (tableEntries.Count == 0)
                return dictionaryDll;

            if (((IntPtr.Size * 2) + 2) > nMaxBaseStringLength)
                nMaxBaseStringLength = (IntPtr.Size * 2) + 2;

            foreach (var table in tableEntries)
            {
                imagePathName = Helpers.ReadRemoteUnicodeString(hProcess, table.FullDllName);
                dllLoadedTime = Helpers.ConvertLargeIntegerToLocalTimeString(table.LoadTime);

                if (string.IsNullOrEmpty(imagePathName))
                    imagePathName = "N/A";

                dictionaryDll.Add(table.DllBase, imagePathName);
                
                if (table.LoadReason.ToString().Length > nMaxReasonStringLength)
                    nMaxReasonStringLength = table.LoadReason.ToString().Length;

                if (dictionaryDll[table.DllBase].Length > nMaxModuleStringLength)
                    nMaxModuleStringLength = imagePathName.Length;

                if (dllLoadedTime.Length > nMaxLoadedStringLength)
                    nMaxLoadedStringLength = dllLoadedTime.Length;
            }

            lineFormat = string.Format(
                "{0}{{0,{1}}} {{1,-{2}}} {{2,-{3}}} {{3,-{4}}}",
                new string(' ', nIndentCount * 4),
                nMaxBaseStringLength,
                nMaxReasonStringLength,
                nMaxLoadedStringLength,
                nMaxModuleStringLength);

            line = string.Format(lineFormat, headerBase, headerReason, headerLoaded, headerModule);
            Console.WriteLine(line.TrimEnd());

            foreach (var table in tableEntries)
            {
                line = string.Format(
                    lineFormat,
                    string.Format("0x{0}", table.DllBase.ToString(addressFormat)),
                    table.LoadReason.ToString(),
                    Helpers.ConvertLargeIntegerToLocalTimeString(table.LoadTime),
                    dictionaryDll[table.DllBase]);
                Console.WriteLine(line.TrimEnd());
            }

            return dictionaryDll;
        }


        public static void DumpMemoryBasicInformation(
            IntPtr hProcess,
            List<MEMORY_BASIC_INFORMATION> memoryTable)
        {
            string line;
            string lineFormat;
            string tempString;
            string mappedImagePathName;
            string addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";
            string headerBaseAddress = "Base";
            string headerRegionSize = "Size";
            string headerState = "State";
            string headerProtect = "Protect";
            string headerType = "Type";
            string headerMapped = "Mapped";
            int nMaxBaseAddressStringLength = headerBaseAddress.Length;
            int nMaxRegionSizeStringLength = headerRegionSize.Length;
            int nMaxStateStringLength = headerState.Length;
            int nMaxProtectStringLength = headerProtect.Length;
            int nMaxTypeStringLength = headerType.Length;
            int nMaxMappedStringLength = headerMapped.Length;
            var dictionaryMappedImagePathName = new Dictionary<IntPtr, string>();

            if (((IntPtr.Size * 2) + 2) > nMaxBaseAddressStringLength)
                nMaxBaseAddressStringLength = (IntPtr.Size * 2) + 2;

            foreach (var mbi in memoryTable)
            {
                tempString = string.Format("0x{0}", mbi.RegionSize.ToUInt64().ToString("X"));
                mappedImagePathName = Helpers.GetMappedImagePathName(hProcess, mbi.BaseAddress);

                if (string.IsNullOrEmpty(mappedImagePathName))
                    mappedImagePathName = "N/A";

                dictionaryMappedImagePathName.Add(mbi.BaseAddress, mappedImagePathName);

                if (tempString.Length > nMaxRegionSizeStringLength)
                    nMaxRegionSizeStringLength = tempString.Length;

                if (mbi.State.ToString().Length > nMaxStateStringLength)
                    nMaxStateStringLength = mbi.State.ToString().Length;

                if (mbi.Protect.ToString().Length > nMaxProtectStringLength)
                    nMaxProtectStringLength = mbi.Protect.ToString().Length;

                if (mbi.Type.ToString().Length > nMaxTypeStringLength)
                    nMaxTypeStringLength = mbi.Type.ToString().Length;

                if (mappedImagePathName.Length > nMaxMappedStringLength)
                    nMaxMappedStringLength = mappedImagePathName.Length;
            }

            lineFormat = string.Format(
                "{{0,{0}}} {{1,{1}}} {{2,-{2}}} {{3,-{3}}} {{4,-{4}}} {{5,-{5}}}",
                nMaxBaseAddressStringLength,
                nMaxRegionSizeStringLength,
                nMaxStateStringLength,
                nMaxProtectStringLength,
                nMaxTypeStringLength,
                nMaxMappedStringLength);
            line = string.Format(
                lineFormat,
                headerBaseAddress,
                headerRegionSize,
                headerState,
                headerProtect,
                headerType,
                headerMapped);
            Console.WriteLine(line.TrimEnd());

            foreach (var mbi in memoryTable)
            {
                line = string.Format(
                    lineFormat,
                    string.Format("0x{0}", mbi.BaseAddress.ToString(addressFormat)),
                    string.Format("0x{0}", mbi.RegionSize.ToUInt64().ToString("X")),
                    mbi.State.ToString(),
                    mbi.Protect.ToString(),
                    mbi.Type.ToString(),
                    dictionaryMappedImagePathName[mbi.BaseAddress]);
                Console.WriteLine(line.TrimEnd());
            }
        }


        public static List<LDR_DATA_TABLE_ENTRY> GetInMemoryOrderModuleList(
            IntPtr hProcess,
            IntPtr pInMemoryOrderModuleList)
        {
            IntPtr pBufferToRead;
            LDR_DATA_TABLE_ENTRY entry;
            int nOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "InMemoryOrderLinks").ToInt32();
            int nStructSize = Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY));
            var pCurrentStruct = new IntPtr(pInMemoryOrderModuleList.ToInt64() - nOffset);
            var tableEntries = new List<LDR_DATA_TABLE_ENTRY>();

            do
            {
                pBufferToRead = Helpers.ReadMemory(hProcess, pCurrentStruct, (uint)nStructSize);

                if (pBufferToRead == IntPtr.Zero)
                    return tableEntries;

                entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(
                    pBufferToRead,
                    typeof(LDR_DATA_TABLE_ENTRY));

                if (entry.DllBase != IntPtr.Zero)
                    tableEntries.Add(entry);

                Marshal.FreeHGlobal(pBufferToRead);

                if (entry.InMemoryOrderLinks.Flink == pInMemoryOrderModuleList)
                    break;
                else
                    pCurrentStruct = new IntPtr(entry.InMemoryOrderLinks.Flink.ToInt64() - nOffset);
            } while (true);

            return tableEntries;
        }


        public static bool GetPebLdrData(
            IntPtr hProcess,
            PEB_PARTIAL peb,
            out PEB_LDR_DATA ldr)
        {
            IntPtr pLdrBuffer;

            pLdrBuffer = Helpers.ReadMemory(
                hProcess,
                peb.Ldr,
                (uint)Marshal.SizeOf(typeof(PEB_LDR_DATA)));

            if (pLdrBuffer == IntPtr.Zero)
            {
                ldr = new PEB_LDR_DATA();

                return false;
            }
            else
            {
                ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(
                    pLdrBuffer,
                    typeof(PEB_LDR_DATA));
                Marshal.FreeHGlobal(pLdrBuffer);

                return true;
            }
        }


        public static bool GetPebPartialData(
            IntPtr hProcess,
            IntPtr pPeb,
            out PEB_PARTIAL pebPartial)
        {
            IntPtr pPebBuffer;

            pPebBuffer = Helpers.ReadMemory(
                hProcess,
                pPeb,
                (uint)Marshal.SizeOf(typeof(PEB_PARTIAL)));

            if (pPebBuffer == IntPtr.Zero)
            {
                pebPartial = new PEB_PARTIAL();

                return false;
            }
            else
            {
                pebPartial = (PEB_PARTIAL)Marshal.PtrToStructure(
                    pPebBuffer,
                    typeof(PEB_PARTIAL));
                Marshal.FreeHGlobal(pPebBuffer);

                return true;
            }
        }


        public static IntPtr OpenTargetProcess(int pid)
        {
            NTSTATUS ntstatus;
            CLIENT_ID clientId;
            var objectAttributes = new OBJECT_ATTRIBUTES();

            clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };

            ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.PROCESS_QUERY_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                in objectAttributes,
                in clientId);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[!] Failed to open the target process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return IntPtr.Zero;
            }

            return hProcess;
        }


        public static void SearchPeHeaderAddress(
            IntPtr hProcess,
            MEMORY_BASIC_INFORMATION mbi,
            ref List<IntPtr> pPeHeaders)
        {
            IntPtr pVerify;
            IntPtr pBufferToRead;
            IMAGE_DOS_HEADER imageDosHeader;

            pBufferToRead = Helpers.ReadMemory(hProcess, mbi.BaseAddress, mbi.RegionSize.ToUInt32());

            if (pBufferToRead == IntPtr.Zero)
                return;

            for (var offset = 0u; offset < mbi.RegionSize.ToUInt32(); offset += 0x1000u)
            {
                pVerify = new IntPtr(pBufferToRead.ToInt64() + offset);
                imageDosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                    pVerify,
                    typeof(IMAGE_DOS_HEADER));

                if (imageDosHeader.IsValid)
                    pPeHeaders.Add(new IntPtr(mbi.BaseAddress.ToInt64() + offset));
            }

            Marshal.FreeHGlobal(pBufferToRead);
        }
    }
}
