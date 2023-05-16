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
            bool is32bit,
            int nIndentCount)
        {
            string line;
            string lineFormat;
            string imagePathName;
            string dllLoadedTime;
            string addressFormat = is32bit ? "X8" : "X16";
            string headerBase = "Base";
            string headerReason = "Reason";
            string headerLoaded = "Loaded";
            string headerModule = "Module";
            int nMaxBaseStringLength = is32bit ? 10 : 18;
            int nMaxReasonStringLength = headerReason.Length;
            int nMaxLoadedStringLength = headerLoaded.Length;
            int nMaxModuleStringLength = headerModule.Length;
            var dictionaryDll = new Dictionary<IntPtr, string>();

            if (tableEntries.Count == 0)
                return dictionaryDll;

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
            IntPtr pCurrentStruct;
            LDR_DATA_TABLE_ENTRY entry;
            LDR_DATA_TABLE_ENTRY32 entry32;
            int nOffset;
            int nStructSize;
            bool is32bit;
            var tableEntries = new List<LDR_DATA_TABLE_ENTRY>();

            if (Environment.Is64BitOperatingSystem)
            {
                NativeMethods.IsWow64Process(hProcess, out bool isWow64);
                is32bit = isWow64;

                if (isWow64)
                {
                    nOffset = Marshal.OffsetOf(
                        typeof(LDR_DATA_TABLE_ENTRY32),
                        "InMemoryOrderLinks").ToInt32();
                    nStructSize = Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY32));
                }
                else
                {
                    nOffset = Marshal.OffsetOf(
                        typeof(LDR_DATA_TABLE_ENTRY),
                        "InMemoryOrderLinks").ToInt32();
                    nStructSize = Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY));
                }
            }
            else
            {
                is32bit = true;
                nOffset = Marshal.OffsetOf(
                    typeof(LDR_DATA_TABLE_ENTRY),
                    "InMemoryOrderLinks").ToInt32();
                nStructSize = Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY));
            }

            pCurrentStruct = new IntPtr(pInMemoryOrderModuleList.ToInt64() - nOffset);

            do
            {
                pBufferToRead = Helpers.ReadMemory(hProcess, pCurrentStruct, (uint)nStructSize);

                if (pBufferToRead == IntPtr.Zero)
                    return tableEntries;

                if (is32bit)
                {
                    entry = new LDR_DATA_TABLE_ENTRY();
                    entry32 = (LDR_DATA_TABLE_ENTRY32)Marshal.PtrToStructure(
                        pBufferToRead,
                        typeof(LDR_DATA_TABLE_ENTRY32));

                    entry.InLoadOrderLinks = Helpers.ConvertListEntry32ToListEntry(entry32.InLoadOrderLinks);
                    entry.InMemoryOrderLinks = Helpers.ConvertListEntry32ToListEntry(entry32.InMemoryOrderLinks);
                    entry.InInitializationOrderLinks = Helpers.ConvertListEntry32ToListEntry(entry32.InInitializationOrderLinks);
                    entry.DllBase = new IntPtr(entry32.DllBase);
                    entry.EntryPoint = new IntPtr(entry32.EntryPoint);
                    entry.SizeOfImage = entry32.SizeOfImage;
                    entry.FullDllName = Helpers.ConvertUnicodeString32ToUnicodeString(entry32.FullDllName);
                    entry.BaseDllName = Helpers.ConvertUnicodeString32ToUnicodeString(entry32.BaseDllName);
                    entry.Flags = entry32.Flags;
                    entry.ObsoleteLoadCount = entry32.ObsoleteLoadCount;
                    entry.TlsIndex = entry32.TlsIndex;
                    entry.HashLinks = Helpers.ConvertListEntry32ToListEntry(entry32.HashLinks);
                    entry.TimeDateStamp = entry32.TimeDateStamp;
                    entry.EntryPointActivationContext = new IntPtr(entry32.EntryPointActivationContext);
                    entry.Lock = new IntPtr(entry32.Lock);
                    entry.DdagNode = new IntPtr(entry32.DdagNode);
                    entry.NodeModuleLink = Helpers.ConvertListEntry32ToListEntry(entry32.NodeModuleLink);
                    entry.LoadContext = new IntPtr(entry32.LoadContext);
                    entry.ParentDllBase = new IntPtr(entry32.ParentDllBase);
                    entry.SwitchBackContext = new IntPtr(entry32.SwitchBackContext);
                    entry.BaseAddressIndexNode = Helpers.ConvertBalanceNode32ToBalanceNode(entry32.BaseAddressIndexNode);
                    entry.MappingInfoIndexNode = Helpers.ConvertBalanceNode32ToBalanceNode(entry32.MappingInfoIndexNode);
                    entry.OriginalBase = (ulong)entry32.OriginalBase;
                    entry.LoadTime = entry32.LoadTime;
                    entry.BaseNameHashValue = entry32.BaseNameHashValue;
                    entry.LoadReason = entry32.LoadReason;
                    entry.ImplicitPathOptions = entry32.ImplicitPathOptions;
                    entry.ReferenceCount = entry32.ReferenceCount;
                    entry.DependentLoadFlags = entry32.DependentLoadFlags;
                    entry.SigningLevel = entry32.SigningLevel;
                    entry.CheckSum = entry32.CheckSum;
                    entry.ActivePatchImageBase = new IntPtr(entry32.ActivePatchImageBase);
                    entry.HotPatchState = entry32.HotPatchState;
                }
                else
                {
                    entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(
                        pBufferToRead,
                        typeof(LDR_DATA_TABLE_ENTRY));
                }

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


        public static bool GetPebLdrData(IntPtr hProcess, IntPtr pLdr, out PEB_LDR_DATA ldr)
        {
            IntPtr pBuffer;
            uint nBufferSize;
            PEB_LDR_DATA32 ldr32;

            if (Environment.Is64BitProcess && Environment.Is64BitProcess)
            {
                NativeMethods.IsWow64Process(hProcess, out bool isWow64);

                if (isWow64)
                    nBufferSize = (uint)Marshal.SizeOf(typeof(PEB_LDR_DATA32));
                else
                    nBufferSize = (uint)Marshal.SizeOf(typeof(PEB_LDR_DATA));

                pBuffer = Helpers.ReadMemory(hProcess, pLdr, nBufferSize);

                if (pBuffer == IntPtr.Zero)
                {
                    ldr = new PEB_LDR_DATA();

                    return false;
                }

                if (isWow64)
                {
                    ldr = new PEB_LDR_DATA();
                    ldr32 = (PEB_LDR_DATA32)Marshal.PtrToStructure(pBuffer, typeof(PEB_LDR_DATA32));

                    ldr.Length = ldr32.Length;
                    ldr.Initialized = ldr32.Initialized;
                    ldr.SsHandle = new IntPtr(ldr32.SsHandle);
                    ldr.InLoadOrderModuleList = Helpers.ConvertListEntry32ToListEntry(ldr32.InLoadOrderModuleList);
                    ldr.InMemoryOrderModuleList = Helpers.ConvertListEntry32ToListEntry(ldr32.InMemoryOrderModuleList);
                    ldr.InInitializationOrderModuleList = Helpers.ConvertListEntry32ToListEntry(ldr32.InInitializationOrderModuleList);
                    ldr.EntryInProgress = new IntPtr(ldr32.EntryInProgress);
                    ldr.ShutdownInProgress = ldr32.ShutdownInProgress;
                    ldr.ShutdownThreadId = new IntPtr(ldr32.ShutdownThreadId);
                }
                else
                {
                    ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(pBuffer, typeof(PEB_LDR_DATA));
                }
            }
            else
            {
                nBufferSize = (uint)Marshal.SizeOf(typeof(PEB_LDR_DATA));

                pBuffer = Helpers.ReadMemory(hProcess, pLdr, nBufferSize);

                if (pBuffer == IntPtr.Zero)
                {
                    ldr = new PEB_LDR_DATA();

                    return false;
                }

                ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(pBuffer, typeof(PEB_LDR_DATA));
            }

            if (pBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pBuffer);

            return true;
        }


        public static bool GetPebPartialData(IntPtr hProcess, IntPtr pPeb, out PEB_PARTIAL peb)
        {
            bool is32bit;
            IntPtr pBuffer;
            uint nBufferSize;
            PEB32_PARTIAL peb32;

            if (Environment.Is64BitProcess)
            {
                NativeMethods.IsWow64Process(hProcess, out bool isWow64);
                is32bit = isWow64;
            }
            else
            {
                is32bit = true;
            }

            if (is32bit)
                nBufferSize = (uint)Marshal.SizeOf(typeof(PEB32_PARTIAL));
            else
                nBufferSize = (uint)Marshal.SizeOf(typeof(PEB64_PARTIAL));
            
            pBuffer = Helpers.ReadMemory(hProcess, pPeb, nBufferSize);

            if (pBuffer == IntPtr.Zero)
            {
                peb = new PEB_PARTIAL();

                return false;
            }

            if (is32bit)
            {
                peb = new PEB_PARTIAL();
                peb32 = (PEB32_PARTIAL)Marshal.PtrToStructure(pBuffer, typeof(PEB32_PARTIAL));

                peb.InheritedAddressSpace = peb32.InheritedAddressSpace;
                peb.ReadImageFileExecOptions = peb32.ReadImageFileExecOptions;
                peb.BeingDebugged = peb32.BeingDebugged;
                peb.Mutant = new IntPtr((int)peb32.Mutant);
                peb.ImageBaseAddress = new IntPtr((int)peb32.ImageBaseAddress);
                peb.Ldr = new IntPtr((int)peb32.Ldr);
                peb.ProcessParameters = new IntPtr((int)peb32.ProcessParameters);
                peb.SubSystemData = new IntPtr((int)peb32.SubSystemData);
                peb.ProcessHeap = new IntPtr((int)peb32.ProcessHeap);
            }
            else
            {
                peb = (PEB_PARTIAL)Marshal.PtrToStructure(pBuffer, typeof(PEB_PARTIAL));
            }

            Marshal.FreeHGlobal(pBuffer);

            return true;
        }


        public static bool GetRemoteModuleExports(
            IntPtr hProcess,
            IntPtr pImageBase,
            out IMAGE_FILE_MACHINE architecture,
            out List<IMAGE_SECTION_HEADER> sectionHeaders,
            out string exportName,
            out Dictionary<string, int> exports)
        {
            IntPtr pHeaderBuffer = Marshal.AllocHGlobal(0x1000);
            int nSectionHeaderSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            var pDirectoryBuffer = IntPtr.Zero;
            var status = false;
            architecture = IMAGE_FILE_MACHINE.UNKNOWN;
            sectionHeaders = new List<IMAGE_SECTION_HEADER>();
            exportName = null;
            exports = new Dictionary<string, int>();

            do
            {
                int e_lfanew;
                ushort nNumberOfSections;
                ushort nSizeOfOptionalHeader;
                int nSectionOffset;
                int nExportDirectoryOffset;
                int nExportDirectorySize;
                IntPtr pSectionHeaderBase;
                IntPtr pSectionHeader;
                IntPtr pExportDirectory;
                NTSTATUS ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pImageBase,
                    pHeaderBuffer,
                    0x1000u,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                if (Marshal.ReadInt16(pHeaderBuffer) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pHeaderBuffer, 0x3C);

                if (e_lfanew > 0x800)
                    break;

                architecture = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pHeaderBuffer, e_lfanew + 0x4);
                nNumberOfSections = (ushort)Marshal.ReadInt16(pHeaderBuffer, e_lfanew + 0x6);
                nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pHeaderBuffer, e_lfanew + 0x14);
                nSectionOffset = e_lfanew + 0x18 + nSizeOfOptionalHeader;

                if ((architecture == IMAGE_FILE_MACHINE.AMD64) ||
                    (architecture == IMAGE_FILE_MACHINE.IA64) ||
                    (architecture == IMAGE_FILE_MACHINE.ARM64))
                {
                    nExportDirectoryOffset = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x88);
                    nExportDirectorySize = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x8C);
                }
                else if ((architecture == IMAGE_FILE_MACHINE.I386) || (architecture == IMAGE_FILE_MACHINE.ARM2))
                {
                    nExportDirectoryOffset = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x78);
                    nExportDirectorySize = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x7C);
                }
                else
                {
                    break;
                }

                if ((nExportDirectoryOffset == 0) || (nExportDirectorySize == 0))
                {
                    status = true;
                    break;
                }

                if (Environment.Is64BitProcess)
                    pSectionHeaderBase = new IntPtr(pHeaderBuffer.ToInt64() + nSectionOffset);
                else
                    pSectionHeaderBase = new IntPtr(pHeaderBuffer.ToInt32() + nSectionOffset);

                for (var index = 0; index < nNumberOfSections; index++)
                {
                    if (Environment.Is64BitProcess)
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt64() + (index * nSectionHeaderSize));
                    else
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt32() + (index * nSectionHeaderSize));

                    var sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pSectionHeader,
                        typeof(IMAGE_SECTION_HEADER));

                    sectionHeaders.Add(sectionHeader);
                }

                if (Environment.Is64BitProcess)
                    pExportDirectory = new IntPtr(pImageBase.ToInt64() + nExportDirectoryOffset);
                else
                    pExportDirectory = new IntPtr(pImageBase.ToInt32() + nExportDirectoryOffset);

                pDirectoryBuffer = Marshal.AllocHGlobal(nExportDirectorySize);
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pExportDirectory,
                    pDirectoryBuffer,
                    (uint)nExportDirectorySize,
                    out uint _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (status)
                {
                    IntPtr pStringBuffer;
                    int nOrdinal;
                    int nFunctionOffset;
                    var nStringOffset = Marshal.ReadInt32(pDirectoryBuffer, 0xC) - nExportDirectoryOffset;
                    var nNumberOfNames = Marshal.ReadInt32(pDirectoryBuffer, 0x18);
                    var nAddressOfFunctions = Marshal.ReadInt32(pDirectoryBuffer, 0x1C) - nExportDirectoryOffset;
                    var nAddressOfNames = Marshal.ReadInt32(pDirectoryBuffer, 0x20) - nExportDirectoryOffset;
                    var nAddressOfOrdinals = Marshal.ReadInt32(pDirectoryBuffer, 0x24) - nExportDirectoryOffset;

                    if (Environment.Is64BitProcess)
                        pStringBuffer = new IntPtr(pDirectoryBuffer.ToInt64() + nStringOffset);
                    else
                        pStringBuffer = new IntPtr(pDirectoryBuffer.ToInt32() + nStringOffset);

                    if (nStringOffset != 0)
                        exportName = Marshal.PtrToStringAnsi(pStringBuffer);

                    for (var index = 0; index < nNumberOfNames; index++)
                    {
                        nStringOffset = Marshal.ReadInt32(pDirectoryBuffer, nAddressOfNames + (index * 4)) - nExportDirectoryOffset;
                        nOrdinal = Marshal.ReadInt16(pDirectoryBuffer, nAddressOfOrdinals + (index * 2));
                        nFunctionOffset = Marshal.ReadInt32(pDirectoryBuffer, nAddressOfFunctions + (nOrdinal * 4));

                        if (Environment.Is64BitProcess)
                            pStringBuffer = new IntPtr(pDirectoryBuffer.ToInt64() + nStringOffset);
                        else
                            pStringBuffer = new IntPtr(pDirectoryBuffer.ToInt32() + nStringOffset);

                        exports.Add(Marshal.PtrToStringAnsi(pStringBuffer), nFunctionOffset);
                    }
                }
            } while (false);

            if (pDirectoryBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pDirectoryBuffer);

            Marshal.FreeHGlobal(pHeaderBuffer);

            return status;
        }


        public static IntPtr OpenTargetProcess(int pid)
        {
            int error;
            IntPtr hProcess = NativeMethods.OpenProcess(
                ACCESS_MASK.PROCESS_QUERY_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[!] Failed to open the target process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
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
