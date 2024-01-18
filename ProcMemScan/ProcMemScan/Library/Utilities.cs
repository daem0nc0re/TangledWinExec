using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ProcMemScan.Interop;

namespace ProcMemScan.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static string DumpInMemoryOrderModuleList(
            IntPtr hProcess,
            List<LDR_DATA_TABLE_ENTRY> tableEntries,
            bool is32bit,
            int nIndentCount,
            out Dictionary<IntPtr, string> dlls)
        {
            string lineFormat;
            var addressFormat = is32bit ? "X8" : "X16";
            var headers = new string[] { "Base", "Reason", "Loaded", "Module" };
            var widths = new int[headers.Length];
            var outputBuilder = new StringBuilder();
            dlls = new Dictionary<IntPtr, string>();

            if (tableEntries.Count == 0)
                return null;

            for (var idx = 0; idx < headers.Length; idx++)
                widths[idx] = headers[idx].Length;

            widths[0] = is32bit ? 10 : 18;
            widths[2] = 19; // "YYYY/MM/DD hh/mm/ss"

            foreach (var table in tableEntries)
            {
                string imagePathName = Helpers.ReadRemoteUnicodeString(hProcess, table.FullDllName);

                if (string.IsNullOrEmpty(imagePathName))
                    imagePathName = "N/A";

                dlls.Add(table.DllBase, imagePathName);

                if (table.LoadReason.ToString().Length > widths[1])
                    widths[1] = table.LoadReason.ToString().Length;
            }

            lineFormat = string.Format("{0}{{0,{1}}} {{1,-{2}}} {{2,-{3}}} {{3}}\n",
                new string(' ', nIndentCount * 4),
                widths[0],
                widths[1],
                widths[2]);

            outputBuilder.AppendFormat(lineFormat, headers[0], headers[1], headers[2], headers[3]);

            foreach (var table in tableEntries)
            {
                outputBuilder.AppendFormat(lineFormat,
                    string.Format("0x{0}", table.DllBase.ToString(addressFormat)),
                    table.LoadReason.ToString(),
                    Helpers.ConvertLargeIntegerToLocalTimeString(table.LoadTime),
                    dlls[table.DllBase]);
            }

            return outputBuilder.ToString();
        }


        public static string DumpMemoryBasicInformation(
            IntPtr hProcess,
            List<MEMORY_BASIC_INFORMATION> memoryTable)
        {
            string format;
            Dictionary<string, string> deviceMap = Helpers.GetDeviceMap();
            var outputBuilder = new StringBuilder();
            var labels = new string[] { "Base", "Size", "State", "Protect", "Type", "Mapped File" };
            var widths = new int[labels.Length];

            if (memoryTable.Count == 0)
                return null;

            for (var index = 0; index < labels.Length; index++)
                widths[index] = labels[index].Length;

            if (Environment.Is64BitProcess)
                widths[0] = 18;
            else
                widths[0] = 10;

            foreach (var info in memoryTable)
            {
                int nLength;
                
                if (Environment.Is64BitProcess)
                    nLength = string.Format("0x{0}", info.RegionSize.ToUInt64().ToString("X")).Length;
                else
                    nLength = string.Format("0x{0}", info.RegionSize.ToUInt32().ToString("X")).Length;

                if (nLength > widths[1])
                    widths[1] = nLength;

                nLength = info.State.ToString().Length;

                if (nLength > widths[2])
                    widths[2] = nLength;

                nLength = info.Protect.ToString().Length;

                if (nLength > widths[3])
                    widths[3] = nLength;

                nLength = info.Type.ToString().Length;

                if (nLength > widths[4])
                    widths[4] = nLength;
            }

            format = string.Format("{{0, {0}}} {{1, {1}}} {{2, -{2}}} {{3, -{3}}} {{4, -{4}}} {{5}}\n",
                widths[0],
                widths[1],
                widths[2],
                widths[3],
                widths[4]);
            outputBuilder.AppendFormat(format,
                labels[0],
                labels[1],
                labels[2],
                labels[3],
                labels[4],
                labels[5]);
            outputBuilder.AppendFormat(format,
                new string('=', widths[0]),
                new string('=', widths[1]),
                new string('=', widths[2]),
                new string('=', widths[3]),
                new string('=', widths[4]),
                new string('=', widths[5]));

            foreach (var info in memoryTable)
            {
                string imageFileName = Helpers.GetMappedImagePathName(hProcess, info.BaseAddress);

                if (!string.IsNullOrEmpty(imageFileName))
                {
                    foreach (var entry in deviceMap)
                    {
                        var convertedPath = Regex.Replace(
                            imageFileName,
                            string.Format(@"^{0}", entry.Value).Replace("\\", "\\\\"),
                            entry.Key,
                            RegexOptions.IgnoreCase);

                        if (convertedPath != imageFileName)
                        {
                            imageFileName = convertedPath;
                            break;
                        }
                    }
                }

                outputBuilder.AppendFormat(format,
                    string.Format("0x{0}", info.BaseAddress.ToString(Environment.Is64BitProcess ? "X16" : "X8")),
                    string.Format("0x{0}", info.RegionSize.ToUInt64().ToString("X")),
                    info.State.ToString(),
                    info.Protect.ToString(),
                    info.Type.ToString(),
                    imageFileName ?? "N/A");
            }

            return outputBuilder.ToString();
        }


        public static string DumpPebInformation(IntPtr hProcess, IntPtr pPeb, bool is32bit)
        {
            bool bReadLdr;
            string mappedImageFile;
            string currentDirectory;
            string windowTitle;
            string imagePathName;
            string commandLine;
            string dllPath;
            Dictionary<string, string> environments;
            IntPtr pProcessParametersData;
            IntPtr pEnvironment;
            List<LDR_DATA_TABLE_ENTRY> tableEntries;
            Dictionary<string, string> deviceMap = Helpers.GetDeviceMap();
            var outputBuilder = new StringBuilder();
            var addressFormat = Environment.Is64BitProcess ? "X16" : "X8";

            if (!GetPebPartialData(hProcess, pPeb, out PEB_PARTIAL peb))
                return null;

            mappedImageFile = Helpers.GetMappedImagePathName(hProcess, peb.ImageBaseAddress);

            if (!string.IsNullOrEmpty(mappedImageFile))
            {
                foreach (var entry in deviceMap)
                {
                    var convertedPath = Regex.Replace(
                        mappedImageFile,
                        string.Format(@"^{0}", entry.Value).Replace("\\", "\\\\"),
                        entry.Key,
                        RegexOptions.IgnoreCase);

                    if (convertedPath != mappedImageFile)
                    {
                        mappedImageFile = convertedPath;
                        break;
                    }
                }
            }

            pProcessParametersData = Helpers.GetProcessParameters(hProcess, pPeb);
            bReadLdr = GetPebLdrData(hProcess, peb.Ldr, out PEB_LDR_DATA ldr);

            if ((pProcessParametersData != IntPtr.Zero) && Environment.Is64BitOperatingSystem && is32bit)
            {
                var processParameters32 = (RTL_USER_PROCESS_PARAMETERS32)Marshal.PtrToStructure(
                    pProcessParametersData,
                    typeof(RTL_USER_PROCESS_PARAMETERS32));
                currentDirectory = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    Helpers.ConvertUnicodeString32ToUnicodeString(processParameters32.CurrentDirectory.DosPath));
                windowTitle = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    Helpers.ConvertUnicodeString32ToUnicodeString(processParameters32.WindowTitle));
                imagePathName = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    Helpers.ConvertUnicodeString32ToUnicodeString(processParameters32.ImagePathName));
                commandLine = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    Helpers.ConvertUnicodeString32ToUnicodeString(processParameters32.CommandLine));
                dllPath = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    Helpers.ConvertUnicodeString32ToUnicodeString(processParameters32.DllPath));
                pEnvironment = new IntPtr(processParameters32.Environment);
                environments = Helpers.EnumEnvrionments(hProcess, pEnvironment, processParameters32.EnvironmentSize);
            }
            else if (pProcessParametersData != IntPtr.Zero)
            {
                var processParameters = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(
                    pProcessParametersData,
                    typeof(RTL_USER_PROCESS_PARAMETERS));
                currentDirectory = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    processParameters.CurrentDirectory.DosPath);
                windowTitle = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    processParameters.WindowTitle);
                imagePathName = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    processParameters.ImagePathName);
                commandLine = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    processParameters.CommandLine);
                dllPath = Helpers.ReadRemoteUnicodeString(
                    hProcess,
                    processParameters.DllPath);
                pEnvironment = processParameters.Environment;
                environments = Helpers.EnumEnvrionments(
                    hProcess,
                    pEnvironment,
                    (uint)processParameters.EnvironmentSize);
            }
            else
            {
                currentDirectory = null;
                windowTitle = null;
                imagePathName = null;
                commandLine = null;
                dllPath = null;
                pEnvironment = IntPtr.Zero;
                environments = new Dictionary<string, string>();
            }

            if (Environment.Is64BitOperatingSystem && is32bit)
                outputBuilder.AppendFormat("ntdll!_PEB32 @ 0x{0}\n", pPeb.ToString(addressFormat));
            else
                outputBuilder.AppendFormat("ntdll!_PEB @ 0x{0}\n", pPeb.ToString(addressFormat));

            outputBuilder.AppendFormat("    InheritedAddressSpace    : {0}\n", peb.InheritedAddressSpace);
            outputBuilder.AppendFormat("    ReadImageFileExecOptions : {0}\n", peb.ReadImageFileExecOptions);
            outputBuilder.AppendFormat("    BeingDebugged            : {0}\n", peb.BeingDebugged);
            outputBuilder.AppendFormat("    ImageBaseAddress         : 0x{0} ({1})\n",
                peb.ImageBaseAddress.ToString(addressFormat),
                mappedImageFile ?? "N/A");
            outputBuilder.AppendFormat("    Ldr                      : 0x{0}\n", peb.Ldr.ToString(addressFormat));

            if (bReadLdr)
            {
                tableEntries = GetInMemoryOrderModuleList(hProcess, ldr.InMemoryOrderModuleList.Flink);

                outputBuilder.AppendFormat("    Ldr.Initialized          : {0}\n", ldr.Initialized);
                outputBuilder.AppendFormat("    Ldr.InInitializationOrderModuleList : {{ 0x{0} - 0x{1} }}\n",
                    ldr.InInitializationOrderModuleList.Flink.ToString(addressFormat),
                    ldr.InInitializationOrderModuleList.Blink.ToString(addressFormat));
                outputBuilder.AppendFormat("    Ldr.InLoadOrderModuleList           : {{ 0x{0} - 0x{1} }}\n",
                    ldr.InLoadOrderModuleList.Flink.ToString(addressFormat),
                    ldr.InLoadOrderModuleList.Blink.ToString(addressFormat));
                outputBuilder.AppendFormat("    Ldr.InMemoryOrderModuleList         : {{ 0x{0} - 0x{1} }}\n",
                    ldr.InMemoryOrderModuleList.Flink.ToString(addressFormat),
                    ldr.InMemoryOrderModuleList.Blink.ToString(addressFormat));
                outputBuilder.Append(DumpInMemoryOrderModuleList(hProcess, tableEntries, is32bit, 2, out var _));
            }

            outputBuilder.AppendFormat("    SubSystemData     : 0x{0}\n", peb.SubSystemData.ToString(addressFormat));
            outputBuilder.AppendFormat("    ProcessHeap       : 0x{0}\n", peb.ProcessHeap.ToString(addressFormat));
            outputBuilder.AppendFormat("    ProcessParameters : 0x{0}\n", peb.ProcessParameters.ToString(addressFormat));

            if (pProcessParametersData != IntPtr.Zero)
            {
                outputBuilder.AppendFormat("    CurrentDirectory  : '{0}'\n", string.IsNullOrEmpty(currentDirectory) ? "(null)" : currentDirectory);
                outputBuilder.AppendFormat("    WindowTitle       : '{0}'\n", string.IsNullOrEmpty(windowTitle) ? "(null)" : windowTitle);
                outputBuilder.AppendFormat("    ImagePathName     : '{0}'\n", string.IsNullOrEmpty(imagePathName) ? "(null)" : imagePathName);
                outputBuilder.AppendFormat("    CommandLine       : '{0}'\n", string.IsNullOrEmpty(commandLine) ? "(null)" : commandLine);
                outputBuilder.AppendFormat("    DLLPath           : '{0}'\n", string.IsNullOrEmpty(dllPath) ? "(null)" : dllPath);
                outputBuilder.AppendFormat("    Environment       : 0x{0}\n", pEnvironment.ToString(addressFormat));

                foreach (var environment in environments)
                    outputBuilder.AppendFormat("        {0}={1}\n", environment.Key, environment.Value);
            }

            return outputBuilder.ToString();
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
            IntPtr hProcess = NativeMethods.OpenProcess(
                ACCESS_MASK.PROCESS_QUERY_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
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
            IntPtr pBufferToRead = Helpers.ReadMemory(hProcess, mbi.BaseAddress, mbi.RegionSize.ToUInt32());

            if (pBufferToRead == IntPtr.Zero)
                return;

            for (var offset = 0u; offset < mbi.RegionSize.ToUInt32(); offset += 0x1000u)
            {
                if (Environment.Is64BitProcess)
                    pVerify = new IntPtr(pBufferToRead.ToInt64() + offset);
                else
                    pVerify = new IntPtr(pBufferToRead.ToInt32() + offset);

                var imageDosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                    pVerify,
                    typeof(IMAGE_DOS_HEADER));

                if (imageDosHeader.IsValid)
                {
                    if (Environment.Is64BitProcess)
                        pPeHeaders.Add(new IntPtr(mbi.BaseAddress.ToInt64() + offset));
                    else
                        pPeHeaders.Add(new IntPtr(mbi.BaseAddress.ToInt32() + offset));
                }
            }

            Marshal.FreeHGlobal(pBufferToRead);
        }
    }
}
