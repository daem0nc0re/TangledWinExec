using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
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


        public static string DumpPebInformation(IntPtr hProcess, IntPtr pPeb, bool bWow32)
        {
            bool bReadLdr;
            uint nEnvSize;
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
            var outputBuilder = new StringBuilder();
            var addressFormat = (Environment.Is64BitProcess && !bWow32) ? "X16" : "X8";

            if (!GetPebPartialData(hProcess, pPeb, bWow32, out PEB_PARTIAL peb))
                return null;

            mappedImageFile = Helpers.GetMappedImagePathName(hProcess, peb.ImageBaseAddress);
            pProcessParametersData = Helpers.GetProcessParameters(hProcess, pPeb, bWow32);
            bReadLdr = GetPebLdrData(hProcess, peb.Ldr, bWow32, out PEB_LDR_DATA ldr);

            if ((pProcessParametersData != IntPtr.Zero) && bWow32)
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
                nEnvSize = processParameters32.EnvironmentSize;
                environments = Helpers.EnumEnvrionments(hProcess, pEnvironment, nEnvSize);
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
                nEnvSize = (uint)processParameters.EnvironmentSize;
                environments = Helpers.EnumEnvrionments(hProcess, pEnvironment, nEnvSize);
            }
            else
            {
                currentDirectory = null;
                windowTitle = null;
                imagePathName = null;
                commandLine = null;
                dllPath = null;
                pEnvironment = IntPtr.Zero;
                nEnvSize = 0u;
                environments = new Dictionary<string, string>();
            }

            if (Environment.Is64BitProcess && bWow32)
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
                tableEntries = GetInMemoryOrderModuleList(hProcess, ldr.InMemoryOrderModuleList.Flink, bWow32);

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
                outputBuilder.Append(DumpInMemoryOrderModuleList(hProcess, tableEntries, bWow32, 2, out var _));
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
                outputBuilder.AppendFormat("    Environment       : 0x{0} (0x{1} Bytes)\n", pEnvironment.ToString(addressFormat), nEnvSize.ToString("X"));

                foreach (var environment in environments)
                    outputBuilder.AppendFormat("        {0}={1}\n", environment.Key, environment.Value);
            }

            return outputBuilder.ToString();
        }


        public static string DumpThreadInformation(
            in List<SYSTEM_THREAD_INFORMATION> threadInfo,
            in Dictionary<IntPtr, string> symbolTable,
            bool bTerminated)
        {
            int nEntryCount = 0;
            var outputBuilder = new StringBuilder();
            
            if (bTerminated)
            {
                outputBuilder.AppendLine("TERMINATED THREAD INFORMATION");
                outputBuilder.AppendLine("-----------------------------\n");
            }
            else
            {
                outputBuilder.AppendLine("ACTIVE THREAD INFORMATION");
                outputBuilder.AppendLine("-------------------------\n");
            }

            if (threadInfo.Count > 0)
            {
                var formatBuilder = new StringBuilder();
                var boarderBuilder = new StringBuilder();
                var columnName = new string[]
                {
                    "TID",
                    "CreateTime",
                    "Priority",
                    "BasePriority",
                    "State",
                    "WaitReason",
                    "StartAddress"
                };
                var columnWidth = new Dictionary<string, int>();

                for (var idx = 0; idx < columnName.Length; idx++)
                    columnWidth.Add(columnName[idx], columnName[idx].Length);

                columnWidth["CreateTime"] = 19;

                foreach (var info in threadInfo)
                {
                    if (!bTerminated && (info.ThreadState == KTHREAD_STATE.Terminated))
                        continue;
                    else if (bTerminated && (info.ThreadState != KTHREAD_STATE.Terminated))
                        continue;
                    else
                        nEntryCount++;

                    if (info.ClientId.UniqueThread.ToString().Length > columnWidth["TID"])
                        columnWidth["TID"] = info.ClientId.UniqueThread.ToString().Length;

                    if (info.ThreadState.ToString().Length > columnWidth["State"])
                        columnWidth["State"] = info.ThreadState.ToString().Length;

                    if (info.WaitReason.ToString().Length > columnWidth["WaitReason"])
                        columnWidth["WaitReason"] = info.WaitReason.ToString().Length;
                }

                if (nEntryCount > 0)
                {
                    for (var idx = 0; idx < columnName.Length; idx++)
                    {
                        if (idx > 0)
                        {
                            formatBuilder.Append(" ");
                            boarderBuilder.Append(" ");
                        }

                        if (idx == columnName.Length - 1)
                            formatBuilder.AppendFormat("{{{0}, -{1}}}", idx, columnWidth[columnName[idx]]);
                        else
                            formatBuilder.AppendFormat("{{{0}, {1}}}", idx, columnWidth[columnName[idx]]);

                        boarderBuilder.Append(new string('=', columnWidth[columnName[idx]]));

                        if (idx == columnName.Length - 1)
                        {
                            formatBuilder.AppendLine();
                            boarderBuilder.AppendLine();
                        }
                    }

                    outputBuilder.AppendFormat(formatBuilder.ToString(),
                        columnName[0],
                        columnName[1],
                        columnName[2],
                        columnName[3],
                        columnName[4],
                        columnName[5],
                        columnName[6]);
                    outputBuilder.Append(boarderBuilder.ToString());

                    foreach (var info in threadInfo)
                    {
                        if (!bTerminated && (info.ThreadState == KTHREAD_STATE.Terminated))
                            continue;
                        else if (bTerminated && (info.ThreadState != KTHREAD_STATE.Terminated))
                            continue;

                        var symbol = string.Format("0x{0}",
                            info.StartAddress.ToString(Environment.Is64BitProcess ? "X16" : "X8"));

                        if (info.StartAddress == IntPtr.Zero)
                        {
                            symbol = "N/A (Access is denied)";
                        }
                        else if (!string.IsNullOrEmpty(symbolTable[info.StartAddress]))
                        {
                            if (!string.IsNullOrEmpty(symbolTable[info.StartAddress]))
                                symbol = symbolTable[info.StartAddress];
                        }

                        outputBuilder.AppendFormat(formatBuilder.ToString(),
                            info.ClientId.UniqueThread,
                            Helpers.ConvertLargeIntegerToLocalTimeString(info.CreateTime),
                            info.Priority,
                            info.BasePriority,
                            info.ThreadState.ToString(),
                            info.WaitReason.ToString(),
                            symbol);
                    }
                }
                else
                {
                    outputBuilder.AppendLine("Nothing.");
                }
            }
            else
            {
                outputBuilder.AppendLine("Failed to get thread information.");
            }

            return outputBuilder.ToString();
        }


        public static List<LDR_DATA_TABLE_ENTRY> GetInMemoryOrderModuleList(
            IntPtr hProcess,
            IntPtr pInMemoryOrderModuleList,
            bool bWow64)
        {
            int nOffset;
            uint nStructSize;
            IntPtr pInfoBuffer;
            IntPtr pBufferToRead;
            var tableEntries = new List<LDR_DATA_TABLE_ENTRY>();

            if (Environment.Is64BitProcess && bWow64)
            {
                nOffset = Marshal.OffsetOf(typeof(LDR_DATA_TABLE_ENTRY32), "InMemoryOrderLinks").ToInt32();
                nStructSize = (uint)Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY32));
            }
            else
            {
                nOffset = Marshal.OffsetOf(typeof(LDR_DATA_TABLE_ENTRY), "InMemoryOrderLinks").ToInt32();
                nStructSize = (uint)Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY));
            }

            if (Environment.Is64BitProcess)
                pBufferToRead = new IntPtr(pInMemoryOrderModuleList.ToInt64() - nOffset);
            else
                pBufferToRead = new IntPtr(pInMemoryOrderModuleList.ToInt32() - nOffset);

            while (true)
            {
                LDR_DATA_TABLE_ENTRY entry;
                pInfoBuffer = Helpers.ReadMemory(hProcess, pBufferToRead, nStructSize, out uint _);

                if (pInfoBuffer == IntPtr.Zero)
                    break;

                if (Environment.Is64BitProcess && bWow64)
                {
                    var entry32 = (LDR_DATA_TABLE_ENTRY32)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(LDR_DATA_TABLE_ENTRY32));
                    entry = new LDR_DATA_TABLE_ENTRY
                    {
                        InLoadOrderLinks = Helpers.ConvertListEntry32ToListEntry(entry32.InLoadOrderLinks),
                        InMemoryOrderLinks = Helpers.ConvertListEntry32ToListEntry(entry32.InMemoryOrderLinks),
                        InInitializationOrderLinks = Helpers.ConvertListEntry32ToListEntry(entry32.InInitializationOrderLinks),
                        DllBase = new IntPtr(entry32.DllBase),
                        EntryPoint = new IntPtr(entry32.EntryPoint),
                        SizeOfImage = entry32.SizeOfImage,
                        FullDllName = Helpers.ConvertUnicodeString32ToUnicodeString(entry32.FullDllName),
                        BaseDllName = Helpers.ConvertUnicodeString32ToUnicodeString(entry32.BaseDllName),
                        Flags = entry32.Flags,
                        ObsoleteLoadCount = entry32.ObsoleteLoadCount,
                        TlsIndex = entry32.TlsIndex,
                        HashLinks = Helpers.ConvertListEntry32ToListEntry(entry32.HashLinks),
                        TimeDateStamp = entry32.TimeDateStamp,
                        EntryPointActivationContext = new IntPtr(entry32.EntryPointActivationContext),
                        Lock = new IntPtr(entry32.Lock),
                        DdagNode = new IntPtr(entry32.DdagNode),
                        NodeModuleLink = Helpers.ConvertListEntry32ToListEntry(entry32.NodeModuleLink),
                        LoadContext = new IntPtr(entry32.LoadContext),
                        ParentDllBase = new IntPtr(entry32.ParentDllBase),
                        SwitchBackContext = new IntPtr(entry32.SwitchBackContext),
                        BaseAddressIndexNode = Helpers.ConvertBalanceNode32ToBalanceNode(entry32.BaseAddressIndexNode),
                        MappingInfoIndexNode = Helpers.ConvertBalanceNode32ToBalanceNode(entry32.MappingInfoIndexNode),
                        OriginalBase = (ulong)entry32.OriginalBase,
                        LoadTime = entry32.LoadTime,
                        BaseNameHashValue = entry32.BaseNameHashValue,
                        LoadReason = entry32.LoadReason,
                        ImplicitPathOptions = entry32.ImplicitPathOptions,
                        ReferenceCount = entry32.ReferenceCount,
                        DependentLoadFlags = entry32.DependentLoadFlags,
                        SigningLevel = entry32.SigningLevel,
                        CheckSum = entry32.CheckSum,
                        ActivePatchImageBase = new IntPtr(entry32.ActivePatchImageBase),
                        HotPatchState = entry32.HotPatchState
                    };
                }
                else
                {
                    entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(LDR_DATA_TABLE_ENTRY));
                }

                if (entry.DllBase != IntPtr.Zero)
                    tableEntries.Add(entry);

                Marshal.FreeHGlobal(pInfoBuffer);

                if (entry.InMemoryOrderLinks.Flink == pInMemoryOrderModuleList)
                    break;

                if (Environment.Is64BitProcess)
                    pBufferToRead = new IntPtr(entry.InMemoryOrderLinks.Flink.ToInt64() - nOffset);
                else
                    pBufferToRead = new IntPtr(entry.InMemoryOrderLinks.Flink.ToInt32() - nOffset);
            }

            return tableEntries;
        }


        public static bool GetPebLdrData(IntPtr hProcess, IntPtr pLdr, bool bWow64, out PEB_LDR_DATA ldr)
        {
            IntPtr pInfoBuffer;
            uint nInfoLength;
            bool bSuccess;

            if (Environment.Is64BitProcess && bWow64)
                nInfoLength = (uint)Marshal.SizeOf(typeof(PEB_LDR_DATA32));
            else
                nInfoLength = (uint)Marshal.SizeOf(typeof(PEB_LDR_DATA));

            pInfoBuffer = Helpers.ReadMemory(hProcess, pLdr, nInfoLength, out uint _);

            if (pInfoBuffer == IntPtr.Zero)
            {
                ldr = new PEB_LDR_DATA();
                bSuccess = false;
            }
            else
            {
                if (Environment.Is64BitProcess && bWow64)
                {
                    var ldr32 = (PEB_LDR_DATA32)Marshal.PtrToStructure(pInfoBuffer, typeof(PEB_LDR_DATA32));
                    ldr = new PEB_LDR_DATA
                    {
                        Length = ldr32.Length,
                        Initialized = ldr32.Initialized,
                        SsHandle = new IntPtr(ldr32.SsHandle),
                        InLoadOrderModuleList = Helpers.ConvertListEntry32ToListEntry(ldr32.InLoadOrderModuleList),
                        InMemoryOrderModuleList = Helpers.ConvertListEntry32ToListEntry(ldr32.InMemoryOrderModuleList),
                        InInitializationOrderModuleList = Helpers.ConvertListEntry32ToListEntry(ldr32.InInitializationOrderModuleList),
                        EntryInProgress = new IntPtr(ldr32.EntryInProgress),
                        ShutdownInProgress = ldr32.ShutdownInProgress,
                        ShutdownThreadId = new IntPtr(ldr32.ShutdownThreadId)
                    };
                }
                else
                {
                    ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(pInfoBuffer, typeof(PEB_LDR_DATA));
                }

                Marshal.FreeHGlobal(pInfoBuffer);
                bSuccess = true;
            }

            return bSuccess;
        }


        public static bool GetPebPartialData(IntPtr hProcess, IntPtr pPeb, bool bWow64, out PEB_PARTIAL peb)
        {
            IntPtr pInfoBuffer;
            uint nInfoLength;
            bool bSuccess;

            if (!Environment.Is64BitProcess || bWow64)
                nInfoLength = (uint)Marshal.SizeOf(typeof(PEB32_PARTIAL));
            else
                nInfoLength = (uint)Marshal.SizeOf(typeof(PEB64_PARTIAL));

            pInfoBuffer = Helpers.ReadMemory(hProcess, pPeb, nInfoLength, out uint _);

            if (pInfoBuffer == IntPtr.Zero)
            {
                peb = new PEB_PARTIAL();
                bSuccess = false;
            }
            else
            {
                if (!Environment.Is64BitProcess || bWow64)
                {
                    var peb32 = (PEB32_PARTIAL)Marshal.PtrToStructure(pInfoBuffer, typeof(PEB32_PARTIAL));
                    peb = new PEB_PARTIAL
                    {
                        InheritedAddressSpace = peb32.InheritedAddressSpace,
                        ReadImageFileExecOptions = peb32.ReadImageFileExecOptions,
                        BeingDebugged = peb32.BeingDebugged,
                        Mutant = new IntPtr((int)peb32.Mutant),
                        ImageBaseAddress = new IntPtr((int)peb32.ImageBaseAddress),
                        Ldr = new IntPtr((int)peb32.Ldr),
                        ProcessParameters = new IntPtr((int)peb32.ProcessParameters),
                        SubSystemData = new IntPtr((int)peb32.SubSystemData),
                        ProcessHeap = new IntPtr((int)peb32.ProcessHeap)
                    };
                }
                else
                {
                    peb = (PEB_PARTIAL)Marshal.PtrToStructure(pInfoBuffer, typeof(PEB_PARTIAL));
                }

                Marshal.FreeHGlobal(pInfoBuffer);
                bSuccess = true;
            }

            return bSuccess;
        }


        public static IntPtr GetProcessHandle(ACCESS_MASK accessMask, int pid)
        {
            int nDosErrorCode;
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                accessMask,
                in objectAttributes,
                in clientId);

            if ((ntstatus == Win32Consts.STATUS_SUCCESS) && (accessMask != ACCESS_MASK.MAXIMUM_ALLOWED))
            {
                var nInfoLength = (uint)Marshal.SizeOf(typeof(OBJECT_BASIC_INFORMATION));
                var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryObject(
                    hProcess,
                    OBJECT_INFORMATION_CLASS.ObjectBasicInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    var info = (OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(OBJECT_BASIC_INFORMATION));

                    if ((info.GrantedAccess & accessMask) != accessMask)
                    {
                        ntstatus = Win32Consts.STATUS_ACCESS_DENIED;
                        NativeMethods.NtClose(hProcess);
                    }
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                hProcess = IntPtr.Zero;

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return hProcess;
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
                MagicType magicType;
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
                magicType = (MagicType)Marshal.ReadInt16(pHeaderBuffer, e_lfanew + 0x18);

                if (magicType == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    nExportDirectoryOffset = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x88);
                    nExportDirectorySize = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x8C);
                }
                else if (magicType == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC)
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

                        if (!string.IsNullOrEmpty(Marshal.PtrToStringAnsi(pStringBuffer)))
                            exports.Add(Marshal.PtrToStringAnsi(pStringBuffer), nFunctionOffset);
                    }
                }
            } while (false);

            if (pDirectoryBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pDirectoryBuffer);

            Marshal.FreeHGlobal(pHeaderBuffer);

            return status;
        }


        public static bool ImpersonateAsSmss(
            in List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            bool bSuccess;
            int nSmssId;
            IntPtr hImpersonationToken;

            try
            {
                nSmssId = Process.GetProcessesByName("smss")[0].Id;
            }
            catch
            {
                adjustedPrivs = new Dictionary<SE_PRIVILEGE_ID, bool>();
                NativeMethods.RtlSetLastWin32Error(5); // ERROR_ACCESS_DENIED
                return false;
            }

            hImpersonationToken = Helpers.GetProcessToken(nSmssId, TOKEN_TYPE.Impersonation);

            if (hImpersonationToken == IntPtr.Zero)
            {
                adjustedPrivs = new Dictionary<SE_PRIVILEGE_ID, bool>();
                NativeMethods.RtlSetLastWin32Error(5);

                foreach (var priv in requiredPrivs)
                    adjustedPrivs.Add(priv, false);

                return false;
            }

            Helpers.EnableTokenPrivileges(
                hImpersonationToken,
                in requiredPrivs,
                out adjustedPrivs);
            bSuccess = Helpers.ImpersonateThreadToken(new IntPtr(-2), hImpersonationToken);
            NativeMethods.NtClose(hImpersonationToken);

            return bSuccess;
        }


        public static bool IsSuspiciousProcess(IntPtr hProcess, out string iocString)
        {
            bool bSuspicious = false;
            var pInfoBuffer = IntPtr.Zero;
            iocString = null;

            do
            {
                IntPtr pImageBase;
                string mappedImageName;
                string processImageName;
                string sha256StringRaw;
                string sha256StringMemory;
                bool bIs32BitProcess;
                bool bSuccess = Helpers.GetPebAddress(
                    hProcess,
                    out IntPtr pPeb,
                    out IntPtr pPebWow32);

                if (!bSuccess)
                    break;

                bIs32BitProcess = (!Environment.Is64BitProcess || (pPebWow32 != IntPtr.Zero));

                if (Environment.Is64BitProcess && bIs32BitProcess)
                    pPeb = pPebWow32;

                pImageBase = Helpers.GetImageBaseAddress(hProcess, pPeb, bIs32BitProcess);

                // IoC #1 - Memory allocation type for ImageBaseAddress is not MEM_IMAGE.
                bSuccess = Helpers.GetMemoryBasicInformation(
                    hProcess,
                    pPeb,
                    out MEMORY_BASIC_INFORMATION memoryInfo);

                if (!bSuccess)
                    break;

                if (memoryInfo.Type == MEMORY_ALLOCATION_TYPE.MEM_IMAGE)
                {
                    bSuspicious = true;
                    iocString = "Memory allocation type for ImageBaseAddress is not MEM_IMAGE.";
                    break;
                }

                // IoC #2 - Mapped file name for ImageBaseAddress cannot be specified.
                mappedImageName = Helpers.GetMappedImagePathName(hProcess, pImageBase);

                if (string.IsNullOrEmpty(mappedImageName))
                {
                    bSuspicious = true;
                    iocString = "Mapped file name for ImageBaseAddress cannot be specified.";
                    break;
                }

                // IoC #3 - Process image name cannot be specified.
                processImageName = Helpers.GetProcessImageFileName(hProcess);

                if (string.IsNullOrEmpty(processImageName))
                {
                    bSuspicious = true;
                    iocString = "Process image name cannot be specified.";
                    break;
                }

                // IoC #4 - Mapped file name for ImageBaseAddress does not match with process image name.
                if (string.Compare(mappedImageName, processImageName, true) != 0)
                {
                    bSuspicious = true;
                    iocString = "Mapped file name for ImageBaseAddress does not match with process image name.";
                    break;
                }

                // IoC #5 - Mapped image file for ImageBaseAddress is not found.
                sha256StringRaw = Helpers.GetImageDataDirectoryHash(mappedImageName);

                if (string.IsNullOrEmpty(sha256StringRaw))
                {
                    bSuspicious = true;
                    iocString = "Mapped image file for ImageBaseAddress is not found.";
                    break;
                }

                // IoC #6 - Mapped image file for ImageBaseAddress is different from image file on disk.
                sha256StringMemory = Helpers.GetImageDataDirectoryHash(hProcess, pImageBase);

                if (string.Compare(sha256StringRaw, sha256StringMemory, true) != 0)
                {
                    bSuspicious = true;
                    iocString = "Mapped image file for ImageBaseAddress is different from image file on disk.";
                    break;
                }
            } while (false);

            if (pInfoBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pInfoBuffer);

            return bSuspicious;
        }


        public static void SearchPeHeaderAddress(
            IntPtr hProcess,
            MEMORY_BASIC_INFORMATION mbi,
            ref List<IntPtr> pPeHeaders)
        {
            IntPtr pVerify;
            IntPtr pBufferToRead = Helpers.ReadMemory(
                hProcess,
                mbi.BaseAddress,
                mbi.RegionSize.ToUInt32(),
                out uint _);

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
