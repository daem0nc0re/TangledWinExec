using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using ProcMemScan.Interop;

namespace ProcMemScan.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool DumpMemory(int pid, IntPtr pMemory, uint range)
        {
            IntPtr hProcess;
            var bSuccess = false;
            var outputBuilder = new StringBuilder();

            Console.WriteLine("[>] Trying to dump target process memory.");

            try
            {
                string processName = Process.GetProcessById(pid).ProcessName;
                Console.WriteLine("[*] Target process is '{0}' (PID : {1}).", processName, pid);
            }
            catch
            {
                Console.WriteLine("[-] The specified PID is not found.");
                return false;
            }

            do
            {
                string addressFormat;
                string mappedFileName;
                var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
                var objectAttributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                };
                NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                    out hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    outputBuilder.AppendLine("[-] Faield to open the specified process.");
                    outputBuilder.AppendFormat("    |-> {0}\n", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    hProcess = IntPtr.Zero;
                    break;
                }

                addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
                mappedFileName = Helpers.GetMappedImagePathName(hProcess, pMemory);
                bSuccess = Helpers.GetMemoryBasicInformation(
                    hProcess,
                    pMemory,
                    out MEMORY_BASIC_INFORMATION mbi);

                if (bSuccess)
                {
                    outputBuilder.AppendLine("[+] Got target process memory.");
                    outputBuilder.AppendFormat("    [*] BaseAddress       : 0x{0}\n", mbi.BaseAddress.ToString(addressFormat));
                    outputBuilder.AppendFormat("    [*] AllocationBase    : 0x{0}\n", mbi.AllocationBase.ToString(addressFormat));
                    outputBuilder.AppendFormat("    [*] RegionSize        : 0x{0}\n", mbi.RegionSize.ToUInt64().ToString("X"));
                    outputBuilder.AppendFormat("    [*] AllocationProtect : {0}\n", mbi.AllocationProtect.ToString());
                    outputBuilder.AppendFormat("    [*] State             : {0}\n", mbi.State.ToString());
                    outputBuilder.AppendFormat("    [*] Protect           : {0}\n", mbi.Protect.ToString());
                    outputBuilder.AppendFormat("    [*] Type              : {0}\n", mbi.Type.ToString());
                    outputBuilder.AppendFormat("    [*] Mapped File Path  : {0}\n", mappedFileName ?? "N/A");
                }
                else
                {
                    outputBuilder.AppendLine("[-] Failed to get memory information.");
                    break;
                }

                if (range > 0)
                {
                    ulong nMaxSize = mbi.RegionSize.ToUInt64() - (ulong)(pMemory.ToInt64() - mbi.BaseAddress.ToInt64());

                    if ((ulong)range > nMaxSize)
                        range = (uint)nMaxSize;
                    else if (range == 0)
                        range = (uint)nMaxSize;

                    if ((mbi.Protect == MEMORY_PROTECTION.PAGE_NOACCESS) || (mbi.Protect == MEMORY_PROTECTION.NONE))
                    {
                        outputBuilder.AppendLine("[-] Cannot access the specified page.");
                    }
                    else
                    {
                        IntPtr pBufferToRead = Helpers.ReadMemory(hProcess, pMemory, range, out uint _);

                        if (pBufferToRead == IntPtr.Zero)
                        {
                            outputBuilder.AppendLine("[-] Failed to read the specified memory.");
                        }
                        else
                        {
                            outputBuilder.AppendFormat("    [*] Hexdump (0x{0} Byte(s)):\n\n", range.ToString("X"));
                            outputBuilder.AppendFormat("{0}\n", HexDump.Dump(pBufferToRead, pMemory, range, 2));
                            Marshal.FreeHGlobal(pBufferToRead);
                        }
                    }
                }
            } while (false);

            if (hProcess != IntPtr.Zero)
                NativeMethods.NtClose(hProcess);

            outputBuilder.AppendLine("[*] Done.");
            Console.Write(outputBuilder.ToString());

            return bSuccess;
        }


        public static bool DumpExportItems(int pid, IntPtr pImageBase)
        {
            var bSuccess = false;

            Console.WriteLine("[>] Trying to dump module exports from process memory.");

            try
            {
                string processName = Process.GetProcessById(pid).ProcessName;
                Console.WriteLine("[*] Target process is '{0}' (PID : {1}).", processName, pid);
            }
            catch
            {
                Console.WriteLine("[-] The specified PID is not found.");
                return false;
            }

            do
            {
                string addressFormat = (Environment.Is64BitProcess) ? "X16" : "X8";
                IntPtr hProcess = Utilities.OpenTargetProcess(pid);

                if (hProcess == IntPtr.Zero)
                    break;

                bSuccess = Utilities.GetRemoteModuleExports(
                    hProcess,
                    pImageBase,
                    out IMAGE_FILE_MACHINE architecture,
                    out List<IMAGE_SECTION_HEADER> sectionHeaders,
                    out string exportName,
                    out Dictionary<string, int> exports);
                NativeMethods.NtClose(hProcess);

                if (bSuccess)
                {
                    Console.WriteLine("[+] Got {0} export(s).", exports.Count);
                    Console.WriteLine("    [*] Architecture : {0}", architecture.ToString());
                    Console.WriteLine("    [*] Export Name  : {0}", exportName);
                    
                    if (exports.Count > 0)
                    {
                        Console.WriteLine("    [*] Export Items :");

                        foreach (var section in sectionHeaders)
                        {
                            var tmpExports = new Dictionary<string, int>();

                            foreach (var entry in exports)
                            {
                                var sectionName = Helpers.GetVirtualAddressSection(sectionHeaders, (uint)entry.Value);

                                if (string.Compare(sectionName, section.Name, true) == 0)
                                    tmpExports.Add(entry.Key, entry.Value);
                            }

                            if (tmpExports.Count > 0)
                            {
                                Console.WriteLine("        [*] {0} Section ({1} Item(s)):", section.Name, tmpExports.Count);

                                foreach (var entry in tmpExports)
                                {
                                    IntPtr pBuffer;

                                    if (Environment.Is64BitProcess)
                                        pBuffer = new IntPtr(pImageBase.ToInt64() + entry.Value);
                                    else
                                        pBuffer = new IntPtr(pImageBase.ToInt32() + entry.Value);

                                    Console.WriteLine("            [*] 0x{0} : {1}", pBuffer.ToString(addressFormat), entry.Key);
                                }

                                Console.WriteLine();
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[-] Valid PE image is not found.");
                }
            } while (false);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool ExtractMemory(int pid, IntPtr pMemory, uint range)
        {
            IntPtr hProcess;
            ulong nMaxSize;
            int index = 0;
            bool bSuccess;
            IntPtr pBufferToRead = IntPtr.Zero;
            IntPtr hFile = Win32Consts.INVALID_HANDLE_VALUE;
            string addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";

            Console.WriteLine("[>] Trying to extract target process memory.");

            try
            {
                string processName = Process.GetProcessById(pid).ProcessName;
                Console.WriteLine("[*] Target process is '{0}' (PID : {1}).", processName, pid);
            }
            catch
            {
                Console.WriteLine("[-] The specified PID is not found.");

                return false;
            }

            hProcess = Utilities.OpenTargetProcess(pid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open target process.");

                return false;
            }

            do
            {
                string mappedFileName = Helpers.GetMappedImagePathName(hProcess, pMemory);
                bSuccess = Helpers.GetMemoryBasicInformation(
                    hProcess,
                    pMemory,
                    out MEMORY_BASIC_INFORMATION mbi);

                if (bSuccess)
                {
                    Console.WriteLine("[+] Got target process memory.");
                    Console.WriteLine("    [*] BaseAddress       : 0x{0}", mbi.BaseAddress.ToString(addressFormat));
                    Console.WriteLine("    [*] AllocationBase    : 0x{0}", mbi.AllocationBase.ToString(addressFormat));
                    Console.WriteLine("    [*] RegionSize        : 0x{0}", mbi.RegionSize.ToUInt64().ToString("X"));
                    Console.WriteLine("    [*] AllocationProtect : {0}", mbi.AllocationProtect.ToString());
                    Console.WriteLine("    [*] State             : {0}", mbi.State.ToString());
                    Console.WriteLine("    [*] Protect           : {0}", mbi.Protect.ToString());
                    Console.WriteLine("    [*] Type              : {0}", mbi.Type.ToString());
                    Console.WriteLine("    [*] Mapped File Path  : {0}", string.IsNullOrEmpty(mappedFileName) ? "N/A" : mappedFileName);

                    nMaxSize = mbi.RegionSize.ToUInt64() - (ulong)(pMemory.ToInt64() - mbi.BaseAddress.ToInt64());

                    if ((ulong)range > nMaxSize)
                        range = (uint)nMaxSize;
                    else if (range == 0)
                        range = (uint)nMaxSize;

                    pBufferToRead = Helpers.ReadMemory(hProcess, pMemory, range, out uint _);

                    if (pBufferToRead == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to read the specified memory.");
                    }
                    else
                    {
                        string filePath = string.Format("memory-0x{0}-0x{1}bytes.bin",
                            pMemory.ToString(addressFormat),
                            range.ToString("X"));
                        filePath = Path.GetFullPath(filePath);

                        while (File.Exists(filePath))
                        {
                            filePath = string.Format("memory-0x{0}-0x{1}bytes_{2}.bin",
                                pMemory.ToString(addressFormat),
                                range.ToString("X"),
                                index);
                            filePath = Path.GetFullPath(filePath);
                            index++;
                        }

                        Console.WriteLine("[>] Trying to export the specified memory.");
                        Console.WriteLine("    [*] File Path : {0}", filePath);

                        hFile = Helpers.CreateExportFile(filePath);

                        if (hFile == Win32Consts.INVALID_HANDLE_VALUE)
                        {
                            Console.WriteLine("[-] Failed to create file.");
                            break;
                        }

                        bSuccess = Helpers.WriteDataIntoFile(hFile, pBufferToRead, range);

                        if (!bSuccess)
                            Console.WriteLine("[-] Failed to write data into file.");
                        else
                            Console.WriteLine("[+] Memory is extracted successfully.");
                    }
                }
                else
                {
                    Console.WriteLine("[-] Failed to get memory information.");
                }
            } while (false);

            if (pBufferToRead != IntPtr.Zero)
                Marshal.FreeHGlobal(pBufferToRead);

            if (hFile != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hFile);

            NativeMethods.NtClose(hProcess);

            return bSuccess;
        }


        public static bool ExtractPeImageFile(int pid, IntPtr pImageDosHeader)
        {
            IntPtr hProcess;
            IntPtr pNtHeader;
            IntPtr pSectionHeader;
            string processName;
            string mappedFileName;
            string filePath;
            string suffixImageName;
            int bitness;
            int nSectionCount;
            int nOptionalHeaderOffset;
            IMAGE_DOS_HEADER imageDosHeader;
            IMAGE_NT_HEADERS32 ntHeader32;
            IMAGE_NT_HEADERS64 ntHeader64;
            IMAGE_SECTION_HEADER sectionHeader;
            IMAGE_FILE_MACHINE imageMachine;
            uint nSizeOfPeHeader;
            int index = 0;
            bool status = false;
            IntPtr pBufferToRead = IntPtr.Zero;
            IntPtr hFile = Win32Consts.INVALID_HANDLE_VALUE;
            string addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";
            var sectionHeaderList = new List<IMAGE_SECTION_HEADER>();

            Console.WriteLine("[>] Trying to extract PE image file from target process memory.");

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] The specified PID is not found.");

                return false;
            }

            Console.WriteLine("[*] Target process is '{0}' (PID : {1}).", processName, pid);

            hProcess = Utilities.OpenTargetProcess(pid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open target process.");

                return false;
            }

            do
            {
                mappedFileName = Helpers.GetMappedImagePathName(hProcess, pImageDosHeader);

                if (!Helpers.GetMemoryBasicInformation(
                    hProcess,
                    pImageDosHeader,
                    out MEMORY_BASIC_INFORMATION mbi))
                {
                    Console.WriteLine("[-] Failed to get memory information");
                    break;
                }

                pBufferToRead = Helpers.ReadMemory(
                    hProcess,
                    pImageDosHeader,
                    mbi.RegionSize.ToUInt32(),
                    out uint _);

                if (pBufferToRead == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to read memory.");
                    break;
                }

                imageDosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                    pBufferToRead,
                    typeof(IMAGE_DOS_HEADER));

                if (!imageDosHeader.IsValid)
                {
                    Console.WriteLine("[-] Failed to find ntdll!_IMAGE_DOS_HEADER.");
                    break;
                }

                pNtHeader = new IntPtr(pBufferToRead.ToInt64() + imageDosHeader.e_lfanew);
                imageMachine = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(new IntPtr(pNtHeader.ToInt64() + Marshal.SizeOf(typeof(int))));
                bitness = Helpers.GetArchitectureBitness(imageMachine);

                if (bitness == 64)
                {
                    ntHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                        pNtHeader,
                        typeof(IMAGE_NT_HEADERS64));
                    nOptionalHeaderOffset = Marshal.OffsetOf(
                        typeof(IMAGE_NT_HEADERS64),
                        "OptionalHeader").ToInt32();
                    pSectionHeader = new IntPtr(pNtHeader.ToInt64() + nOptionalHeaderOffset + ntHeader64.FileHeader.SizeOfOptionalHeader);
                    nSectionCount = (int)ntHeader64.FileHeader.NumberOfSections;
                }
                else if (bitness == 32)
                {
                    ntHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                        pNtHeader,
                        typeof(IMAGE_NT_HEADERS32));
                    nOptionalHeaderOffset = Marshal.OffsetOf(
                        typeof(IMAGE_NT_HEADERS32),
                        "OptionalHeader").ToInt32();
                    pSectionHeader = new IntPtr(pNtHeader.ToInt64() + nOptionalHeaderOffset + ntHeader32.FileHeader.SizeOfOptionalHeader);
                    nSectionCount = (int)ntHeader32.FileHeader.NumberOfSections;
                }
                else
                {
                    Console.WriteLine("[-] Unsupported architecture is detected.");
                    break;
                }

                if (nSectionCount == 0)
                {
                    Console.WriteLine("[-] No sections found.");
                    break;
                }

                for (var count = 0; count < nSectionCount; count++)
                {
                    sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        new IntPtr(pSectionHeader.ToInt64() + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * count)),
                        typeof(IMAGE_SECTION_HEADER));
                    sectionHeaderList.Add(sectionHeader);
                }

                if (string.IsNullOrEmpty(mappedFileName))
                    suffixImageName = "Unknown";
                else
                    suffixImageName = Path.GetFileName(mappedFileName).Replace('.', '_');
                filePath = string.Format(
                    "image-0x{0}-{1}-{2}.bin",
                    pImageDosHeader.ToString(addressFormat),
                    suffixImageName,
                    imageMachine.ToString());
                filePath = Path.GetFullPath(filePath);

                while (File.Exists(filePath))
                {
                    filePath = string.Format(
                        "image-0x{0}-{1}-{2}_{3}.bin",
                        pImageDosHeader.ToString(addressFormat),
                        suffixImageName,
                        imageMachine.ToString(),
                        index);
                    filePath = Path.GetFullPath(filePath);

                    index++;
                }

                Console.WriteLine("[>] Trying to export the specified memory.");
                Console.WriteLine("    [*] File Path          : {0}", filePath);
                Console.WriteLine("    [*] Image Architecture : {0}", imageMachine.ToString());

                nSizeOfPeHeader = sectionHeaderList[0].PointerToRawData;
                hFile = Helpers.CreateExportFile(filePath);

                if (hFile == Win32Consts.INVALID_HANDLE_VALUE)
                {
                    Console.WriteLine("[-] Failed to create export file.");
                    break;
                }

                status = Helpers.WriteDataIntoFile(hFile, pBufferToRead, nSizeOfPeHeader);
                Marshal.FreeHGlobal(pBufferToRead);
                pBufferToRead = IntPtr.Zero;

                if (!status)
                {
                    Console.WriteLine("[-] Failed to write data into file.");
                    break;
                }

                foreach (var section in sectionHeaderList)
                {
                    pBufferToRead = Helpers.ReadMemory(
                        hProcess,
                        new IntPtr(pImageDosHeader.ToInt64() + section.VirtualAddress),
                        section.SizeOfRawData,
                        out uint _);

                    if (pBufferToRead == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to read {0} section data.", section.Name);
                        break;
                    }

                    status = Helpers.WriteDataIntoFile(hFile, pBufferToRead, section.SizeOfRawData);
                    Marshal.FreeHGlobal(pBufferToRead);
                    pBufferToRead = IntPtr.Zero;

                    if (!status)
                    {
                        Console.WriteLine("[-] Failed to write data into file.");
                        break;
                    }
                }

                if (status)
                    Console.WriteLine("[+] Image file is extracted successfully.");
            } while (false);

            if (pBufferToRead != IntPtr.Zero)
                Marshal.FreeHGlobal(pBufferToRead);

            if (hFile != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hFile);

            NativeMethods.NtClose(hProcess);

            return status;
        }


        public static bool GetProcessInformation(int pid)
        {
            IntPtr hProcess;
            bool bSuccess;

            Console.WriteLine("[>] Trying to get target process information.");

            try
            {
                var processName = Process.GetProcessById(pid).ProcessName;
                Console.WriteLine("[*] Target process is '{0}' (PID : {1}).", processName, pid);
            }
            catch
            {
                Console.WriteLine("[-] The specified PID is not found.");
                return false;
            }

            hProcess = Utilities.OpenTargetProcess(pid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open target process.");
                return false;
            }

            do
            {
                string output;
                bSuccess = Helpers.GetPebAddress(hProcess, out IntPtr pPeb, out IntPtr pPebWow32);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to get PEB address.");
                    break;
                }

                if (pPebWow32 != IntPtr.Zero)
                {
                    output = Utilities.DumpPebInformation(hProcess, pPebWow32, true);
                    Console.Write("\nWOW {0}\n", output);

                    output = Utilities.DumpPebInformation(hProcess, pPeb, false);
                    Console.Write("\nWOW {0}\n", output);
                }
                else
                {
                    output = Utilities.DumpPebInformation(hProcess, pPeb, false);
                    Console.Write("\n{0}\n", output);
                }
            } while (false);

            NativeMethods.NtClose(hProcess);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool GetProcessMemoryInformation(int pid)
        {
            string processName;
            IntPtr hProcess;
            List<MEMORY_BASIC_INFORMATION> memoryTable;

            Console.WriteLine("[>] Trying to get target process memory information.");

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] The specified PID is not found.");

                return false;
            }

            Console.WriteLine(@"[*] Target process is '{0}' (PID : {1}).", processName, pid);

            hProcess = Utilities.OpenTargetProcess(pid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open target process.");
                return false;
            }

            do
            {
                memoryTable = Helpers.EnumMemoryBasicInformation(hProcess);

                if (memoryTable.Count > 0)
                {
                    Console.WriteLine("[+] Got target process memory information.\n");
                    Console.WriteLine(Utilities.DumpMemoryBasicInformation(hProcess, memoryTable));
                }
                else
                {
                    Console.WriteLine("[-] Failed to get target process memory information.");
                }
            } while (false);
            
            NativeMethods.NtClose(hProcess);

            Console.WriteLine("[*] Done.");

            return true;
        }


        public static Dictionary<int, KeyValuePair<string, string>> ScanAllProcesses()
        {
            var suspiciousProcesses = new Dictionary<int, KeyValuePair<string, string>>();

            Console.WriteLine("[>] Scanning all processes...");

            foreach (Process process in Process.GetProcesses())
            {
                bool bSuspicious;
                string processName = process.ProcessName;
                var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(process.Id) };
                var objectAttributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                };
                NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                    out IntPtr hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    continue;

                bSuspicious = Utilities.IsSuspiciousProcess(hProcess, out string iocString);
                NativeMethods.NtClose(hProcess);

                if (bSuspicious)
                    suspiciousProcesses.Add(process.Id, new KeyValuePair<string, string>(processName, iocString));
            }

            if (suspiciousProcesses.Count > 0)
            {
                string lineFormat;
                var columnNames = new string[] { "PID", "Process Name", "Reason" };
                var columnWidth = new int[] { 3, 12, 6 };
                var outputBuilder = new StringBuilder();

                foreach (var process in suspiciousProcesses)
                {
                    if (process.Key.ToString().Length > columnWidth[0])
                        columnWidth[0] = process.Key.ToString().Length;

                    if (process.Value.Key.Length > columnWidth[1])
                        columnWidth[1] = process.Value.Key.Length;
                }

                lineFormat = string.Format("{{0, {0}}} {{1, -{1}}} {{2}}\n", columnWidth[0], columnWidth[1]);
                outputBuilder.AppendLine("\nSUSPICIOUS PROCESSES");
                outputBuilder.AppendLine("--------------------\n");
                outputBuilder.AppendFormat(lineFormat, columnNames[0], columnNames[1], columnNames[2]);
                outputBuilder.AppendFormat(lineFormat,
                    new string('=', columnWidth[0]),
                    new string('=', columnWidth[1]),
                    new string('=', columnWidth[2]));

                foreach (var process in suspiciousProcesses)
                    outputBuilder.AppendFormat(lineFormat, process.Key, process.Value.Key, process.Value.Value);

                outputBuilder.AppendFormat("\n[!] Found {0} suspicious process(es).\n", suspiciousProcesses.Count);

                Console.Write(outputBuilder.ToString());
            }
            {
                Console.WriteLine("[*] No suspicious processes.");
            }

            return suspiciousProcesses;
        }


        public static bool ScanProcess(int pid)
        {
            bool bSuspicious = false;
            Console.WriteLine("[>] Trying to scan target process.");

            do
            {
                NTSTATUS ntstatus;
                var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
                var objectAttributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
                };

                try
                {
                    string processName = Process.GetProcessById(pid).ProcessName;
                    Console.WriteLine(@"[*] Target process is '{0}' (PID : {1}).", processName, pid);
                }
                catch
                {
                    Console.WriteLine("[-] The specified PID is not found.");
                    break;
                }

                ntstatus = NativeMethods.NtOpenProcess(
                    out IntPtr hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION | ACCESS_MASK.PROCESS_VM_READ,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Faield to open the specified process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }

                bSuspicious = Utilities.IsSuspiciousProcess(hProcess, out string iocString);
                NativeMethods.NtClose(hProcess);

                if (bSuspicious)
                {
                    Console.WriteLine("[!] The specified process is suspicious.");
                    Console.WriteLine("    [*] IoC : {0}", iocString);
                }
                else
                {
                    Console.WriteLine("[*] The specified process seems benign.");
                }
            } while (false);

            Console.WriteLine("[*] Done.");

            return bSuspicious;
        }
    }
}
