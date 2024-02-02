using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using ProcMemScan.Interop;

namespace ProcMemScan.Library
{
    internal class Modules
    {
        public static bool DumpMemory(int pid, IntPtr pMemory, uint range)
        {
            bool bSuccess;
            IntPtr hProcess;

            Console.WriteLine("[>] Trying to dump target process memory.");

            try
            {
                string processName = Process.GetProcessById(pid).ProcessName;
                Console.WriteLine(@"[*] Target process is '{0}' (PID : {1}).", processName, pid);
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
                string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
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
                    Console.WriteLine("    [*] Mapped File Path  : {0}", mappedFileName ?? "N/A");
                }
                else
                {
                    Console.WriteLine("[-] Failed to get memory information.");
                    break;
                }

                if (range > 0)
                {
                    ulong nMaxSize = mbi.RegionSize.ToUInt64() - (ulong)(pMemory.ToInt64() - mbi.BaseAddress.ToInt64());

                    if ((ulong)range > nMaxSize)
                        range = (uint)nMaxSize;
                    else if (range == 0)
                        range = (uint)nMaxSize;

                    if ((mbi.Protect == MEMORY_PROTECTION.PAGE_NOACCESS) ||
                        (mbi.Protect == MEMORY_PROTECTION.NONE))
                    {
                        Console.WriteLine("[-] Cannot access the specified page.");
                    }
                    else
                    {
                        IntPtr pBufferToRead = Helpers.ReadMemory(hProcess, pMemory, range);

                        if (pBufferToRead == IntPtr.Zero)
                        {
                            Console.WriteLine("[-] Failed to read the specified memory.");
                        }
                        else
                        {
                            if (range == 1)
                                Console.WriteLine("    [*] Hexdump (0x1 Byte):\n");
                            else
                                Console.WriteLine("    [*] Hexdump (0x{0} Bytes):\n", range.ToString("X"));

                            HexDump.Dump(pBufferToRead, pMemory, range, 2);
                            Console.WriteLine();

                            Marshal.FreeHGlobal(pBufferToRead);
                        }
                    }
                }
            } while (false);

            NativeMethods.NtClose(hProcess);

            Console.WriteLine("[*] Done.");

            return bSuccess;
        }


        public static bool DumpExportItems(int pid, IntPtr pImageBase)
        {
            IntPtr hProcess;
            string processName;
            string addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";
            var status = false;

            Console.WriteLine("[>] Trying to dump module exports from process memory.");

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

            do
            {
                hProcess = Utilities.OpenTargetProcess(pid);

                if (hProcess == IntPtr.Zero)
                    break;

                status = Utilities.GetRemoteModuleExports(
                    hProcess,
                    pImageBase,
                    out IMAGE_FILE_MACHINE architecture,
                    out List<IMAGE_SECTION_HEADER> sectionHeaders,
                    out string exportName,
                    out Dictionary<string, int> exports);
                NativeMethods.NtClose(hProcess);

                if (status)
                {
                    Console.WriteLine("[+] Got {0} export(s).", exports.Count);
                    Console.WriteLine("    [*] Architecture : {0}", architecture.ToString());
                    Console.WriteLine("    [*] Export Name  : {0}", string.IsNullOrEmpty(exportName) ? "N/A" : exportName);
                    
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

            return status;
        }


        public static bool ExtractMemory(int pid, IntPtr pMemory, uint range)
        {
            IntPtr hProcess;
            ulong nMaxSize;
            string processName;
            string mappedFileName;
            string filePath;
            int index = 0;
            bool status;
            IntPtr pBufferToRead = IntPtr.Zero;
            IntPtr hFile = Win32Consts.INVALID_HANDLE_VALUE;
            string addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";

            Console.WriteLine("[>] Trying to extract target process memory.");

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
                status = Helpers.GetMemoryBasicInformation(
                    hProcess,
                    pMemory,
                    out MEMORY_BASIC_INFORMATION mbi);
                mappedFileName = Helpers.GetMappedImagePathName(hProcess, pMemory);

                if (status)
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

                    pBufferToRead = Helpers.ReadMemory(hProcess, pMemory, range);

                    if (pBufferToRead == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to read the specified memory.");
                    }
                    else
                    {
                        filePath = string.Format(
                            "memory-0x{0}-0x{1}bytes.bin",
                            pMemory.ToString(addressFormat),
                            range.ToString("X"));
                        filePath = Path.GetFullPath(filePath);

                        while (File.Exists(filePath))
                        {
                            filePath = string.Format(
                                "memory-0x{0}-0x{1}bytes_{2}.bin",
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

                        status = Helpers.WriteDataIntoFile(hFile, pBufferToRead, range);

                        if (!status)
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

            return status;
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

                pBufferToRead = Helpers.ReadMemory(hProcess, pImageDosHeader, mbi.RegionSize.ToUInt32());

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
                        section.SizeOfRawData);

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
                bSuccess = Helpers.GetPebAddress(hProcess, out IntPtr pPeb, out IntPtr pPebWow64);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to get PEB address.");
                    break;
                }

                if (pPebWow64 != IntPtr.Zero)
                {
                    output = Utilities.DumpPebInformation(hProcess, pPebWow64, true);
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


        public static bool ScanSuspiciousProcess(int pid)
        {
            IntPtr hProcess;
            RTL_USER_PROCESS_PARAMETERS processParameters;
            List<MEMORY_BASIC_INFORMATION> memoryTable;
            string imagePathName;
            string commandLine;
            IntPtr pProcessParametersData = IntPtr.Zero;
            string imageBaseMappedFile;
            string commandLineImagePathName;
            bool bSuspicious = false;
            var results = new StringBuilder();
            var pPeHeaders = new List<IntPtr>();

            Console.WriteLine("[>] Trying to scan target process.");

            try
            {
                string processName = Process.GetProcessById(pid).ProcessName;
                Console.WriteLine(@"[*] Target process is '{0}' (PID : {1}).", processName, pid);
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
                /*
                 * Collect process information
                 */
                bool bSuccess = Helpers.GetPebAddress(hProcess, out IntPtr pPeb, out IntPtr pPebWow64);

                if (!bSuccess)
                {
                    Console.WriteLine("[-] Failed to get ntdll!_PEB address.");
                    break;
                }

                if (pPebWow64 != IntPtr.Zero)
                    pPeb = pPebWow64;

                if (!Utilities.GetPebPartialData(hProcess, pPeb, out PEB_PARTIAL peb))
                {
                    Console.WriteLine("[-] Failed to get ntdll!_PEB data.");

                    break;
                }

                imageBaseMappedFile = Helpers.GetMappedImagePathName(hProcess, peb.ImageBaseAddress);
                pProcessParametersData = Helpers.GetProcessParameters(hProcess, pPeb, (pPebWow64 != IntPtr.Zero));

                if (pProcessParametersData != IntPtr.Zero)
                {
                    processParameters = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(
                        pProcessParametersData,
                        typeof(RTL_USER_PROCESS_PARAMETERS));
                    imagePathName = Helpers.ReadRemoteUnicodeString(
                        hProcess,
                        processParameters.ImagePathName);
                    commandLine = Helpers.ReadRemoteUnicodeString(
                        hProcess,
                        processParameters.CommandLine);
                }
                else
                {
                    imagePathName = null;
                    commandLine = null;
                }

                memoryTable = Helpers.EnumMemoryBasicInformation(hProcess);

                foreach (var mbi in memoryTable)
                {
                    if (Helpers.IsReadableAddress(hProcess, mbi.BaseAddress))
                        Utilities.SearchPeHeaderAddress(hProcess, mbi, ref pPeHeaders);
                }

                /*
                 * Analyze data
                 */
                // Check ntdll!_PEB.ImageBaseAddress
                Helpers.GetMemoryBasicInformation(
                    hProcess,
                    peb.ImageBaseAddress,
                    out MEMORY_BASIC_INFORMATION mbiImageBaseAddress);

                if (mbiImageBaseAddress.Type != MEMORY_ALLOCATION_TYPE.MEM_IMAGE)
                {
                    bSuspicious = true;
                    results.Append("    [!] ntdll!_PEB.ImageBaseAddress does not point to MEM_IMAGE region.\n");
                }

                if (string.IsNullOrEmpty(imageBaseMappedFile))
                {
                    bSuspicious = true;
                    results.Append("    [!] Cannot specify mapped file for ntdll!_PEB.ImageBaseAddress.\n");
                }
                else
                {
                    if (string.Compare(
                        imageBaseMappedFile,
                        imagePathName,
                        StringComparison.OrdinalIgnoreCase) != 0)
                    {
                        bSuspicious = true;
                        results.Append("    [!] The mapped file for ntdll!_PEB.ImageBaseAddress does not match ProcessParameters.ImagePathName.\n");
                        results.Append(string.Format("        [*] Mapped File for ImageBaseAddress : {0}\n", imageBaseMappedFile));
                        results.Append(string.Format("        [*] ProcessParameters.ImagePathName  : {0}\n", imagePathName));
                    }

                    if (!File.Exists(imageBaseMappedFile))
                    {
                        bSuspicious = true;
                        results.Append("    [!] The mapped file for ntdll!_PEB.ImageBaseAddress does not exist.\n");
                        results.Append(string.Format("        [*] Mapped File for ImageBaseAddress : {0}\n", imageBaseMappedFile));
                    }
                }

                // Check ProcessParameters
                commandLineImagePathName = Helpers.ResolveImagePathName(commandLine);

                if (string.Compare(
                    commandLineImagePathName,
                    imagePathName,
                    StringComparison.OrdinalIgnoreCase) != 0)
                {
                    bSuspicious = true;
                    results.Append("[!] The image path for ProcessParameters.CommandLine does not match ProcessParameters.ImagePathName.\n");
                    results.Append(string.Format("        [*] ProcessParameters.ImagePathName : {0}\n", imagePathName));
                    results.Append(string.Format("        [*] ProcessParameters.CommandLine   : {0}\n", commandLineImagePathName));
                }
            } while (false);

            if (pProcessParametersData != IntPtr.Zero)
                Marshal.FreeHGlobal(pProcessParametersData);

            NativeMethods.NtClose(hProcess);

            if (bSuspicious)
                Console.WriteLine("[!] Found suspicious things:\n{0}", results.ToString().TrimEnd('\n'));
            else
                Console.WriteLine("[*] Suspicious things are not found.");

            Console.WriteLine("[*] Done.");

            return bSuspicious;
        }
    }
}
