using System;
using System.Text;
using System.Runtime.InteropServices;
using CommandLineSpoofing.Interop;

namespace CommandLineSpoofing.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static bool CreateSuspendedProcess(
            string command,
            out PROCESS_INFORMATION processInfo)
        {
            bool status;
            var startupInfo = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO))
            };

            status = NativeMethods.CreateProcess(
                null,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                ProcessCreationFlags.CREATE_SUSPENDED,
                IntPtr.Zero,
                Environment.CurrentDirectory,
                ref startupInfo,
                out processInfo);

            return status;
        }


        public static void RebaseProcessParameters(
            IntPtr pLocalProcessParameters,
            IntPtr pRemoteProcessParameters,
            bool toLocalPointers)
        {
            long nOffset;
            var processParameters = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(
                pLocalProcessParameters,
                typeof(RTL_USER_PROCESS_PARAMETERS));
            ulong nSizeBuffer = processParameters.MaximumLength + processParameters.EnvironmentSize;
            IntPtr pEnvironment = processParameters.Environment;
            IntPtr pCurdirBuffer = processParameters.CurrentDirectory.DosPath.GetBuffer();
            IntPtr pDllPathBuffer = processParameters.DllPath.GetBuffer();
            IntPtr pImagePathNameBuffer = processParameters.ImagePathName.GetBuffer();
            IntPtr pCommandLineBuffer = processParameters.CommandLine.GetBuffer();
            IntPtr pWindowTitleBuffer = processParameters.WindowTitle.GetBuffer();
            IntPtr pDesktopInfoBuffer = processParameters.DesktopInfo.GetBuffer();
            IntPtr pShellInfoBuffer = processParameters.ShellInfo.GetBuffer();
            IntPtr pRuntimeDataBuffer = processParameters.RuntimeData.GetBuffer();
            IntPtr pRedirectionDllNameBuffer = processParameters.RedirectionDllName.GetBuffer();
            IntPtr pHeapPartitionNameBuffer = processParameters.HeapPartitionName.GetBuffer();

            if (toLocalPointers)
                nOffset = pLocalProcessParameters.ToInt64() - pRemoteProcessParameters.ToInt64();
            else
                nOffset = pRemoteProcessParameters.ToInt64() - pLocalProcessParameters.ToInt64();

            if ((ulong)(pEnvironment.ToInt64() - pLocalProcessParameters.ToInt64()) < nSizeBuffer)
                processParameters.Environment = new IntPtr(pEnvironment.ToInt64() + nOffset);

            if (pCurdirBuffer != IntPtr.Zero)
                processParameters.CurrentDirectory.DosPath.SetBuffer(new IntPtr(pCurdirBuffer.ToInt64() + nOffset));

            if (pDllPathBuffer != IntPtr.Zero)
                processParameters.DllPath.SetBuffer(new IntPtr(pDllPathBuffer.ToInt64() + nOffset));

            if (pImagePathNameBuffer != IntPtr.Zero)
                processParameters.ImagePathName.SetBuffer(new IntPtr(pImagePathNameBuffer.ToInt64() + nOffset));

            if (pCommandLineBuffer != IntPtr.Zero)
                processParameters.CommandLine.SetBuffer(new IntPtr(pCommandLineBuffer.ToInt64() + nOffset));

            if (pWindowTitleBuffer != IntPtr.Zero)
                processParameters.WindowTitle.SetBuffer(new IntPtr(pWindowTitleBuffer.ToInt64() + nOffset));

            if (pDesktopInfoBuffer != IntPtr.Zero)
                processParameters.DesktopInfo.SetBuffer(new IntPtr(pDesktopInfoBuffer.ToInt64() + nOffset));

            if (pShellInfoBuffer != IntPtr.Zero)
                processParameters.ShellInfo.SetBuffer(new IntPtr(pShellInfoBuffer.ToInt64() + nOffset));

            if (pRuntimeDataBuffer != IntPtr.Zero)
                processParameters.RuntimeData.SetBuffer(new IntPtr(pRuntimeDataBuffer.ToInt64() + nOffset));

            if (pRedirectionDllNameBuffer != IntPtr.Zero)
                processParameters.RedirectionDllName.SetBuffer(new IntPtr(pRedirectionDllNameBuffer.ToInt64() + nOffset));

            if (pHeapPartitionNameBuffer != IntPtr.Zero)
                processParameters.HeapPartitionName.SetBuffer(new IntPtr(pHeapPartitionNameBuffer.ToInt64() + nOffset));

            for (var idx = 0; idx < 32; idx++)
            {
                pCurdirBuffer = processParameters.CurrentDirectores[idx].DosPath.GetBuffer();

                if (pCurdirBuffer != IntPtr.Zero)
                {
                    processParameters.CurrentDirectores[idx].DosPath.SetBuffer(
                        new IntPtr(pCurdirBuffer.ToInt64() + nOffset));
                }
            }

            Marshal.StructureToPtr(processParameters, pLocalProcessParameters, true);
        }


        public static bool SetCommandLineSpoofedParameters(
            IntPtr hSuspendedProcess,
            string imagePathName,
            string commandLineOriginal,
            string commandLineExecute,
            string windowTitle)
        {
            bool status;
            IntPtr pPeb;
            IntPtr pProcessParameters;
            IntPtr pEnvironment;
            IntPtr pReadBuffer;
            int nOffsetCommandline = Marshal.OffsetOf(
                typeof(RTL_USER_PROCESS_PARAMETERS),
                "CommandLine").ToInt32();
            int nOffsetEnvironment = Marshal.OffsetOf(
                typeof(RTL_USER_PROCESS_PARAMETERS),
                "Environment").ToInt32();
            int nSizeUnicodeString = Marshal.SizeOf(typeof(UNICODE_STRING));
            UNICODE_STRING originalCommandline;
            IntPtr pRemoteProcessParameters;

            pPeb = Helpers.GetPebAddress(hSuspendedProcess);

            if (pPeb == IntPtr.Zero)
                return false;

            pProcessParameters = Helpers.GetProcessParametersAddress(hSuspendedProcess, pPeb);

            if (pProcessParameters == IntPtr.Zero)
                return false;

            // Read ntdll!_RTL_USER_PROCESS_PARAMETERS.Environment
            pReadBuffer = Helpers.ReadMemory(
                hSuspendedProcess,
                new IntPtr(pProcessParameters.ToInt64() + nOffsetEnvironment),
                IntPtr.Size);

            if (pReadBuffer == IntPtr.Zero)
                return false;

            pEnvironment = Marshal.ReadIntPtr(pReadBuffer);
            Marshal.FreeHGlobal(pReadBuffer);

            // Read ntdll!_RTL_USER_PROCESS_PARAMETERS.CommandLine
            pReadBuffer = Helpers.ReadMemory(
                hSuspendedProcess,
                new IntPtr(pProcessParameters.ToInt64() + nOffsetCommandline),
                nSizeUnicodeString);

            if (pReadBuffer == IntPtr.Zero)
                return false;

            originalCommandline = (UNICODE_STRING)Marshal.PtrToStructure(
                pReadBuffer,
                typeof(UNICODE_STRING));
            Marshal.FreeHGlobal(pReadBuffer);

            // Read string pointed by ntdll!_RTL_USER_PROCESS_PARAMETERS.CommandLine.Buffer
            pReadBuffer = Helpers.ReadMemory(
                hSuspendedProcess,
                originalCommandline.GetBuffer(),
                (uint)originalCommandline.MaximumLength);

            if (pReadBuffer == IntPtr.Zero)
                return false;

            Console.WriteLine("[*] ntdll!_RTL_USER_PROCESS_PARAMETERS.CommandLine");
            Console.WriteLine("    |-> Length        : 0x{0}", originalCommandline.Length.ToString("X"));
            Console.WriteLine("    |-> MaximumLength : 0x{0}", originalCommandline.MaximumLength.ToString("X"));
            Console.WriteLine("    |-> Buffer        : {0}", Marshal.PtrToStringUni(pReadBuffer));
            Marshal.FreeHGlobal(pReadBuffer);

            // Write new ntdll!_RTL_USER_PROCESS_PARAMETERS to remote process
            if (commandLineOriginal.Length > commandLineExecute.Length)
            {
                pRemoteProcessParameters = SetProcessParameters(
                    hSuspendedProcess,
                    imagePathName,
                    commandLineOriginal,
                    Environment.CurrentDirectory,
                    windowTitle);
            }
            else
            {
                pRemoteProcessParameters = SetProcessParameters(
                    hSuspendedProcess,
                    imagePathName,
                    commandLineExecute,
                    Environment.CurrentDirectory,
                    windowTitle);
            }

            if (pRemoteProcessParameters == IntPtr.Zero)
                return false;

            if (commandLineOriginal.Length > commandLineExecute.Length)
                UpdateCommandLine(hSuspendedProcess, commandLineExecute);

            // Overwrite ntdll!_PEB.ProcessParameters
            status = Helpers.SetProcessParametersAddress(
                hSuspendedProcess,
                pPeb,
                pRemoteProcessParameters);

            return status;
        }


        public static IntPtr SetProcessParameters(
            IntPtr hProcess,
            string imagePathName,
            string commandLine,
            string currentDirectory,
            string windowTitle)
        {
            NTSTATUS ntstatus;
            bool status;
            IntPtr pPeb;
            IntPtr pRemoteProcessParametersPointer;
            IntPtr pRemoteProcessParameters;
            IntPtr pRemoteEnvironment;
            IntPtr pLocalEnvironmentPointer;
            IntPtr pDataBuffer;
            int nSizeParameters;
            int nSizeEnvironment;
            int nSizeBuffer;
            int nOffsetProcessParameters;
            int nOffsetEnvironment;
            int nOffsetEnvironmentSize;
            string winDir = Environment.GetEnvironmentVariable("windir");
            var unicodeImagePathName = new UNICODE_STRING(imagePathName);
            var unicodeCommandline = new UNICODE_STRING(commandLine);
            var unicodeCurrentDirectory = new UNICODE_STRING(currentDirectory);
            var unicodeWindowTitle = new UNICODE_STRING(windowTitle);
            var dllPath = new UNICODE_STRING(string.Format(@"{0}\System32", winDir));
            var desktopInfo = new UNICODE_STRING(@"WinSta0\Default");

            pPeb = Helpers.GetPebAddress(hProcess);

            if (pPeb == IntPtr.Zero)
                return IntPtr.Zero;

            nOffsetEnvironment = Marshal.OffsetOf(
                typeof(RTL_USER_PROCESS_PARAMETERS),
                "Environment").ToInt32();
            nOffsetEnvironmentSize = Marshal.OffsetOf(
                    typeof(RTL_USER_PROCESS_PARAMETERS),
                    "EnvironmentSize").ToInt32();

            if (IntPtr.Size == 4)
            {
                nOffsetProcessParameters = Marshal.OffsetOf(
                    typeof(PEB32_PARTIAL),
                    "ProcessParameters").ToInt32();
                pRemoteProcessParametersPointer = new IntPtr(
                    pPeb.ToInt32() + nOffsetProcessParameters);
            }
            else
            {
                nOffsetProcessParameters = Marshal.OffsetOf(
                    typeof(PEB64_PARTIAL),
                    "ProcessParameters").ToInt32();
                pRemoteProcessParametersPointer = new IntPtr(
                    pPeb.ToInt64() + nOffsetProcessParameters);
            }

            if (!NativeMethods.CreateEnvironmentBlock(
                out IntPtr pLocalEnvironment,
                IntPtr.Zero,
                true))
            {
                return IntPtr.Zero;
            }

            ntstatus = NativeMethods.RtlCreateProcessParametersEx(
                    out IntPtr pLocalProcessParameters,
                    in unicodeImagePathName,
                    in dllPath,
                    in unicodeCurrentDirectory,
                    in unicodeCommandline,
                    pLocalEnvironment,
                    in unicodeWindowTitle,
                    in desktopInfo,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    RTL_USER_PROC_FLAGS.PARAMS_NORMALIZED);
            NativeMethods.DestroyEnvironmentBlock(pLocalEnvironment);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return IntPtr.Zero;

            nSizeParameters = Marshal.ReadInt32(pLocalProcessParameters); // MaxLength
            nSizeEnvironment = (int)Marshal.ReadInt64(new IntPtr(
                pLocalProcessParameters.ToInt64() +
                nOffsetEnvironmentSize));
            nSizeBuffer = nSizeParameters + nSizeEnvironment;
            pRemoteProcessParameters = Helpers.AllocateReadWriteMemory(
                hProcess,
                IntPtr.Zero,
                (uint)nSizeBuffer);

            if (pRemoteProcessParameters == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to allocate memory.");

                return IntPtr.Zero;
            }

            pRemoteEnvironment = new IntPtr(
                pRemoteProcessParameters.ToInt64() +
                nSizeParameters);
            pLocalEnvironmentPointer = new IntPtr(
                pLocalProcessParameters.ToInt64() +
                nOffsetEnvironment);
            RebaseProcessParameters(
                pLocalProcessParameters,
                pRemoteProcessParameters,
                false);
            Marshal.WriteIntPtr(pLocalEnvironmentPointer, pRemoteEnvironment);

            status = Helpers.WriteMemory(
                hProcess,
                pRemoteProcessParameters,
                pLocalProcessParameters,
                (uint)nSizeBuffer);
            NativeMethods.RtlDestroyProcessParameters(pLocalProcessParameters);

            if (!status)
            {
                Console.WriteLine("[-] Failed to write process parameters.");

                return IntPtr.Zero;
            }

            pDataBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pDataBuffer, pRemoteProcessParameters);

            status = Helpers.WriteMemory(
                hProcess,
                pRemoteProcessParametersPointer,
                pDataBuffer,
                (uint)IntPtr.Size);

            Marshal.FreeHGlobal(pDataBuffer);

            if (!status)
                return IntPtr.Zero;

            return pRemoteProcessParameters;
        }


        public static bool UpdateCommandLine(
            IntPtr hProcess,
            string commandLine)
        {
            bool status;
            IntPtr pPeb;
            IntPtr pMaximumLengthBuffer;
            IntPtr pLocalProcessParameters;
            IntPtr pRemoteProcessParameters;
            IntPtr pUnicodeStringBuffer;
            byte[] unicodeBytes = Encoding.Unicode.GetBytes(commandLine);
            RTL_USER_PROCESS_PARAMETERS processParameters;

            pPeb = Helpers.GetPebAddress(hProcess);

            if (pPeb == IntPtr.Zero)
                return false;

            pRemoteProcessParameters = Helpers.GetProcessParametersAddress(hProcess, pPeb);

            if (pRemoteProcessParameters == IntPtr.Zero)
                return false;

            pMaximumLengthBuffer = Helpers.ReadMemory(hProcess, pRemoteProcessParameters, 4);

            if (pMaximumLengthBuffer == IntPtr.Zero)
                return false;

            pLocalProcessParameters = Helpers.ReadMemory(
                hProcess,
                pRemoteProcessParameters,
                Marshal.ReadInt32(pMaximumLengthBuffer));
            Marshal.FreeHGlobal(pMaximumLengthBuffer);

            RebaseProcessParameters(pLocalProcessParameters, pRemoteProcessParameters, true);

            processParameters = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(
                pLocalProcessParameters,
                typeof(RTL_USER_PROCESS_PARAMETERS));
            processParameters.CommandLine.Length = (ushort)unicodeBytes.Length;
            pUnicodeStringBuffer = processParameters.CommandLine.GetBuffer();

            Helpers.ZeroMemory(
                pUnicodeStringBuffer,
                (int)processParameters.CommandLine.MaximumLength);
            Marshal.Copy(unicodeBytes, 0, pUnicodeStringBuffer, unicodeBytes.Length);
            Marshal.StructureToPtr(processParameters, pLocalProcessParameters, true);

            RebaseProcessParameters(pLocalProcessParameters, pRemoteProcessParameters, false);

            status = Helpers.WriteMemory(
                hProcess,
                pRemoteProcessParameters,
                pLocalProcessParameters,
                (uint)Marshal.ReadInt32(pLocalProcessParameters));
            Marshal.FreeHGlobal(pLocalProcessParameters);

            return status;
        }
    }
}
