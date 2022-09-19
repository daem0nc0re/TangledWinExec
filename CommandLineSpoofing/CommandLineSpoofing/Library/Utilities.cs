using System;
using System.Runtime.InteropServices;
using System.Text;
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
            bool toLocalPointers,
            bool containsEnvironment)
        {
            ulong nBaseOffset;
            IntPtr pBasePointer;
            IntPtr pTempPointer;
            IntPtr pVerify;
            IntPtr pOverwrite;
            var processParameters = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(
                pLocalProcessParameters,
                typeof(RTL_USER_PROCESS_PARAMETERS));
            ulong nSizeStructure = (ulong)processParameters.MaximumLength;
            ulong nDataSize = nSizeStructure;

            if (containsEnvironment)
                nDataSize += processParameters.EnvironmentSize;

            if (toLocalPointers)
            {
                pBasePointer = pRemoteProcessParameters;
                nBaseOffset = (ulong)(pLocalProcessParameters.ToInt64() - pRemoteProcessParameters.ToInt64());
            }
            else
            {
                pBasePointer = pLocalProcessParameters;
                nBaseOffset = (ulong)(pRemoteProcessParameters.ToInt64() - pLocalProcessParameters.ToInt64());
            }

            for (int nPosition = 0; nPosition < (int)nSizeStructure; nPosition += IntPtr.Size)
            {
                pTempPointer = new IntPtr(pLocalProcessParameters.ToInt64() + nPosition);
                pVerify = Marshal.ReadIntPtr(pTempPointer);

                if ((ulong)(pVerify.ToInt64() - pBasePointer.ToInt64()) < nDataSize)
                {
                    pOverwrite = new IntPtr(pVerify.ToInt64() + (long)nBaseOffset);
                    Marshal.WriteIntPtr(pTempPointer, pOverwrite);
                }
            }
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
            IntPtr pReadBuffer;
            int nOffsetCommandline = Marshal.OffsetOf(
                typeof(RTL_USER_PROCESS_PARAMETERS),
                "CommandLine").ToInt32();
            int nSizeUnicodeString = Marshal.SizeOf(typeof(UNICODE_STRING));
            UNICODE_STRING originalCommandline;
            IntPtr pRemoteProcessParameters;

            pPeb = Helpers.GetPebAddress(hSuspendedProcess);

            if (pPeb == IntPtr.Zero)
                return false;

            pProcessParameters = Helpers.GetProcessParametersAddress(hSuspendedProcess, pPeb);

            if (pProcessParameters == IntPtr.Zero)
                return false;

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
            IntPtr pLocalEnvironment;
            IntPtr pRemoteProcessParametersPointer;
            IntPtr pRemoteProcessParameters;
            IntPtr pDataBuffer;
            int nSizeParameters;
            int nSizeEnvironment;
            int nSizeBuffer;
            int nOffsetProcessParameters;
            int nOffsetEnvironmentSize;
            int nPageOffset;
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

            pLocalEnvironment = Helpers.GetCurrentEnvironmentAddress();

            if (pLocalEnvironment == IntPtr.Zero)
                return IntPtr.Zero;

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

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return IntPtr.Zero;

            nPageOffset = (int)(pLocalProcessParameters.ToInt64() - (pLocalProcessParameters.ToInt64() & ~(0xFFF)));
            nSizeParameters = Marshal.ReadInt32(pLocalProcessParameters); // MaxLength
            nSizeEnvironment = (int)Marshal.ReadInt64(new IntPtr(
                pLocalProcessParameters.ToInt64() +
                nOffsetEnvironmentSize));
            nSizeBuffer = nSizeParameters + nSizeEnvironment;

            pRemoteProcessParameters = Helpers.AllocateReadWriteMemory(
                hProcess,
                IntPtr.Zero,
                (uint)(nSizeBuffer + 0x1000));

            if (pRemoteProcessParameters == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to allocate memory.");

                return IntPtr.Zero;
            }

            pRemoteProcessParameters = new IntPtr(pRemoteProcessParameters.ToInt64() + nPageOffset);

            RebaseProcessParameters(
                pLocalProcessParameters,
                pRemoteProcessParameters,
                false,
                true);

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

            RebaseProcessParameters(
                pLocalProcessParameters,
                pRemoteProcessParameters,
                true,
                false);

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

            RebaseProcessParameters(
                pLocalProcessParameters,
                pRemoteProcessParameters,
                false,
                false);

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
