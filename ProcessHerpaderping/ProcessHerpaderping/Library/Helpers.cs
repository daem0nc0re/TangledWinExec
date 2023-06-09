using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ProcessHerpaderping.Interop;

namespace ProcessHerpaderping.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Helpers
    {
        public static IntPtr AllocateReadWriteMemory(
            IntPtr hProcess,
            IntPtr pAllocateBuffer,
            uint nSizeAllocateBuffer)
        {
            NTSTATUS ntstauts;
            SIZE_T nRegionSize = new SIZE_T(nSizeAllocateBuffer);

            ntstauts = NativeMethods.NtAllocateVirtualMemory(
                hProcess,
                ref pAllocateBuffer,
                SIZE_T.Zero,
                ref nRegionSize,
                ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                MEMORY_PROTECTION.READWRITE);

            if (ntstauts != Win32Consts.STATUS_SUCCESS)
                pAllocateBuffer = IntPtr.Zero;
            
            return pAllocateBuffer;
        }


        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static void CopyMemory(IntPtr pDestination, IntPtr pSource, int nSize)
        {
            for (int offset = 0; offset < nSize; offset++)
                Marshal.WriteByte(pDestination, offset, Marshal.ReadByte(pSource, offset));
        }


        public static bool DeleteFile(string filePathName)
        {
            bool status = false;

            try
            {
                if (File.Exists(filePathName))
                    File.Delete(filePathName);

                status = true;
            }
            catch
            {
                Console.WriteLine("[!] Failed to delete \"{0}\". Delete it manually.", filePathName);
            }

            return status;
        }


        public static IntPtr GetCurrentEnvironmentAddress()
        {
            int nOffsetEnvironmentPointer;
            int nOffsetProcessParametersPointer;
            IntPtr pProcessParameters;
            var hProcess = Process.GetCurrentProcess().Handle;
            var pEnvironment = IntPtr.Zero;

            if (GetProcessBasicInformation(hProcess, out PROCESS_BASIC_INFORMATION pbi))
            {
                if (Environment.Is64BitProcess)
                {
                    nOffsetEnvironmentPointer = 0x80;
                    nOffsetProcessParametersPointer = 0x20;
                }
                else
                {
                    nOffsetEnvironmentPointer = 0x48;
                    nOffsetProcessParametersPointer = 0x10;
                }

                pProcessParameters = Marshal.ReadIntPtr(pbi.PebBaseAddress, nOffsetProcessParametersPointer);
                pEnvironment = Marshal.ReadIntPtr(pProcessParameters, nOffsetEnvironmentPointer);
            }

            return pEnvironment;
        }


        public static IntPtr GetImageBaseAddress(IntPtr hProcess, IntPtr pPeb)
        {
            IntPtr pImageBase;
            IntPtr pReadBuffer;
            int nSizePointer;
            int nOffsetImageBaseAddress;

            if (Environment.Is64BitOperatingSystem)
            {
                if (!NativeMethods.IsWow64Process(
                    hProcess,
                    out bool Wow64Process))
                {
                    return IntPtr.Zero;
                }

                if (Wow64Process)
                {
                    nSizePointer = 4;
                    nOffsetImageBaseAddress = Marshal.OffsetOf(
                        typeof(PEB32_PARTIAL),
                        "ImageBaseAddress").ToInt32();
                }
                else
                {
                    nSizePointer = 8;
                    nOffsetImageBaseAddress = Marshal.OffsetOf(
                        typeof(PEB64_PARTIAL),
                        "ImageBaseAddress").ToInt32();
                }
            }
            else
            {
                nSizePointer = 4;
                nOffsetImageBaseAddress = Marshal.OffsetOf(
                    typeof(PEB32_PARTIAL),
                    "ImageBaseAddress").ToInt32();
            }

            pReadBuffer = ReadMemory(
                hProcess,
                new IntPtr(pPeb.ToInt64() + nOffsetImageBaseAddress),
                (uint)nSizePointer);

            if (pReadBuffer == IntPtr.Zero)
                return IntPtr.Zero;

            if (nSizePointer == 4)
                pImageBase = new IntPtr(Marshal.ReadInt32(pReadBuffer));
            else
                pImageBase = new IntPtr(Marshal.ReadInt64(pReadBuffer));

            Marshal.FreeHGlobal(pReadBuffer);

            return pImageBase;
        }


        public static IntPtr GetPebAddress(IntPtr hProcess)
        {
            if (!GetProcessBasicInformation(
                hProcess,
                out PROCESS_BASIC_INFORMATION pbi))
            {
                return IntPtr.Zero;
            }
            else
            {
                return pbi.PebBaseAddress;
            }
        }


        public static IntPtr GetPebAddressWow64(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr pPeb;

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessWow64Information,
                pInfoBuffer,
                (uint)IntPtr.Size,
                IntPtr.Zero);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                pPeb = IntPtr.Zero;
            else
                pPeb = Marshal.ReadIntPtr(pInfoBuffer);

            Marshal.FreeHGlobal(pInfoBuffer);

            return pPeb;
        }


        public static bool GetProcessBasicInformation(
            IntPtr hProcess,
            out PROCESS_BASIC_INFORMATION pbi)
        {
            NTSTATUS ntstatus;
            var nSizeBuffer = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nSizeBuffer);

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                nSizeBuffer,
                IntPtr.Zero);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                pbi = new PROCESS_BASIC_INFORMATION();
            }
            else
            {
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static IntPtr GetProcessParametersAddress(IntPtr hProcess, IntPtr pPeb)
        {
            IntPtr pProcessParameters;
            IntPtr pReadBuffer;
            int nSizePointer;
            int nOffsetImageBaseAddress;

            if (Environment.Is64BitOperatingSystem)
            {
                if (!NativeMethods.IsWow64Process(
                    hProcess,
                    out bool Wow64Process))
                {
                    return IntPtr.Zero;
                }

                if (Wow64Process)
                {
                    nSizePointer = 4;
                    nOffsetImageBaseAddress = Marshal.OffsetOf(
                        typeof(PEB32_PARTIAL),
                        "ProcessParameters").ToInt32();
                }
                else
                {
                    nSizePointer = 8;
                    nOffsetImageBaseAddress = Marshal.OffsetOf(
                        typeof(PEB64_PARTIAL),
                        "ProcessParameters").ToInt32();
                }
            }
            else
            {
                nSizePointer = 4;
                nOffsetImageBaseAddress = Marshal.OffsetOf(
                    typeof(PEB32_PARTIAL),
                    "ProcessParameters").ToInt32();
            }

            pReadBuffer = ReadMemory(
                hProcess,
                new IntPtr(pPeb.ToInt64() + nOffsetImageBaseAddress),
                (uint)nSizePointer);

            if (pReadBuffer == IntPtr.Zero)
                return IntPtr.Zero;

            if (nSizePointer == 4)
                pProcessParameters = new IntPtr(Marshal.ReadInt32(pReadBuffer));
            else
                pProcessParameters = new IntPtr(Marshal.ReadInt64(pReadBuffer));

            Marshal.FreeHGlobal(pReadBuffer);

            return pProcessParameters;
        }


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            var dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            var pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (CompareIgnoreCase(Path.GetFileName(module.FileName), "ntdll.dll"))
                    {
                        pNtdll = module.BaseAddress;
                        dwFlags |= FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE;
                        break;
                    }
                }
            }

            nReturnedLength = NativeMethods.FormatMessage(
                dwFlags,
                pNtdll,
                code,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", code.ToString("X8"), message.ToString().Trim());
        }


        public static IntPtr ReadMemory(
            IntPtr hProcess,
            IntPtr pReadAddress,
            uint nSizeToRead)
        {
            NTSTATUS ntstatus;
            IntPtr pBuffer = Marshal.AllocHGlobal((int)nSizeToRead);
            ZeroMemory(pBuffer, (int)nSizeToRead);

            ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pReadAddress,
                    pBuffer,
                    nSizeToRead,
                    IntPtr.Zero);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Marshal.FreeHGlobal(pBuffer);
                pBuffer = IntPtr.Zero;
            }

            return pBuffer;
        }


        public static string ResolveImagePathName(string commandLine)
        {
            int returnedLength;
            int nCountQuotes;
            string fileName;
            string extension;
            string imagePathName = null;
            string[] arguments = Regex.Split(commandLine.Trim(), @"\s+");
            var candidatePath = new StringBuilder(Win32Consts.MAX_PATH);
            var resolvedPath = new StringBuilder(Win32Consts.MAX_PATH);
            var regexExtension = new Regex(@".+\.\S+$");
            var regexExe = new Regex(@".+\.exe$");

            for (var idx = 0; idx < arguments.Length; idx++)
            {
                if (idx > 0)
                    candidatePath.Append(" ");

                candidatePath.Append(arguments[idx]);
                fileName = candidatePath.ToString();

                nCountQuotes = Regex.Matches(fileName, "\"").Count;

                if (((nCountQuotes % 2) != 0) && (nCountQuotes > 0))
                {
                    continue;
                }
                else if (nCountQuotes == 0)
                {
                    nCountQuotes = Regex.Matches(fileName, "\'").Count;

                    if (((nCountQuotes % 2) != 0) && (nCountQuotes > 0))
                        continue;
                    else
                        fileName = fileName.Trim('\'');
                }
                else
                {
                    fileName = fileName.Trim('\"');
                }

                extension = regexExtension.IsMatch(fileName) ? null : ".exe";

                try
                {
                    imagePathName = Path.GetFullPath(fileName);
                }
                catch
                {
                    imagePathName = null;

                    break;
                }

                if (File.Exists(imagePathName) && regexExe.IsMatch(imagePathName))
                {
                    break;
                }
                else
                {
                    returnedLength = NativeMethods.SearchPath(
                        null,
                        fileName,
                        extension,
                        Win32Consts.MAX_PATH,
                        resolvedPath,
                        IntPtr.Zero);

                    if (returnedLength > 0)
                    {
                        imagePathName = resolvedPath.ToString();

                        if (regexExe.IsMatch(imagePathName))
                            break;
                    }
                }

                resolvedPath.Clear();
                resolvedPath.Capacity = Win32Consts.MAX_PATH;
                imagePathName = null;
            }

            candidatePath.Clear();
            resolvedPath.Clear();

            return imagePathName;
        }


        public static bool SetProcessParametersAddress(
            IntPtr hProcess,
            IntPtr pPeb,
            IntPtr pProcessParameters)
        {
            bool status;
            IntPtr pDataBuffer;
            int nOffset;

            if (IntPtr.Size == 4)
                nOffset = Marshal.OffsetOf(typeof(PEB32_PARTIAL), "ProcessParameters").ToInt32();
            else
                nOffset = Marshal.OffsetOf(typeof(PEB64_PARTIAL), "ProcessParameters").ToInt32();

            pDataBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pDataBuffer, pProcessParameters);

            status = WriteMemory(
                hProcess,
                new IntPtr(pPeb.ToInt64() + nOffset),
                pDataBuffer,
                (uint)IntPtr.Size);
            Marshal.FreeHGlobal(pDataBuffer);

            return status;
        }


        public static bool WriteDataIntoFile(IntPtr hDstFile, byte[] data, bool flush)
        {
            int ntstatus;
            int nSizeIoStatusBlock = Marshal.SizeOf(typeof(IO_STATUS_BLOCK));
            IntPtr pIoStatusBlock = Marshal.AllocHGlobal(nSizeIoStatusBlock);

            NativeMethods.SetFilePointerEx(
                hDstFile,
                new LARGE_INTEGER { QuadPart = 0L },
                IntPtr.Zero,
                FILE_POINTER_MOVE_METHOD.FILE_BEGIN);

            ntstatus = NativeMethods.NtWriteFile(
                hDstFile,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                pIoStatusBlock,
                data,
                (uint)data.Length,
                IntPtr.Zero,
                IntPtr.Zero);

            if (flush)
                NativeMethods.FlushFileBuffers(hDstFile);

            /*
             * This API call will fail while herpaderping process is running.
             */
            NativeMethods.SetEndOfFile(hDstFile);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool WriteMemory(
            IntPtr hProcess,
            IntPtr pWriteAddress,
            IntPtr pDataToWrite,
            uint nSizeToWrite)
        {
            NTSTATUS ntstatus;

            ntstatus = NativeMethods.NtWriteVirtualMemory(
                hProcess,
                pWriteAddress,
                pDataToWrite,
                nSizeToWrite,
                IntPtr.Zero);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }


        public static void ZeroMemory(byte[] buffer, int size)
        {
            var nullBytes = new byte[size];
            Buffer.BlockCopy(nullBytes, 0, buffer, 0, size);
        }
    }
}
