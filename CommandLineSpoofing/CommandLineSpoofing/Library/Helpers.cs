using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using CommandLineSpoofing.Interop;

namespace CommandLineSpoofing.Library
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
            return NativeMethods.VirtualAllocEx(
                hProcess,
                pAllocateBuffer,
                new SIZE_T(nSizeAllocateBuffer),
                ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                MEMORY_PROTECTION.READWRITE);
        }


        public static IntPtr AllocateReadWriteMemory(
            IntPtr hProcess,
            IntPtr pAllocateBuffer,
            int nSizeAllocateBuffer)
        {
            return NativeMethods.VirtualAllocEx(
                hProcess,
                pAllocateBuffer,
                new SIZE_T((uint)nSizeAllocateBuffer),
                ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                MEMORY_PROTECTION.READWRITE);
        }


        public static IntPtr GetPebAddress(IntPtr hProcess)
        {
            int ntstatus;
            PROCESS_BASIC_INFORMATION pbi;
            IntPtr pPeb;
            var nSizeBuffer = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nSizeBuffer);

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESS_INFORMATION_CLASS.ProcessBasicInformation,
                pInfoBuffer,
                nSizeBuffer,
                IntPtr.Zero);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                pPeb = IntPtr.Zero;
            }
            else
            {
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
                pPeb = pbi.PebBaseAddress;
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return pPeb;
        }


        public static IntPtr GetPebAddressWow64(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr pPeb;

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESS_INFORMATION_CLASS.ProcessWow64Information,
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


        public static IntPtr GetProcessParametersAddress(
            IntPtr hProcess,
            IntPtr pPeb)
        {
            int nOffset;
            IntPtr pProcessParameters;
            IntPtr pReadBuffer;

            if (IntPtr.Size == 4)
            {
                nOffset = Marshal.OffsetOf(
                    typeof(PEB32_PARTIAL),
                    "ProcessParameters").ToInt32();
            }
            else
            {
                nOffset = Marshal.OffsetOf(
                    typeof(PEB64_PARTIAL),
                    "ProcessParameters").ToInt32();
            }

            pReadBuffer = ReadMemory(hProcess, new IntPtr(pPeb.ToInt64() + nOffset), IntPtr.Size);
            
            if (pReadBuffer == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }
            else
            {
                if (IntPtr.Size == 4)
                    pProcessParameters = new IntPtr(Marshal.ReadInt32(pReadBuffer));
                else
                    pProcessParameters = new IntPtr(Marshal.ReadInt64(pReadBuffer));

                Marshal.FreeHGlobal(pReadBuffer);

                return pProcessParameters;
            }
        }


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            int nReturnedLength;
            ProcessModuleCollection modules;
            FormatMessageFlags dwFlags;
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            IntPtr pNtdll = IntPtr.Zero;

            if (isNtStatus)
            {
                modules = Process.GetCurrentProcess().Modules;

                foreach (ProcessModule mod in modules)
                {
                    if (string.Compare(
                        Path.GetFileName(mod.FileName),
                        "ntdll.dll",
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        pNtdll = mod.BaseAddress;
                        break;
                    }
                }

                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                dwFlags = FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
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
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }


        public static IntPtr ReadMemory(
            IntPtr hProcess,
            IntPtr pReadAddress,
            uint nSizeToRead)
        {
            IntPtr pBuffer = Marshal.AllocHGlobal((int)nSizeToRead);
            ZeroMemory(pBuffer, (int)nSizeToRead);

            if (!NativeMethods.ReadProcessMemory(
                    hProcess,
                    pReadAddress,
                    pBuffer,
                    new SIZE_T(nSizeToRead),
                    IntPtr.Zero))
            {
                Marshal.FreeHGlobal(pBuffer);

                return IntPtr.Zero;
            }

            return pBuffer;
        }


        public static IntPtr ReadMemory(
            IntPtr hProcess,
            IntPtr pReadAddress,
            int nSizeToRead)
        {
            IntPtr pBuffer = Marshal.AllocHGlobal(nSizeToRead);
            ZeroMemory(pBuffer, nSizeToRead);

            if (!NativeMethods.ReadProcessMemory(
                    hProcess,
                    pReadAddress,
                    pBuffer,
                    new SIZE_T((uint)nSizeToRead),
                    IntPtr.Zero))
            {
                Marshal.FreeHGlobal(pBuffer);

                return IntPtr.Zero;
            }

            return pBuffer;
        }


        public static string ResolveImageNamePath(string commandLine)
        {
            int returnedLength;
            string fileName;
            string extension;
            string[] arguments = Regex.Split(commandLine.Trim(), @"\s+");
            var resolvedPath = new StringBuilder(Win32Consts.MAX_PATH);
            var regexExtension = new Regex(@".+\.\S+$");
            var regexExe = new Regex(@".+\.exe$");

            fileName = arguments[0];
            extension = regexExtension.IsMatch(fileName) ? null : ".exe";
            arguments[0] = Path.GetFullPath(fileName);

            if (regexExe.IsMatch(arguments[0]) && File.Exists(arguments[0]))
            {
                return arguments[0];
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

                if (returnedLength == 0)
                    return null;
                else
                    return resolvedPath.ToString();
            }
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
            {
                nOffset = Marshal.OffsetOf(
                    typeof(PEB32_PARTIAL),
                    "ProcessParameters").ToInt32();
            }
            else
            {
                nOffset = Marshal.OffsetOf(
                    typeof(PEB64_PARTIAL),
                    "ProcessParameters").ToInt32();
            }

            pDataBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pDataBuffer, pProcessParameters);

            status = WriteMemory(
                hProcess,
                new IntPtr(pPeb.ToInt64() + nOffset),
                pDataBuffer,
                IntPtr.Size);
            Marshal.FreeHGlobal(pDataBuffer);

            return status;
        }


        public static bool WriteMemory(
            IntPtr hProcess,
            IntPtr pWriteAddress,
            IntPtr pDataToWrite,
            uint nSizeToWrite)
        {
            return NativeMethods.WriteProcessMemory(
                hProcess,
                pWriteAddress,
                pDataToWrite,
                new SIZE_T(nSizeToWrite),
                IntPtr.Zero);
        }


        public static bool WriteMemory(
            IntPtr hProcess,
            IntPtr pWriteAddress,
            IntPtr pDataToWrite,
            int nSizeToWrite)
        {
            return NativeMethods.WriteProcessMemory(
                hProcess,
                pWriteAddress,
                pDataToWrite,
                new SIZE_T((uint)nSizeToWrite),
                IntPtr.Zero);
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }
    }
}
