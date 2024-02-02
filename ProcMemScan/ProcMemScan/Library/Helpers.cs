using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ProcMemScan.Interop;

namespace ProcMemScan.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Helpers
    {
        public static RTL_BALANCED_NODE ConvertBalanceNode32ToBalanceNode(
            RTL_BALANCED_NODE32 balanceNode32)
        {
            return new RTL_BALANCED_NODE
            {
                Left = new IntPtr(balanceNode32.Left),
                Right = new IntPtr(balanceNode32.Right),
                ParentValue = balanceNode32.ParentValue
            };
        }


        public static string ConvertLargeIntegerToLocalTimeString(LARGE_INTEGER fileTime)
        {
            if (NativeMethods.FileTimeToSystemTime(in fileTime, out SYSTEMTIME systemTime))
            {
                if (NativeMethods.SystemTimeToTzSpecificLocalTime(
                    IntPtr.Zero,
                    in systemTime,
                    out SYSTEMTIME localTime))
                {
                    return string.Format(
                        "{0}/{1}/{2} {3}:{4}:{5}",
                        localTime.wYear.ToString("D4"),
                        localTime.wMonth.ToString("D2"),
                        localTime.wDay.ToString("D2"),
                        localTime.wHour.ToString("D2"),
                        localTime.wMinute.ToString("D2"),
                        localTime.wSecond.ToString("D2"));
                }
                else
                {
                    return string.Format(
                        "{0}/{1}/{2} {3}:{4}:{5}",
                        systemTime.wYear.ToString("D4"),
                        systemTime.wMonth.ToString("D2"),
                        systemTime.wDay.ToString("D2"),
                        systemTime.wHour.ToString("D2"),
                        systemTime.wMinute.ToString("D2"),
                        systemTime.wSecond.ToString("D2"));
                }
            }
            else
            {
                return "N/A";
            }
        }


        public static LIST_ENTRY ConvertListEntry32ToListEntry(LIST_ENTRY32 listEntry32)
        {
            return new LIST_ENTRY
            {
                Flink = new IntPtr(listEntry32.Flink),
                Blink = new IntPtr(listEntry32.Blink)
            };
        }


        public static UNICODE_STRING ConvertUnicodeString32ToUnicodeString(
            UNICODE_STRING32 unicodeString32)
        {
            var unicodeString = new UNICODE_STRING
            {
                Length = unicodeString32.Length,
                MaximumLength = unicodeString32.MaximumLength
            };
            unicodeString.SetBuffer(new IntPtr(unicodeString32.Buffer));

            return unicodeString;
        }


        public static IntPtr CreateExportFile(string path)
        {
            IntPtr hFile = Win32Consts.INVALID_HANDLE_VALUE;

            using (var objectAttributes = new OBJECT_ATTRIBUTES(
                string.Format(@"\??\{0}", Path.GetFullPath(path)),
                OBJECT_ATTRIBUTES_FLAGS.OBJ_CASE_INSENSITIVE))
            {
                NTSTATUS ntstatus = NativeMethods.NtCreateFile(
                    out hFile,
                    ACCESS_MASK.FILE_GENERIC_READ | ACCESS_MASK.FILE_GENERIC_WRITE | ACCESS_MASK.SYNCHRONIZE,
                    in objectAttributes,
                    out IO_STATUS_BLOCK _,
                    IntPtr.Zero,
                    FILE_ATTRIBUTE_FLAGS.NORMAL,
                    FILE_SHARE_ACCESS.NONE,
                    FILE_CREATE_DISPOSITION.OPEN_IF,
                    FILE_CREATE_OPTIONS.RANDOM_ACCESS | FILE_CREATE_OPTIONS.NON_DIRECTORY_FILE | FILE_CREATE_OPTIONS.SYNCHRONOUS_IO_NONALERT,
                    IntPtr.Zero,
                    0);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hFile = Win32Consts.INVALID_HANDLE_VALUE;
            }
            
            return hFile;
        }


        public static Dictionary<string, string> EnumEnvrionments(
            IntPtr hProcess,
            IntPtr pEnvironment,
            uint nEnvironmentSize)
        {
            IntPtr pBufferToRead;
            int nOffset = 0;
            var environments = new Dictionary<string, string>();

            if ((pEnvironment == IntPtr.Zero) || (nEnvironmentSize == 0))
                return environments;

            pBufferToRead = ReadMemory(hProcess, pEnvironment, nEnvironmentSize);

            if (pBufferToRead == IntPtr.Zero)
                return environments;

            while (nOffset < nEnvironmentSize)
            {
                if (Marshal.ReadInt32(pBufferToRead, nOffset) == 0)
                {
                    nOffset += 4;

                    while (Marshal.ReadInt16(pBufferToRead, nOffset) != 0)
                        nOffset += 2;
                }
                else if (Marshal.ReadInt16(pBufferToRead, nOffset) != 0)
                {
                    var keyBytes = new List<byte>();
                    var valueBytes = new List<byte>();

                    while (Marshal.ReadInt16(pBufferToRead, nOffset) != 0)
                    {
                        if (Marshal.ReadInt16(pBufferToRead, nOffset) == 0x3D)
                        {
                            nOffset += 2;
                            break;
                        }

                        for (int idx = 0; idx < 2; idx++)
                        {
                            keyBytes.Add(Marshal.ReadByte(pBufferToRead, nOffset));
                            nOffset++;
                        }
                    }

                    while (Marshal.ReadInt16(pBufferToRead, nOffset) != 0)
                    {
                        for (int idx = 0; idx < 2; idx++)
                        {
                            valueBytes.Add(Marshal.ReadByte(pBufferToRead, nOffset));
                            nOffset++;
                        }
                    }

                    if (valueBytes.Count > 0)
                    {
                        var key = Encoding.Unicode.GetString(keyBytes.ToArray());
                        var value = Encoding.Unicode.GetString(valueBytes.ToArray());

                        if (!environments.ContainsKey(key))
                            environments.Add(key, value);
                    }
                }
                else
                {
                    nOffset += 2;
                }
            }

            Marshal.FreeHGlobal(pBufferToRead);

            return environments;
        }


        public static List<MEMORY_BASIC_INFORMATION> EnumMemoryBasicInformation(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            bool status;
            MEMORY_BASIC_INFORMATION memoryBasicInfo;
            var results = new List<MEMORY_BASIC_INFORMATION>();
            int nInfoBufferSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(nInfoBufferSize);
            IntPtr pCurrentBaseAddress = IntPtr.Zero;

            do
            {
                ntstatus = NativeMethods.NtQueryVirtualMemory(
                    hProcess,
                    pCurrentBaseAddress,
                    MEMORY_INFORMATION_CLASS.MemoryBasicInformation,
                    pInfoBuffer,
                    new SIZE_T((uint)nInfoBufferSize),
                    out SIZE_T _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (status)
                {
                    memoryBasicInfo = (MEMORY_BASIC_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(MEMORY_BASIC_INFORMATION));

                    results.Add(memoryBasicInfo);

                    pCurrentBaseAddress = new IntPtr(
                        pCurrentBaseAddress.ToInt64() + (long)memoryBasicInfo.RegionSize.ToUInt64());
                }
            } while (status);

            Marshal.FreeHGlobal(pInfoBuffer);

            return results;
        }


        public static int GetArchitectureBitness(IMAGE_FILE_MACHINE arch)
        {
            if (arch == IMAGE_FILE_MACHINE.I386)
                return 32;
            else if (arch == IMAGE_FILE_MACHINE.ARM)
                return 32;
            else if (arch == IMAGE_FILE_MACHINE.ARM2)
                return 32;
            else if (arch == IMAGE_FILE_MACHINE.IA64)
                return 64;
            else if (arch == IMAGE_FILE_MACHINE.AMD64)
                return 64;
            else if (arch == IMAGE_FILE_MACHINE.ARM64)
                return 64;
            else
                return 0;
        }


        public static string GetMappedImagePathName(IntPtr hProcess, IntPtr pMemory)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string imagePathName = null;
            Dictionary<string, string> deviceMap = GetDeviceMap();
            var nInfoLength = new SIZE_T((uint)(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength.ToUInt32());
                ntstatus = NativeMethods.NtQueryVirtualMemory(
                    hProcess,
                    pMemory,
                    MEMORY_INFORMATION_CLASS.MemoryMappedFilenameInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (UNICODE_STRING)Marshal.PtrToStructure(pInfoBuffer, typeof(UNICODE_STRING));
                imagePathName = info.ToString();

                if (string.IsNullOrEmpty(imagePathName))
                {
                    imagePathName = null;
                }
                else
                {
                    foreach (var entry in deviceMap)
                    {
                        var convertedPath = Regex.Replace(
                            imagePathName,
                            string.Format(@"^{0}", entry.Value).Replace(@"\", @"\\"),
                            entry.Key,
                            RegexOptions.IgnoreCase);

                        if (convertedPath != imagePathName)
                        {
                            imagePathName = convertedPath;
                            break;
                        }
                    }
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return imagePathName;
        }


        public static bool GetMemoryBasicInformation(
            IntPtr hProcess,
            IntPtr pMemory,
            out MEMORY_BASIC_INFORMATION memoryBasicInfo)
        {
            var nInfoBufferSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoBufferSize);
            NTSTATUS ntstatus = NativeMethods.NtQueryVirtualMemory(
                hProcess,
                pMemory,
                MEMORY_INFORMATION_CLASS.MemoryBasicInformation,
                pInfoBuffer,
                new SIZE_T(nInfoBufferSize),
                out SIZE_T _);
            
            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                memoryBasicInfo = (MEMORY_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(MEMORY_BASIC_INFORMATION));
            }
            else
            {
                memoryBasicInfo = new MEMORY_BASIC_INFORMATION();
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static Dictionary<string, string> GetDeviceMap()
        {
            var driveLetters = new List<string>();
            var deviceMap = new Dictionary<string, string>();
            var nInfoLength = (uint)Marshal.SizeOf(typeof(PROCESS_DEVICEMAP_INFORMATION));
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                new IntPtr(-1),
                PROCESSINFOCLASS.ProcessDeviceMap,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                int nDeviceMap = Marshal.ReadInt32(pInfoBuffer);
                Marshal.FreeHGlobal(pInfoBuffer);

                for (int idx = 0; idx < 0x1A; idx++)
                {
                    var nTestBit = (1 << idx);
                    var driveLetterBytes = new byte[] { (byte)(0x41 + idx), 0x3A };

                    if ((nDeviceMap & nTestBit) == nTestBit)
                        driveLetters.Add(Encoding.ASCII.GetString(driveLetterBytes));
                }
            }

            foreach (var letter in driveLetters)
            {
                IntPtr hSymlink;
                var unicodeString = new UNICODE_STRING { MaximumLength = 512 };

                using (var objectAttributes = new OBJECT_ATTRIBUTES(
                    string.Format(@"\GLOBAL??\{0}", letter),
                    OBJECT_ATTRIBUTES_FLAGS.OBJ_CASE_INSENSITIVE))
                {
                    ntstatus = NativeMethods.NtOpenSymbolicLinkObject(
                        out hSymlink,
                        ACCESS_MASK.SYMBOLIC_LINK_QUERY,
                        in objectAttributes);
                }

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    continue;

                pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);

                if (Environment.Is64BitProcess)
                    unicodeString.SetBuffer(new IntPtr(pInfoBuffer.ToInt64() + Marshal.SizeOf(typeof(UNICODE_STRING))));
                else
                    unicodeString.SetBuffer(new IntPtr(pInfoBuffer.ToInt32() + Marshal.SizeOf(typeof(UNICODE_STRING))));

                Marshal.StructureToPtr(unicodeString, pInfoBuffer, true);

                ntstatus = NativeMethods.NtQuerySymbolicLinkObject(hSymlink, pInfoBuffer, out uint _);
                NativeMethods.NtClose(hSymlink);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    var target = (UNICODE_STRING)Marshal.PtrToStructure(pInfoBuffer, typeof(UNICODE_STRING));

                    if (!string.IsNullOrEmpty(target.ToString()))
                        deviceMap.Add(letter, target.ToString());
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return deviceMap;
        }


        public static bool GetPebAddress(IntPtr hProcess, out IntPtr pPeb, out IntPtr pPebWow64)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            pPeb = IntPtr.Zero;
            pPebWow64 = IntPtr.Zero;

            if (Environment.Is64BitProcess)
            {
                pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessWow64Information,
                    pInfoBuffer,
                    (uint)IntPtr.Size,
                    IntPtr.Zero);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    pPebWow64 = Marshal.ReadIntPtr(pInfoBuffer);

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
                pPeb = info.PebBaseAddress;
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetProcessBasicInformation(
            IntPtr hProcess,
            out PROCESS_BASIC_INFORMATION pbi)
        {
            var nSizeBuffer = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nSizeBuffer);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                nSizeBuffer,
                IntPtr.Zero);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
            }
            else
            {
                pbi = new PROCESS_BASIC_INFORMATION();
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static string GetProcessImageFileName(IntPtr hProcess)
        {
            var nInfoLength = (uint)(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            string imageFileName = null;
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessImageFileName,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == 0)
            {
                var info = (UNICODE_STRING)Marshal.PtrToStructure(pInfoBuffer, typeof(UNICODE_STRING));
                Dictionary<string, string> deviceMap = GetDeviceMap();
                imageFileName = info.ToString();

                if (info.Length > 0)
                {
                    foreach (var alias in deviceMap)
                    {
                        if (imageFileName.StartsWith(alias.Value, StringComparison.OrdinalIgnoreCase))
                        {
                            imageFileName = Regex.Replace(
                                imageFileName,
                                string.Format(@"^{0}", alias.Value).Replace(@"\", @"\\"),
                                alias.Key,
                                RegexOptions.IgnoreCase);
                            break;
                        }
                    }
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return imageFileName;
        }


        public static IntPtr GetProcessParameters(IntPtr hProcess, IntPtr pPeb, bool bWow64)
        {
            int nOffset;
            uint nStructSize;
            uint nPointerSize;
            IntPtr pBufferToRead;
            IntPtr pInfoBuffer;
            IntPtr pProcessParametersBuffer;
            var pProcessParameters = IntPtr.Zero;

            if (!Environment.Is64BitProcess || bWow64)
            {
                nOffset = Marshal.OffsetOf(typeof(PEB32_PARTIAL), "ProcessParameters").ToInt32();
                nStructSize = (uint)Marshal.SizeOf(typeof(RTL_USER_PROCESS_PARAMETERS32));
                nPointerSize = 4;
            }
            else
            {
                nOffset = Marshal.OffsetOf(typeof(PEB64_PARTIAL), "ProcessParameters").ToInt32();
                nStructSize = (uint)Marshal.SizeOf(typeof(RTL_USER_PROCESS_PARAMETERS));
                nPointerSize = 8;
            }

            do
            {
                if (Environment.Is64BitProcess)
                    pBufferToRead = new IntPtr(pPeb.ToInt64() + nOffset);
                else
                    pBufferToRead = new IntPtr(pPeb.ToInt32() + nOffset);

                pInfoBuffer = ReadMemory(hProcess, pBufferToRead, nPointerSize);

                if (pInfoBuffer == IntPtr.Zero)
                    break;

                if (nPointerSize == 8)
                    pProcessParametersBuffer = new IntPtr(Marshal.ReadInt64(pInfoBuffer));
                else
                    pProcessParametersBuffer = new IntPtr(Marshal.ReadInt32(pInfoBuffer));

                Marshal.FreeHGlobal(pInfoBuffer);
                pProcessParameters = ReadMemory(hProcess, pProcessParametersBuffer, nStructSize);
            } while (false);

            return pProcessParameters;
        }


        public static string GetVirtualAddressSection(List<IMAGE_SECTION_HEADER> sections, uint nVirtualAddress)
        {
            string sectionName = null;

            foreach (var section in sections)
            {
                if ((nVirtualAddress >= section.VirtualAddress) &&
                    (nVirtualAddress < (section.VirtualAddress + section.VirtualSize)))
                {
                    sectionName = section.Name;
                    break;
                }
            }

            return sectionName;
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
                    if (string.Compare(Path.GetFileName(module.FileName), "ntdll.dll", true) == 0)
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


        public static bool IsReadableAddress(IntPtr hProcess, IntPtr pMemory)
        {
            bool status = GetMemoryBasicInformation(
                hProcess,
                pMemory,
                out MEMORY_BASIC_INFORMATION mbi);

            if (status)
                status = ((mbi.Protect != MEMORY_PROTECTION.NONE) && (mbi.Protect != MEMORY_PROTECTION.PAGE_NOACCESS));

            return status;
        }


        public static IntPtr ReadMemory(IntPtr hProcess, IntPtr pReadAddress, uint nSizeToRead)
        {
            IntPtr pBuffer = Marshal.AllocHGlobal((int)nSizeToRead);
            NTSTATUS ntstatus = NativeMethods.NtReadVirtualMemory(
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


        public static string ReadRemoteUnicodeString(IntPtr hProcess, UNICODE_STRING unicodeString)
        {
            string result;
            IntPtr pUnicodeString = unicodeString.GetBuffer();

            if (pUnicodeString == IntPtr.Zero)
                return null;

            IntPtr pBuffer = ReadMemory(
                hProcess,
                pUnicodeString,
                unicodeString.MaximumLength);

            if (pBuffer == IntPtr.Zero)
                return null;

            result = Marshal.PtrToStringUni(pBuffer);
            Marshal.FreeHGlobal(pBuffer);

            return result;
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


        public static bool WriteDataIntoFile(IntPtr hFile, IntPtr pBuffer, uint nBufferSize)
        {
            NTSTATUS ntstatus = NativeMethods.NtWriteFile(
                hFile,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out IO_STATUS_BLOCK _,
                pBuffer,
                nBufferSize,
                IntPtr.Zero,
                IntPtr.Zero);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
