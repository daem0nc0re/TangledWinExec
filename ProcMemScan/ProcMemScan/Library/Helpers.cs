using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
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
            string output = "N/A";

            if (NativeMethods.FileTimeToSystemTime(in fileTime, out SYSTEMTIME systemTime))
            {
                if (NativeMethods.SystemTimeToTzSpecificLocalTime(
                    IntPtr.Zero,
                    in systemTime,
                    out SYSTEMTIME localTime))
                {
                    output = string.Format("{0}/{1}/{2} {3}:{4}:{5}",
                        localTime.wYear.ToString("D4"),
                        localTime.wMonth.ToString("D2"),
                        localTime.wDay.ToString("D2"),
                        localTime.wHour.ToString("D2"),
                        localTime.wMinute.ToString("D2"),
                        localTime.wSecond.ToString("D2"));
                }
                else
                {
                    output = string.Format("{0}/{1}/{2} {3}:{4}:{5}",
                        systemTime.wYear.ToString("D4"),
                        systemTime.wMonth.ToString("D2"),
                        systemTime.wDay.ToString("D2"),
                        systemTime.wHour.ToString("D2"),
                        systemTime.wMinute.ToString("D2"),
                        systemTime.wSecond.ToString("D2"));
                }
            }

            return output;
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
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
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


        public static bool EnableTokenPrivileges(
            in List<SE_PRIVILEGE_ID> requiredPrivs,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                in requiredPrivs,
                out adjustedPrivs);
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            in List<SE_PRIVILEGE_ID> privsToEnable,
            out Dictionary<SE_PRIVILEGE_ID, bool> adjustedPrivs)
        {
            bool bAllEnabled;
            int nDosErrorCode;
            IntPtr pInfoBuffer;
            NTSTATUS nErrorStatus = Win32Consts.STATUS_SUCCESS;
            adjustedPrivs = new Dictionary<SE_PRIVILEGE_ID, bool>();

            foreach (var id in privsToEnable)
                adjustedPrivs.Add(id, false);

            if (privsToEnable.Count == 0)
                return true;

            bAllEnabled = GetTokenPrivileges(
                hToken,
                out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

            if (!bAllEnabled)
                return false;

            pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));

            foreach (var priv in privsToEnable)
            {
                NTSTATUS ntstatus;
                var info = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES[1]
                };

                if (!availablePrivs.ContainsKey(priv))
                {
                    nErrorStatus = Win32Consts.STATUS_PRIVILEGE_NOT_HELD;
                    bAllEnabled = false;
                    continue;
                }

                if ((availablePrivs[priv] & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
                {
                    adjustedPrivs[priv] = true;
                    continue;
                }

                info.Privileges[0].Luid.QuadPart = (long)priv;
                info.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                Marshal.StructureToPtr(info, pInfoBuffer, true);
                ntstatus = NativeMethods.NtAdjustPrivilegesToken(
                    hToken,
                    BOOLEAN.FALSE,
                    pInfoBuffer,
                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                    IntPtr.Zero,
                    out uint _);
                adjustedPrivs[priv] = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    nErrorStatus = ntstatus;
                    bAllEnabled = false;
                }
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(nErrorStatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return bAllEnabled;
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

            pBufferToRead = ReadMemory(hProcess, pEnvironment, nEnvironmentSize, out uint _);

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


        public static string GetImageDataDirectoryHash(string filePath)
        {
            string sha256String = null;
            int nDataDirectoriesLength = Marshal.SizeOf(typeof(IMAGE_DATA_DIRECTORY)) * 16;
            var dataDirectories = new byte[nDataDirectoriesLength];

            do
            {
                byte[] fileBytes;
                ushort magic;
                int e_lfanew;
                int nDataDirectoryOffset;

                try
                {
                    fileBytes = File.ReadAllBytes(filePath);
                }
                catch
                {
                    break;
                }

                if ((BitConverter.ToInt16(fileBytes, 0) != 0x5A4D) || (fileBytes.Length < 0x40))
                    break;

                e_lfanew = BitConverter.ToInt32(fileBytes, 0x3C);
                magic = (ushort)BitConverter.ToInt16(fileBytes, e_lfanew + 0x18);

                if (magic == 0x20B)
                    nDataDirectoryOffset = 0x88;
                else if (magic == 0x10B)
                    nDataDirectoryOffset = 0x78;
                else
                    break;

                if (fileBytes.Length < e_lfanew + nDataDirectoryOffset + nDataDirectoriesLength)
                    break;

                for (var idx = 0; idx < nDataDirectoriesLength; idx++)
                    dataDirectories[idx] = fileBytes[e_lfanew + nDataDirectoryOffset + idx];

                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] sha256Bytes = sha256.ComputeHash(dataDirectories);
                    var sha256StringBuilder = new StringBuilder();

                    for (var idx = 0; idx < sha256Bytes.Length; idx++)
                        sha256StringBuilder.AppendFormat("{0}", sha256Bytes[idx].ToString("X2"));

                    sha256String = sha256StringBuilder.ToString();
                }
            } while (false);

            return sha256String;
        }


        public static string GetImageDataDirectoryHash(IntPtr hProcess, IntPtr pImageBase)
        {
            string sha256String = null;
            int nDataDirectoriesLength = Marshal.SizeOf(typeof(IMAGE_DATA_DIRECTORY)) * 16;
            uint nInfoLength = 0x88u + (uint)nDataDirectoriesLength;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);

            do
            {
                ushort magic;
                int nDataDirectoryOffset;
                IntPtr pImageNtHeaders;
                var dataDirectories = new byte[nDataDirectoriesLength];
                NTSTATUS ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pImageBase,
                    pInfoBuffer,
                    0x40u, // sizeof(IMAGE_DOS_HEADER)
                    out uint nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != 0x40u))
                    break;

                if (Environment.Is64BitProcess)
                    pImageNtHeaders = new IntPtr(pImageBase.ToInt64() + Marshal.ReadInt32(pInfoBuffer, 0x3C));
                else
                    pImageNtHeaders = new IntPtr(pImageBase.ToInt32() + Marshal.ReadInt32(pInfoBuffer, 0x3C));

                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pImageNtHeaders,
                    pInfoBuffer,
                    nInfoLength, // sizeof(IMAGE_NT_HEADERS64)
                    out nReturnedLength);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) || (nReturnedLength != nInfoLength))
                    break;

                magic = (ushort)Marshal.ReadInt16(pInfoBuffer, 0x18);

                if (magic == 0x20B)
                    nDataDirectoryOffset = 0x88;
                else if (magic == 0x10B)
                    nDataDirectoryOffset = 0x78;
                else
                    break;

                for (var idx = 0; idx < nDataDirectoriesLength; idx++)
                    dataDirectories[idx] = Marshal.ReadByte(pInfoBuffer, nDataDirectoryOffset + idx);

                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] sha256Bytes = sha256.ComputeHash(dataDirectories);
                    var sha256StringBuilder = new StringBuilder();

                    for (var idx = 0; idx < sha256Bytes.Length; idx++)
                        sha256StringBuilder.AppendFormat("{0}", sha256Bytes[idx].ToString("X2"));

                    sha256String = sha256StringBuilder.ToString();
                }
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);

            return sha256String;
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
            var pInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)) + 512);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                new IntPtr(-1),
                PROCESSINFOCLASS.ProcessDeviceMap,
                pInfoBuffer,
                nInfoLength,
                out uint _);
            int nDeviceMap = Marshal.ReadInt32(pInfoBuffer);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
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
                    OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive))
                {
                    ntstatus = NativeMethods.NtOpenSymbolicLinkObject(
                        out hSymlink,
                        ACCESS_MASK.SYMBOLIC_LINK_QUERY,
                        in objectAttributes);
                }

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    continue;

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

                    if (target.Length != 0)
                        deviceMap.Add(letter, target.ToString());
                }
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return deviceMap;
        }


        public static IntPtr GetImageBaseAddress(IntPtr hProcess, IntPtr pPeb, bool bIs32BitProcess)
        {
            NTSTATUS ntstatus;
            IntPtr pBufferToRead;
            int nOffset = bIs32BitProcess ? 0x08 : 0x10;
            var nInfoLength = bIs32BitProcess ? 4u : 8u;
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            var pImageBase = IntPtr.Zero;

            if (Environment.Is64BitProcess)
                pBufferToRead = new IntPtr(pPeb.ToInt64() + nOffset);
            else
                pBufferToRead = new IntPtr(pPeb.ToInt32() + nOffset);

            ntstatus = NativeMethods.NtReadVirtualMemory(
                hProcess,
                pBufferToRead,
                pInfoBuffer,
                nInfoLength,
                out uint nReturnedLength);

            if ((ntstatus == Win32Consts.STATUS_SUCCESS) && (nReturnedLength == nInfoLength))
            {
                if (bIs32BitProcess)
                    pImageBase = new IntPtr(Marshal.ReadInt32(pInfoBuffer));
                else
                    pImageBase = new IntPtr(Marshal.ReadInt64(pInfoBuffer));
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return pImageBase;
        }


        public static bool GetPebAddress(IntPtr hProcess, out IntPtr pPeb, out IntPtr pPebWow32)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            pPeb = IntPtr.Zero;
            pPebWow32 = IntPtr.Zero;

            if (Environment.Is64BitProcess)
            {
                pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessWow64Information,
                    pInfoBuffer,
                    (uint)IntPtr.Size,
                    out uint _);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    pPebWow32 = Marshal.ReadIntPtr(pInfoBuffer);

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

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
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


        public static Dictionary<IntPtr, string> GetProcessMemorySymbols(
            IntPtr hProcess,
            List<IntPtr> memories)
        {
            IntPtr pInfoBuffer;
            var mappedFileName = new UNICODE_STRING();
            var nInfoLength = (uint)(Marshal.SizeOf(typeof(UNICODE_STRING)) + ushort.MaxValue);
            var symbolTable = new Dictionary<IntPtr, string>();
            NativeMethods.SymSetOptions(SYM_OPTIONS.AUTO_PUBLICS |
                SYM_OPTIONS.CASE_INSENSITIVE |
                SYM_OPTIONS.DEFERRED_LOADS |
                SYM_OPTIONS.FAIL_CRITICAL_ERRORS |
                SYM_OPTIONS.INCLUDE_32BIT_MODULES |
                SYM_OPTIONS.LOAD_LINES |
                SYM_OPTIONS.OMAP_FIND_NEAREST |
                SYM_OPTIONS.UNDNAME);

            if (!NativeMethods.SymInitialize(hProcess, null, true))
                return null;

            pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            Marshal.StructureToPtr(mappedFileName, pInfoBuffer, false);

            foreach (var pBuffer in memories)
            {
                if (symbolTable.ContainsKey(pBuffer))
                    continue;
                else
                    symbolTable.Add(pBuffer, null);

                var symbolBuilder = new StringBuilder();
                var symbolInfo = new SYMBOL_INFO
                {
                    SizeOfStruct = (uint)Marshal.SizeOf(typeof(SYMBOL_INFO)) - Win32Consts.MAX_SYM_NAME,
                    MaxNameLen = Win32Consts.MAX_SYM_NAME,
                    Name = new byte[Win32Consts.MAX_SYM_NAME]
                };
                NTSTATUS ntstatus = NativeMethods.NtQueryVirtualMemory(
                    hProcess,
                    pBuffer,
                    MEMORY_INFORMATION_CLASS.MemoryMappedFilenameInformation,
                    pInfoBuffer,
                    new SIZE_T(nInfoLength),
                    out SIZE_T _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    continue;

                mappedFileName = (UNICODE_STRING)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(UNICODE_STRING));

                if (string.IsNullOrEmpty(mappedFileName.ToString()))
                    continue;

                symbolBuilder.Append(Path.GetFileName(mappedFileName.ToString()));

                if (NativeMethods.SymFromAddr(
                    hProcess,
                    pBuffer.ToInt64(),
                    out long nDisplacement,
                    ref symbolInfo))
                {
                    symbolBuilder.AppendFormat("!{0}", Encoding.ASCII.GetString(symbolInfo.Name).Trim('\0'));

                    if (nDisplacement != 0L)
                        symbolBuilder.AppendFormat("+0x{0}", nDisplacement.ToString("X"));
                }
                else
                {
                    ntstatus = NativeMethods.NtQueryVirtualMemory(
                        hProcess,
                        pBuffer,
                        MEMORY_INFORMATION_CLASS.MemoryImageInformation,
                        pInfoBuffer,
                        new SIZE_T((uint)Marshal.SizeOf(typeof(MEMORY_IMAGE_INFORMATION))),
                        out SIZE_T _);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        int nDelta;
                        var info = (MEMORY_IMAGE_INFORMATION)Marshal.PtrToStructure(
                            pInfoBuffer,
                            typeof(MEMORY_IMAGE_INFORMATION));

                        if (Environment.Is64BitProcess)
                            nDelta = (int)(pBuffer.ToInt64() - info.ImageBase.ToInt64());
                        else
                            nDelta = pBuffer.ToInt32() - info.ImageBase.ToInt32();

                        if (nDelta != 0L)
                            symbolBuilder.AppendFormat("+0x{0}", nDelta.ToString("X"));
                    }
                }

                if (symbolBuilder.Length > 0)
                    symbolTable[pBuffer] = symbolBuilder.ToString();
                else
                    symbolTable[pBuffer] = null;
            } while (false) ;

            NativeMethods.SymCleanup(hProcess);
            Marshal.FreeHGlobal(pInfoBuffer);

            return symbolTable;
        }


        public static IntPtr GetProcessParameters(IntPtr hProcess, IntPtr pPeb, bool bWow32)
        {
            int nOffset;
            uint nStructSize;
            uint nPointerSize;
            IntPtr pBufferToRead;
            IntPtr pInfoBuffer;
            IntPtr pProcessParametersBuffer;
            var pProcessParameters = IntPtr.Zero;

            if (!Environment.Is64BitProcess || bWow32)
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

                pInfoBuffer = ReadMemory(hProcess, pBufferToRead, nPointerSize, out uint _);

                if (pInfoBuffer == IntPtr.Zero)
                    break;

                if (nPointerSize == 8)
                    pProcessParametersBuffer = new IntPtr(Marshal.ReadInt64(pInfoBuffer));
                else
                    pProcessParametersBuffer = new IntPtr(Marshal.ReadInt32(pInfoBuffer));

                Marshal.FreeHGlobal(pInfoBuffer);
                pProcessParameters = ReadMemory(hProcess, pProcessParametersBuffer, nStructSize, out uint _);
            } while (false);

            return pProcessParameters;
        }


        public static bool GetProcessThreadInformation(
            int pid,
            out List<SYSTEM_THREAD_INFORMATION> threadInfo,
            out Dictionary<IntPtr, string> symbolTable)
        {
            int nDosErrorCode;
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.PROCESS_QUERY_INFORMATION,
                in objectAttributes,
                in clientId);
            threadInfo = new List<SYSTEM_THREAD_INFORMATION>();

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var hThread = IntPtr.Zero;
                var addresses = new List<IntPtr>();

                do
                {
                    ntstatus = NativeMethods.NtGetNextThread(
                        hProcess,
                        hThread,
                        ACCESS_MASK.THREAD_QUERY_LIMITED_INFORMATION,
                        OBJECT_ATTRIBUTES_FLAGS.None,
                        0u,
                        out IntPtr hNextThread);

                    if (hThread != IntPtr.Zero)
                        NativeMethods.NtClose(hThread);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        var nInfoLength = (uint)Marshal.SizeOf(typeof(SYSTEM_THREAD_INFORMATION));
                        var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                        ntstatus = NativeMethods.NtQueryInformationThread(
                            hNextThread,
                            THREADINFOCLASS.ThreadSystemThreadInformation,
                            pInfoBuffer,
                            nInfoLength,
                            out uint _);

                        if (ntstatus == Win32Consts.STATUS_SUCCESS)
                        {
                            var info = (SYSTEM_THREAD_INFORMATION)Marshal.PtrToStructure(
                                pInfoBuffer,
                                typeof(SYSTEM_THREAD_INFORMATION));

                            ntstatus = NativeMethods.NtDuplicateObject(
                                new IntPtr(-1),
                                hNextThread,
                                new IntPtr(-1),
                                out IntPtr hQueryThread,
                                ACCESS_MASK.THREAD_QUERY_INFORMATION,
                                OBJECT_ATTRIBUTES_FLAGS.None,
                                DUPLICATE_OPTION_FLAGS.NONE);

                            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                            {
                                ntstatus = NativeMethods.NtQueryInformationThread(
                                    hQueryThread,
                                    THREADINFOCLASS.ThreadQuerySetWin32StartAddress,
                                    pInfoBuffer,
                                    8u,
                                    out uint _);

                                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                                    info.StartAddress = Marshal.ReadIntPtr(pInfoBuffer);
                            }
                            else
                            {
                                info.StartAddress = IntPtr.Zero;
                            }

                            threadInfo.Add(info);

                            if (!addresses.Contains(info.StartAddress))
                                addresses.Add(info.StartAddress);
                        }

                        Marshal.FreeHGlobal(pInfoBuffer);
                        hThread = hNextThread;
                        ntstatus = Win32Consts.STATUS_SUCCESS;
                    }
                } while (ntstatus == Win32Consts.STATUS_SUCCESS);

                symbolTable = GetProcessMemorySymbols(hProcess, addresses);

                NativeMethods.NtClose(hProcess);
            }
            else
            {
                symbolTable = new Dictionary<IntPtr, string>();
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (threadInfo.Count > 0);
        }


        public static IntPtr GetProcessToken(int pid, TOKEN_TYPE tokenType)
        {
            NTSTATUS ntstatus;
            var hDupToken = IntPtr.Zero;
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            var objectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var nContextSize = Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE));
            var context = new SECURITY_QUALITY_OF_SERVICE
            {
                Length = nContextSize,
                ImpersonationLevel = SECURITY_IMPERSONATION_LEVEL.Impersonation
            };
            var pContextBuffer = Marshal.AllocHGlobal(nContextSize);
            Marshal.StructureToPtr(context, pContextBuffer, true);

            if (tokenType == TOKEN_TYPE.Impersonation)
                objectAttributes.SecurityQualityOfService = pContextBuffer;

            do
            {
                ntstatus = NativeMethods.NtOpenProcess(
                    out IntPtr hProcess,
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NtOpenProcessToken(
                    hProcess,
                    ACCESS_MASK.TOKEN_DUPLICATE,
                    out IntPtr hToken);
                NativeMethods.NtClose(hProcess);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                ntstatus = NativeMethods.NtDuplicateToken(
                    hToken,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    in objectAttributes,
                    BOOLEAN.FALSE,
                    tokenType,
                    out hDupToken);
                NativeMethods.NtClose(hToken);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hDupToken = IntPtr.Zero;
            } while (false);

            ntstatus = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(ntstatus);
            Marshal.FreeHGlobal(pContextBuffer);

            return hDupToken;
        }


        public static bool GetTokenPrivileges(
            IntPtr hToken,
            out Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES> privileges)
        {
            int nDosErrorCode;
            var nOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
            var nUnitSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
            var nInfoLength = (uint)(nOffset + (nUnitSize * 36));
            var pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                pInfoBuffer,
                nInfoLength,
                out uint _);
            privileges = new Dictionary<SE_PRIVILEGE_ID, SE_PRIVILEGE_ATTRIBUTES>();

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                int nPrivilegeCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nPrivilegeCount; idx++)
                {
                    privileges.Add(
                        (SE_PRIVILEGE_ID)Marshal.ReadInt32(pInfoBuffer, nOffset),
                        (SE_PRIVILEGE_ATTRIBUTES)Marshal.ReadInt32(pInfoBuffer, nOffset + 8));
                    nOffset += nUnitSize;
                }
            }

            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);
            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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


        public static string GetWin32ErrorMessage(int nDosErrorCode)
        {
            int nSizeMesssage = 256;
            var message = new StringBuilder(nSizeMesssage);
            int nReturnedLength = NativeMethods.FormatMessage(
                FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM,
                IntPtr.Zero,
                nDosErrorCode,
                0,
                message,
                nSizeMesssage,
                IntPtr.Zero);

            if (nReturnedLength == 0)
                return string.Format("[ERROR] Code 0x{0}", nDosErrorCode.ToString("X8"));
            else
                return string.Format("[ERROR] Code 0x{0} : {1}", nDosErrorCode.ToString("X8"), message.ToString().Trim());
        }


        public static bool ImpersonateThreadToken(IntPtr hThread, IntPtr hToken)
        {
            NTSTATUS ntstatus;
            int nDosErrorCode;
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            var bSuccess = false;
            Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Zero);

            do
            {
                SECURITY_IMPERSONATION_LEVEL originalLevel;
                SECURITY_IMPERSONATION_LEVEL grantedLevel;
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pInfoBuffer,
                    4u,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;
                else
                    originalLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pInfoBuffer);

                Marshal.WriteIntPtr(pInfoBuffer, hToken);
                ntstatus = NativeMethods.NtSetInformationThread(
                    hThread,
                    THREADINFOCLASS.ThreadImpersonationToken,
                    pInfoBuffer,
                    (uint)IntPtr.Size);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pInfoBuffer,
                    4u,
                    out uint _);
                grantedLevel = (SECURITY_IMPERSONATION_LEVEL)Marshal.ReadInt32(pInfoBuffer);
                bSuccess = (grantedLevel == originalLevel);

                if (bSuccess)
                    ntstatus = Win32Consts.STATUS_PRIVILEGE_NOT_HELD;
            } while (false);

            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError((int)ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return bSuccess;
        }


        public static bool IsValidPeData(
            IntPtr pInfoBuffer,
            uint nInfoLength,
            out IMAGE_FILE_MACHINE architecture,
            out bool bIs64BitImageData,
            out List<IMAGE_SECTION_HEADER> sectionHeaders)
        {
            var bIsValidPeData = false;
            architecture = IMAGE_FILE_MACHINE.UNKNOWN;
            bIs64BitImageData = false;
            sectionHeaders = new List<IMAGE_SECTION_HEADER>();

            do
            {
                ushort magic;
                int e_lfanew;
                int nNumberOfSections;
                int nSizeOfOptionalHeader;
                int nSectionHeaderOffset;
                int nSizeOfSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

                if ((Marshal.ReadInt16(pInfoBuffer) != 0x5A4D) || (nInfoLength < 0x40u))
                    break;

                e_lfanew = Marshal.ReadInt32(pInfoBuffer, 0x3C);

                if ((uint)(e_lfanew + 0x88) > nInfoLength)
                    break;

                if (Marshal.ReadInt32(pInfoBuffer, e_lfanew) != 0x4550)
                    break;

                architecture = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pInfoBuffer, e_lfanew + 4);

                if (!Enum.IsDefined(typeof(IMAGE_FILE_MACHINE), architecture))
                    break;

                magic = (ushort)Marshal.ReadInt16(pInfoBuffer, e_lfanew + 0x18);

                if (magic == 0x20B)
                    bIs64BitImageData = true;
                else if (magic == 0x10B)
                    bIs64BitImageData = false;
                else
                    break;

                nNumberOfSections = (int)(ushort)Marshal.ReadInt16(pInfoBuffer, e_lfanew + 0x6);
                nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pInfoBuffer, e_lfanew + 0x14);
                nSectionHeaderOffset = e_lfanew + 0x18 + nSizeOfOptionalHeader;
                bIsValidPeData = ((uint)(nSectionHeaderOffset + (nNumberOfSections * nSizeOfSectionHeader)) < nInfoLength);

                if (!bIsValidPeData)
                    break;

                for (var idx = 0; idx < nNumberOfSections; idx++)
                {
                    IntPtr pSectionHeader;

                    if (Environment.Is64BitProcess)
                        pSectionHeader = new IntPtr(pInfoBuffer.ToInt64() + nSectionHeaderOffset + (idx * nSizeOfSectionHeader));
                    else
                        pSectionHeader = new IntPtr(pInfoBuffer.ToInt32() + nSectionHeaderOffset + (idx * nSizeOfSectionHeader));

                    sectionHeaders.Add((IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pSectionHeader,
                        typeof(IMAGE_SECTION_HEADER)));
                }
            } while (false);


            return bIsValidPeData;
        }


        public static IntPtr ReadMemory(
            IntPtr hProcess,
            IntPtr pReadAddress,
            uint nSizeToRead,
            out uint nReturnedBytes)
        {
            NTSTATUS ntstatus;
            IntPtr pBuffer = Marshal.AllocHGlobal((int)nSizeToRead);

            for (var idx = 0; idx < (int)nSizeToRead; idx++)
                Marshal.WriteByte(pBuffer, idx, 0);

            ntstatus = NativeMethods.NtReadVirtualMemory(
                hProcess,
                pReadAddress,
                pBuffer,
                nSizeToRead,
                out nReturnedBytes);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Marshal.FreeHGlobal(pBuffer);
                pBuffer = IntPtr.Zero;
                nReturnedBytes = 0u;
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
                unicodeString.MaximumLength,
                out uint _);

            if (pBuffer == IntPtr.Zero)
                return null;

            result = Marshal.PtrToStringUni(pBuffer);
            Marshal.FreeHGlobal(pBuffer);

            return result;
        }


        public static bool RevertThreadToken(IntPtr hThread)
        {
            int nDosErrorCode;
            NTSTATUS ntstatus;
            var pInfoBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pInfoBuffer, IntPtr.Zero);
            ntstatus = NativeMethods.NtSetInformationThread(
                hThread,
                THREADINFOCLASS.ThreadImpersonationToken,
                pInfoBuffer,
                (uint)IntPtr.Size);
            Marshal.FreeHGlobal(pInfoBuffer);
            nDosErrorCode = (int)NativeMethods.RtlNtStatusToDosError(ntstatus);
            NativeMethods.RtlSetLastWin32Error(nDosErrorCode);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
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
