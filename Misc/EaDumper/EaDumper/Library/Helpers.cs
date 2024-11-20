using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using EaDumper.Interop;

namespace EaDumper.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
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


        public static NTSTATUS GetEaInformationFromFile(string filePath, out IntPtr pEaInfoBuffer)
        {
            NTSTATUS ntstatus;
            OBJECT_ATTRIBUTES objectAttributes;
            int nEaBufferSize = 0x100;
            pEaInfoBuffer = IntPtr.Zero;
            filePath = string.Format(@"\??\{0}", Path.GetFullPath(filePath.Replace('/', '\\')));

            objectAttributes = new OBJECT_ATTRIBUTES(filePath, OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);

            ntstatus = NativeMethods.NtOpenFile(
                out IntPtr hFile,
                ACCESS_MASK.READ_CONTROL | ACCESS_MASK.FILE_READ_EA,
                in objectAttributes,
                out IO_STATUS_BLOCK _,
                FILE_SHARE.NONE,
                FILE_CREATE_OPTIONS.NONE);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return ntstatus;

            do
            {
                nEaBufferSize <<= 1;
                pEaInfoBuffer = Marshal.AllocHGlobal(nEaBufferSize);

                ntstatus = NativeMethods.NtQueryEaFile(
                    hFile,
                    out IO_STATUS_BLOCK _,
                    pEaInfoBuffer,
                    (uint)nEaBufferSize,
                    BOOLEAN.FALSE,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    BOOLEAN.TRUE);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pEaInfoBuffer);
                    pEaInfoBuffer = IntPtr.Zero;
                }
            } while ((ntstatus == Win32Consts.STATUS_BUFFER_OVERFLOW) || (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL));

            NativeMethods.NtClose(hFile);

            return ntstatus;
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


        public static void ParseEsbCache(byte[] cacheData)
        {
            ushort ciMajorVersion = BitConverter.ToUInt16(cacheData, 4);
            int nCounter = 0;
            int nCurrentExtraDataSize = 0;
            IntPtr pBuffer = Marshal.AllocHGlobal(cacheData.Length);
            Marshal.Copy(cacheData, 0, pBuffer, cacheData.Length);

            if (ciMajorVersion == 3)
            {
                var ciEsbEaV3Data = (CI_ESB_EA_V3)Marshal.PtrToStructure(pBuffer, typeof(CI_ESB_EA_V3));

                Console.WriteLine("    [*] Parsed EA Cache Data");
                Console.WriteLine("        [*] Major Version        : {0}", ciEsbEaV3Data.MajorVersion);
                Console.WriteLine("        [*] Minor Version        : {0}", ciEsbEaV3Data.MinorVersion);
                Console.WriteLine("        [*] Signing Level        : {0}", ciEsbEaV3Data.SignerLevel.ToString());
                Console.WriteLine("        [*] USN Journal ID       : 0x{0}", ciEsbEaV3Data.UsnJournalId.ToInt64().ToString("X16"));
                Console.WriteLine("        [*] Last Black List Time : {0}", ConvertLargeIntegerToLocalTimeString(ciEsbEaV3Data.LastBlackListTime));
                Console.WriteLine("        [*] Flags                : {0}", ((CachedSigningLevelFlags)ciEsbEaV3Data.Flags).ToString());

                while (nCurrentExtraDataSize < ciEsbEaV3Data.ExtraDataSize)
                {
                    var hashStringBuilder = new StringBuilder();
                    int nExtraDataOffset = Marshal.OffsetOf(typeof(CI_ESB_EA_V3), "ExtraData").ToInt32();
                    var blobType = (CI_DATA_BLOB_TYPE)Marshal.ReadByte(pBuffer, nCurrentExtraDataSize + nExtraDataOffset + 1);

                    Console.WriteLine("        [*] Extra Data[0x{0}]", nCounter.ToString("X2"));

                    if ((blobType == CI_DATA_BLOB_TYPE.FileHash) ||
                        (blobType == CI_DATA_BLOB_TYPE.SignerHash) ||
                        (blobType == CI_DATA_BLOB_TYPE.DeviceGuardPolicyHash) ||
                        (blobType == CI_DATA_BLOB_TYPE.AntiCheatPolicyHash))
                    {
                        Console.WriteLine("            [*] Blob Type      : {0}", blobType.ToString());
                        Console.WriteLine("            [*] Hash Algorithm : {0}", ((HASH_ALGORITHM)Marshal.ReadInt32(pBuffer, nCurrentExtraDataSize + nExtraDataOffset + 2)));

                        for (var index = 0; index < Marshal.ReadByte(pBuffer, nCurrentExtraDataSize + nExtraDataOffset + 6); index++)
                        {
                            hashStringBuilder.Append(Marshal.ReadByte(pBuffer, nCurrentExtraDataSize + nExtraDataOffset + 7 + index).ToString("X2"));
                        }

                        Console.WriteLine("            [*] Hash Value     : {0}", hashStringBuilder.ToString());
                    }

                    hashStringBuilder.Clear();
                    nCurrentExtraDataSize += (int)Marshal.ReadByte(pBuffer, nCurrentExtraDataSize + nExtraDataOffset);
                    nCounter++;
                }

                Console.WriteLine();
            }

            Marshal.FreeHGlobal(pBuffer);
        }


        public static void ParseFileFullEaInformation(
            IntPtr /* PFILE_FULL_EA_INFORMATION */ pFileFullEaInformation,
            out EA_INFORMATION_FLAGS flags,
            out string eaName,
            out byte[] eaValue,
            out IntPtr pNextEntry) // Should be nullptr for last entry.
        {
            IntPtr pNameBuffer;
            IntPtr pValueBuffer;
            int nDataOffset = Marshal.OffsetOf(typeof(FILE_FULL_EA_INFORMATION), "EaName").ToInt32();
            var fileFullEaInformation = (FILE_FULL_EA_INFORMATION)Marshal.PtrToStructure(
                pFileFullEaInformation,
                typeof(FILE_FULL_EA_INFORMATION));

            if (Environment.Is64BitProcess)
            {
                pNameBuffer = new IntPtr(pFileFullEaInformation.ToInt64() + nDataOffset);
                pValueBuffer = new IntPtr(pNameBuffer.ToInt64() + fileFullEaInformation.EaNameLength + 1);

                if (fileFullEaInformation.NextEntryOffset > 0)
                    pNextEntry = new IntPtr(pFileFullEaInformation.ToInt64() + fileFullEaInformation.NextEntryOffset);
                else
                    pNextEntry = IntPtr.Zero;
            }
            else
            {
                pNameBuffer = new IntPtr(pFileFullEaInformation.ToInt32() + nDataOffset);
                pValueBuffer = new IntPtr(pNameBuffer.ToInt32() + fileFullEaInformation.EaNameLength + 1);

                if (fileFullEaInformation.NextEntryOffset > 0)
                    pNextEntry = new IntPtr(pFileFullEaInformation.ToInt32() + fileFullEaInformation.NextEntryOffset);
                else
                    pNextEntry = IntPtr.Zero;
            }

            eaName = Marshal.PtrToStringAnsi(pNameBuffer);
            eaValue = new byte[fileFullEaInformation.EaValueLength];
            flags = fileFullEaInformation.Flags;

            Marshal.Copy(pValueBuffer, eaValue, 0, fileFullEaInformation.EaValueLength);
        }


        /*public static string ReadSignerHash(IntPtr pEaHashBlob, out SIGNER_HASH_ALGORITHM algorithm)
        {
            var hash = new StringBuilder();
            int nHashLength = Marshal.ReadByte(pEaHashBlob, 4);
            algorithm = (SIGNER_HASH_ALGORITHM)Marshal.ReadInt32(pEaHashBlob);

            for (var offset = 0; offset < nHashLength; offset++)
                hash.Append(Marshal.ReadByte(pEaHashBlob, 5 + offset).ToString("X2"));

            return hash.ToString();
        }*/
    }
}
