using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using SdDumper.Interop;

namespace SdDumper.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string strSid,
            out string accountName,
            out SID_NAME_USE peUse)
        {
            bool status;
            int error;
            int cchName = 4;
            int cchReferencedDomainName = 4;
            var pName = new StringBuilder();
            var pReferencedDomainName = new StringBuilder();
            strSid = null;
            accountName = null;
            peUse = SID_NAME_USE.SidTypeUnknown;

            if (!NativeMethods.IsValidSid(pSid))
                return false;

            if (!NativeMethods.ConvertSidToStringSid(pSid, out strSid))
            {
                strSid = null;

                return false;
            }

            if (Regex.IsMatch(strSid, @"^S-1-19-"))
            {
                pReferencedDomainName.Append("TRUST LEVEL");

                if (string.Compare(strSid, "S-1-19-512-1024", true) == 0)
                    pName.Append("ProtectedLight-Authenticode");
                else if (string.Compare(strSid, "S-1-19-512-1536", true) == 0)
                    pName.Append("ProtectedLight-AntiMalware");
                else if (string.Compare(strSid, "S-1-19-512-2048", true) == 0)
                    pName.Append("ProtectedLight-App");
                else if (string.Compare(strSid, "S-1-19-512-4096", true) == 0)
                    pName.Append("ProtectedLight-Windows");
                else if (string.Compare(strSid, "S-1-19-512-8192", true) == 0)
                    pName.Append("ProtectedLight-WinTcb");
                else if (string.Compare(strSid, "S-1-19-1024-1024", true) == 0)
                    pName.Append("Protected-Authenticode");
                else if (string.Compare(strSid, "S-1-19-1024-1536", true) == 0)
                    pName.Append("Protected-AntiMalware");
                else if (string.Compare(strSid, "S-1-19-1024-2048", true) == 0)
                    pName.Append("Protected-App");
                else if (string.Compare(strSid, "S-1-19-1024-4096", true) == 0)
                    pName.Append("Protected-Windows");
                else if (string.Compare(strSid, "S-1-19-1024-8192", true) == 0)
                    pName.Append("Protected-WinTcb");
                else
                    pReferencedDomainName.Clear();

                cchName = pName.Length;
                cchReferencedDomainName = pReferencedDomainName.Length;
                status = ((cchName > 0) && (cchReferencedDomainName > 0));
            }
            else
            {
                do
                {
                    pName.Capacity = cchName;
                    pReferencedDomainName.Capacity = cchReferencedDomainName;

                    status = NativeMethods.LookupAccountSid(
                        null,
                        pSid,
                        pName,
                        ref cchName,
                        pReferencedDomainName,
                        ref cchReferencedDomainName,
                        out peUse);
                    error = Marshal.GetLastWin32Error();

                    if (!status)
                    {
                        pName.Clear();
                        pReferencedDomainName.Clear();
                    }
                } while (!status && error == Win32Consts.ERROR_INSUFFICIENT_BUFFER);
            }

            if (!status)
            {
                accountName = "N/A";
                peUse = SID_NAME_USE.SidTypeUnknown;
            }
            else
            {
                if ((cchName == 0) && (cchReferencedDomainName > 0))
                    accountName = pReferencedDomainName.ToString();
                else if ((cchName > 0) && (cchReferencedDomainName == 0))
                    accountName = pName.ToString();
                else if ((cchName > 0) && (cchReferencedDomainName > 0))
                    accountName = string.Format(@"{0}\{1}", pReferencedDomainName.ToString(), pName.ToString());
                else
                    accountName = "N/A";
            }

            return true;
        }


        public static bool EnumNtDirectoryItems(
            IntPtr hDirectory,
            out Dictionary<string, string> items)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            IntPtr pUnicodeString;
            IntPtr pStringBuffer;
            string objectName;
            string objectType;
            uint nBufferSize;
            uint counter = 1;
            int nUnicodeStringSize = Marshal.SizeOf(typeof(UNICODE_STRING));
            int nBufferOffset = Marshal.OffsetOf(typeof(UNICODE_STRING), "buffer").ToInt32();
            uint nContext = 0u;
            items = new Dictionary<string, string>();

            do
            {
                nBufferSize = 0x1000 * counter;
                pInfoBuffer = Marshal.AllocHGlobal((int)nBufferSize);
                ntstatus = NativeMethods.NtQueryDirectoryObject(
                    hDirectory,
                    pInfoBuffer,
                    nBufferSize,
                    BOOLEAN.FALSE,
                    BOOLEAN.TRUE,
                    ref nContext,
                    IntPtr.Zero);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Marshal.FreeHGlobal(pInfoBuffer);
                    pInfoBuffer = IntPtr.Zero;
                    counter++;
                }
            } while ((ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL) || (ntstatus == Win32Consts.STATUS_MORE_ENTRIES));

            if (pInfoBuffer == IntPtr.Zero)
                return false;

            pUnicodeString = pInfoBuffer;

            while (Marshal.ReadIntPtr(pUnicodeString, nBufferOffset) != IntPtr.Zero)
            {
                pStringBuffer = Marshal.ReadIntPtr(pUnicodeString, nBufferOffset);
                objectName = Marshal.PtrToStringUni(pStringBuffer, Marshal.ReadInt16(pUnicodeString) / 2);
                pStringBuffer = Marshal.ReadIntPtr(pUnicodeString, nBufferOffset + nUnicodeStringSize);
                objectType = Marshal.PtrToStringUni(pStringBuffer, Marshal.ReadInt16(pUnicodeString, nUnicodeStringSize) / 2);
                items.Add(objectName, objectType);

                if (Environment.Is64BitProcess)
                    pUnicodeString = new IntPtr(pUnicodeString.ToInt64() + (nUnicodeStringSize * 2));
                else
                    pUnicodeString = new IntPtr(pUnicodeString.ToInt32() + (nUnicodeStringSize * 2));
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (items.Count > 0);
        }


        public static bool GetNtObjectType(ref string ntPath, out string typeName)
        {
            NTSTATUS ntstatus;
            OBJECT_ATTRIBUTES objectAttributes;
            bool status = false;
            string directoryPath;
            string objectPath;
            var compareOption = StringComparison.OrdinalIgnoreCase;
            ntPath = ntPath.Replace('/', '\\').TrimEnd('\\');
            directoryPath = Regex.Replace(ntPath, @"\\[^\\]+$", string.Empty);
            directoryPath = string.IsNullOrEmpty(directoryPath) ? @"\" : directoryPath;
            objectAttributes = new OBJECT_ATTRIBUTES(
                directoryPath,
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);
            typeName = null;

            do
            {
                if (string.IsNullOrEmpty(ntPath))
                {
                    ntPath = @"\";
                    typeName = "Directory";
                    status = true;
                    break;
                }

                ntstatus = NativeMethods.NtOpenDirectoryObject(
                    out IntPtr hDirectory,
                    ACCESS_MASK.DIRECTORY_QUERY,
                    in objectAttributes);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                EnumNtDirectoryItems(hDirectory, out Dictionary<string, string> items);

                foreach (var item in items)
                {
                    objectPath = string.Format(@"{0}\{1}", directoryPath.TrimEnd('\\'), item.Key);

                    if (string.Compare(objectPath, ntPath, compareOption) == 0)
                    {
                        typeName = item.Value;
                        status = true;
                        break;
                    }
                }

                NativeMethods.NtClose(hDirectory);
            } while (false);

            objectAttributes.Dispose();

            return status;
        }


        public static bool GetInformationFromToken(
            IntPtr hToken,
            TOKEN_INFORMATION_CLASS tokenInformationClass,
            out IntPtr pTokenInformation)
        {
            NTSTATUS ntstatus;
            int nTokenInformationLength = 4;

            do
            {
                pTokenInformation = Marshal.AllocHGlobal(nTokenInformationLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    tokenInformationClass,
                    pTokenInformation,
                    (uint)nTokenInformationLength,
                    out uint nReturnLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    nTokenInformationLength = (int)nReturnLength;
                    Marshal.FreeHGlobal(pTokenInformation);
                    pTokenInformation = IntPtr.Zero;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetPrivilegeLuid(string privilegeName, out LUID luid)
        {
            int error;

            if (!NativeMethods.LookupPrivilegeValue(
                null,
                privilegeName,
                out luid))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to lookup {0}.", privilegeName);
                Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(error, false));

                return false;
            }

            return true;
        }


        public static string GetPrivilegeName(LUID priv)
        {
            int error;
            int cchName = 255;
            StringBuilder privilegeName = new StringBuilder(255);

            if (!NativeMethods.LookupPrivilegeName(
                null,
                ref priv,
                privilegeName,
                ref cchName))
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to lookup privilege name.");
                Console.WriteLine("    |-> {0}", GetWin32ErrorMessage(error, false));

                return null;
            }

            return privilegeName.ToString();
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


        public static void MoveMemory(IntPtr pSrc, int nOffset, IntPtr pDst, int nSize)
        {
            for (var idx = 0; idx < nSize; idx++)
                Marshal.WriteByte(pDst, idx, Marshal.ReadByte(pSrc, nOffset + idx));
        }


        public static string ReadUnicodeString(IntPtr pSrc, int nOffset, int nLength)
        {
            string result;
            IntPtr pTempBuffer = Marshal.AllocHGlobal(nLength + 2);
            ZeroMemory(pTempBuffer, nLength + 2);
            MoveMemory(pSrc, nOffset, pTempBuffer, nLength);
            result = Marshal.PtrToStringUni(pTempBuffer);
            Marshal.FreeHGlobal(pTempBuffer);

            return result;
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            for (var offset = 0; offset < size; offset++)
                Marshal.WriteByte(buffer, offset, 0);
        }
    }
}
