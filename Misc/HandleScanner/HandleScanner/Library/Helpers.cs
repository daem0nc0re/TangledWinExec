using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using HandleScanner.Interop;

namespace HandleScanner.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        /*
         * Struct Definition
         */
        [StructLayout(LayoutKind.Sequential)]
        public struct FileQueryContext
        {
            public NTSTATUS Status;
            public IntPtr FileHandle;
            public IntPtr ExitEventHandle;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string FilePath;
        }

        /*
         * Thread Routine
         */
        private static void FileQueryRoutine(object threadParameter)
        {
            if (threadParameter.GetType() == typeof(IntPtr))
            {
                IntPtr pContext = (IntPtr)threadParameter;
                NTSTATUS ntstatus = Win32Consts.STATUS_UNSUCCESSFUL;
                var nInfoLength = 0x400u;
                var threadContext = (FileQueryContext)Marshal.PtrToStructure(
                    pContext,
                    typeof(FileQueryContext));
                IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                Marshal.WriteInt32(pContext, ntstatus);

                for (int idx = 0; idx < (int)nInfoLength; idx++)
                    Marshal.WriteByte(pInfoBuffer, idx, 0);

                threadContext.Status = NativeMethods.NtQueryObject(
                    threadContext.FileHandle,
                    OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out uint _);

                if (threadContext.Status == Win32Consts.STATUS_SUCCESS)
                {
                    var nameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(
                        pInfoBuffer,
                        typeof(OBJECT_NAME_INFORMATION));
                    threadContext.FilePath = nameInfo.Name.ToString();
                }

                Marshal.StructureToPtr(threadContext, pContext, true);
                Marshal.FreeHGlobal(pInfoBuffer);
                NativeMethods.NtSetEvent(threadContext.ExitEventHandle, out int _);
            }
        }

        /*
         * Function Definition
         */
        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static bool ConvertSidToAccountName(
            IntPtr pSid,
            out string name,
            out string domainName,
            out SID_NAME_USE sidType)
        {
            int nNameLength = 255;
            int nDomainNameLength = 255;
            var nameBuilder = new StringBuilder(nNameLength);
            var domainNameBuilder = new StringBuilder(nDomainNameLength);
            bool status = NativeMethods.LookupAccountSid(
                null,
                pSid,
                nameBuilder,
                ref nNameLength,
                domainNameBuilder,
                ref nDomainNameLength,
                out sidType);

            if (status)
            {
                name = nameBuilder.ToString();
                domainName = domainNameBuilder.ToString();
            }
            else
            {
                name = null;
                domainName = null;
                sidType = SID_NAME_USE.SidTypeUnknown;
            }

            return status;
        }


        public static string GetFileObjectName(IntPtr hFile)
        {
            NTSTATUS ntstatus;
            string objectName = null;
            int ms = 50;
            var timeout = LARGE_INTEGER.FromInt64(-(ms * 10000));
            var context = new FileQueryContext {
                Status = Win32Consts.STATUS_UNSUCCESSFUL,
                FileHandle = hFile
            };
            var nContextSize = Marshal.SizeOf(context);
            var pContext = Marshal.AllocHGlobal(nContextSize);

            do
            {
                ntstatus = NativeMethods.NtCreateEvent(
                    out context.ExitEventHandle,
                    ACCESS_MASK.EVENT_ALL_ACCESS,
                    IntPtr.Zero,
                    EVENT_TYPE.SynchronizationEvent,
                    BOOLEAN.FALSE);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    context.ExitEventHandle = IntPtr.Zero;
                    break;
                }

                Marshal.StructureToPtr(context, pContext, false);

                for (var count = 0; count < 1; count++)
                {
                    var threadRoutine = new Thread(new ParameterizedThreadStart(FileQueryRoutine));
                    threadRoutine.Start(pContext);
                    ntstatus = NativeMethods.NtWaitForSingleObject(context.ExitEventHandle, true, in timeout);

                    if (ntstatus == Win32Consts.STATUS_TIMEOUT)
                    {
                        threadRoutine.Abort();
                    }
                    else
                    {
                        threadRoutine.Join();
                        context = (FileQueryContext)Marshal.PtrToStructure(
                            pContext,
                            typeof(FileQueryContext));

                        if (context.Status == Win32Consts.STATUS_SUCCESS)
                            objectName = context.FilePath;

                        break;
                    }
                }
            } while (false);

            if (context.ExitEventHandle != IntPtr.Zero)
                NativeMethods.NtClose(context.ExitEventHandle);

            return objectName;
        }


        public static string GetObjectName(IntPtr hObject)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string objectName = null;
            var nInfoLength = 0x400u;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryObject(
                    hObject,
                    OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var nameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(OBJECT_NAME_INFORMATION));
                objectName = nameInfo.Name.ToString();
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return objectName;
        }


        public static string GetProcessObjectName(IntPtr hProcess)
        {
            string objectName = null;
            string name = GetProcessNameByHandle(hProcess);

            GetProcessBasicInformation(hProcess, out PROCESS_BASIC_INFORMATION pbi);

            if (!string.IsNullOrEmpty(name) && (pbi.UniqueProcessId != UIntPtr.Zero))
                objectName = string.Format("{0} (PID: {1})", Path.GetFileName(name), pbi.UniqueProcessId);
            else if (pbi.UniqueProcessId != UIntPtr.Zero)
                objectName = string.Format("N/A (PID: {0})", pbi.UniqueProcessId);
            else if (!string.IsNullOrEmpty(name))
                objectName = string.Format("{0} (PID: N/A)", Path.GetFileName(name));

            return objectName;
        }


        public static string GetThreadObjectName(IntPtr hThread)
        {
            string objectName = null;

            if (GetThreadBasicInformation(hThread, out THREAD_BASIC_INFORMATION threadInfo))
            {
                string name;

                try
                {
                    name = Process.GetProcessById(threadInfo.ClientId.UniqueProcess.ToInt32()).ProcessName;
                }
                catch
                {
                    name = null;
                }

                if (!string.IsNullOrEmpty(name))
                {
                    objectName = string.Format(
                        "{0} (PID: {1}, TID: {2})",
                        name, threadInfo.ClientId.UniqueProcess, threadInfo.ClientId.UniqueThread);
                }
            }

            return objectName;
        }


        public static string GetTokenObjectName(IntPtr hToken)
        {
            string objectName = null;
            string tokenInfo = null;
            var status = GetTokenUser(
                hToken,
                out string _,
                out string name,
                out string domain,
                out SID_NAME_USE _);

            if (status)
            {
                if (GetTokenStatistics(hToken, out TOKEN_STATISTICS stats))
                {
                    tokenInfo = string.Format(
                        "AuthId: 0x{0}, Type: {1}",
                        stats.AuthenticationId.ToInt64().ToString("X"),
                        stats.TokenType.ToString());
                }

                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(domain))
                    objectName = string.Format(@"{0}\{1}", domain, name);
                else if (!string.IsNullOrEmpty(name))
                    objectName = string.Format("{0}", name);
                else if (!string.IsNullOrEmpty(domain))
                    objectName = string.Format("{0}", domain);

                if (!string.IsNullOrEmpty(objectName) && !string.IsNullOrEmpty(tokenInfo))
                    objectName = string.Format("{0} ({1})", objectName, tokenInfo);
            }

            return objectName;
        }


        public static Dictionary<int, string> GetObjectTypeTable()
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoSize = (uint)Marshal.SizeOf(typeof(OBJECT_TYPES_INFORMATION));
            var table = new Dictionary<int, string>();

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoSize);
                ntstatus = NativeMethods.NtQueryObject(
                    IntPtr.Zero,
                    OBJECT_INFORMATION_CLASS.ObjectTypesInformation,
                    pInfoBuffer,
                    nInfoSize,
                    out nInfoSize);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pEntry;
                var nEntryCount = Marshal.ReadInt32(pInfoBuffer);

                if (Environment.Is64BitProcess)
                    pEntry = new IntPtr(pInfoBuffer.ToInt64() + IntPtr.Size);
                else
                    pEntry = new IntPtr(pInfoBuffer.ToInt32() + IntPtr.Size);

                for (var idx = 0; idx < nEntryCount; idx++)
                {
                    var entry = (OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(
                        pEntry,
                        typeof(OBJECT_TYPE_INFORMATION));
                    var nNextOffset = Marshal.SizeOf(typeof(OBJECT_TYPE_INFORMATION));
                    nNextOffset += entry.TypeName.MaximumLength;

                    if ((nNextOffset % IntPtr.Size) > 0)
                        nNextOffset += (IntPtr.Size - (nNextOffset % IntPtr.Size));

                    table.Add((int)entry.TypeIndex, entry.TypeName.ToString());

                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pEntry.ToInt64() + nNextOffset);
                    else
                        pEntry = new IntPtr(pEntry.ToInt32() + nNextOffset);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return table;
        }


        public static bool GetProcessBasicInformation(
            IntPtr hProcess,
            out PROCESS_BASIC_INFORMATION pbi)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                nInfoLength,
                out uint _);

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


        public static string GetProcessNameByHandle(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            string processName = null;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(UNICODE_STRING));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessImageFileName,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var nameData = (UNICODE_STRING)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(UNICODE_STRING));
                processName = nameData.ToString();
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return processName;
        }


        public static bool GetSystemHandleInformation(
            out Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>> info)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoSize = (uint)Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION));
            info = new Dictionary<int, List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>>();

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoSize);
                ntstatus = NativeMethods.NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                    pInfoBuffer,
                    nInfoSize,
                    out nInfoSize);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pEntry;
                var nEntrySize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                var nEntryOffset = (int)Marshal.OffsetOf(typeof(SYSTEM_HANDLE_INFORMATION), "Handles");
                var nEntryCount = Marshal.ReadInt32(pInfoBuffer);

                for (var idx = 0; idx < nEntryCount; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pEntry = new IntPtr(pInfoBuffer.ToInt64() + nEntryOffset + (nEntrySize * idx));
                    else
                        pEntry = new IntPtr(pInfoBuffer.ToInt32() + nEntryOffset + (nEntrySize * idx));

                    var entry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(
                        pEntry,
                        typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));

                    if (info.ContainsKey(entry.UniqueProcessId))
                    {
                        info[entry.UniqueProcessId].Add(entry);
                    }
                    else
                    {
                        info.Add(
                            entry.UniqueProcessId,
                            new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> { entry });
                    }
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetThreadBasicInformation(IntPtr hThread, out THREAD_BASIC_INFORMATION info)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(THREAD_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationThread(
                hThread,
                THREADINFOCLASS.ThreadBasicInformation,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                info = (THREAD_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(THREAD_BASIC_INFORMATION));
            }
            else
            {
                info = new THREAD_BASIC_INFORMATION();
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenPrivileges(
            IntPtr hToken,
            out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> privileges)
        {
            NTSTATUS ntstatus;
            IntPtr pInformationBuffer;
            var nInformationLength = (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
            privileges = new Dictionary<string, SE_PRIVILEGE_ATTRIBUTES>();

            do
            {
                pInformationBuffer = Marshal.AllocHGlobal((int)nInformationLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    pInformationBuffer,
                    nInformationLength,
                    out nInformationLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInformationBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var tokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                    pInformationBuffer,
                    typeof(TOKEN_PRIVILEGES));
                var nEntryOffset = Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES), "Privileges").ToInt32();
                var nUnitSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));

                for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
                {
                    int cchName = 128;
                    var stringBuilder = new StringBuilder(cchName);
                    var luid = LUID.FromInt64(Marshal.ReadInt64(pInformationBuffer, nEntryOffset + (nUnitSize * idx)));
                    var nAttributesOffset = Marshal.OffsetOf(typeof(LUID_AND_ATTRIBUTES), "Attributes").ToInt32();
                    var attributes = (SE_PRIVILEGE_ATTRIBUTES)Marshal.ReadInt32(
                        pInformationBuffer,
                        nEntryOffset + (nUnitSize * idx) + nAttributesOffset);

                    NativeMethods.LookupPrivilegeName(null, in luid, stringBuilder, ref cchName);
                    privileges.Add(stringBuilder.ToString(), attributes);
                    stringBuilder.Clear();
                }

                Marshal.FreeHGlobal(pInformationBuffer);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenStatistics(IntPtr hToken, out TOKEN_STATISTICS info)
        {
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_STATISTICS));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
            NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenStatistics,
                pInfoBuffer,
                nInfoLength,
                out uint _);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                info = (TOKEN_STATISTICS)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_STATISTICS));
                Marshal.FreeHGlobal(pInfoBuffer);
            }
            else
            {
                info = new TOKEN_STATISTICS();
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetTokenUser(
            IntPtr hToken,
            out string stringSid,
            out string name,
            out string domainName,
            out SID_NAME_USE sidType)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var nInfoLength = (uint)Marshal.SizeOf(typeof(TOKEN_USER));
            var status = false;
            stringSid= null;
            name = null;
            domainName = null;
            sidType = SID_NAME_USE.SidTypeUnknown;

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQueryInformationToken(
                    hToken,
                    TOKEN_INFORMATION_CLASS.TokenUser,
                    pInfoBuffer,
                    nInfoLength,
                    out nInfoLength);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_BUFFER_TOO_SMALL);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var info = (TOKEN_USER)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(TOKEN_USER));

                NativeMethods.ConvertSidToStringSid(info.User.Sid, out stringSid);
                status = ConvertSidToAccountName(
                    info.User.Sid,
                    out name,
                    out domainName,
                    out sidType);
                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return status;
        }
    }
}
