using GetEPROCESSBaseCmdlet.Interop;
using System;
using System.Runtime.InteropServices;

namespace GetEPROCESSBaseCmdlet.Library
{
    using NTSTATUS = Int32;

    internal sealed class Helpers
    {
        internal static IntPtr GetHandleAddress(int pid, IntPtr hObject)
        {
            NTSTATUS ntstatus;
            IntPtr pInfoBuffer;
            var pObject = new IntPtr(-1);
            var uniquePid = new IntPtr(pid);
            var nInfoLength = (uint)Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION_EX));

            do
            {
                pInfoBuffer = Marshal.AllocHGlobal((int)nInfoLength);
                ntstatus = NativeMethods.NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                    pInfoBuffer,
                    nInfoLength,
                    out uint nRequiredLength);
                nInfoLength += nRequiredLength;

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    Marshal.FreeHGlobal(pInfoBuffer);
            } while (ntstatus == Win32Consts.STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                IntPtr pHandleBase;
                ulong nHandleCount;
                var nUnitSize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                var nOffset = Marshal.OffsetOf(typeof(SYSTEM_HANDLE_INFORMATION_EX), "Handles").ToInt32();

                if (Environment.Is64BitProcess)
                {
                    pHandleBase = new IntPtr(pInfoBuffer.ToInt64() + nOffset);
                    nHandleCount = (ulong)Marshal.ReadInt64(pInfoBuffer);
                }
                else
                {
                    pHandleBase = new IntPtr(pInfoBuffer.ToInt32() + nOffset);
                    nHandleCount = (uint)Marshal.ReadInt32(pInfoBuffer);
                }

                for (ulong i = 0; i < nHandleCount; i++)
                {
                    var info = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(
                        pHandleBase,
                        typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

                    if ((info.UniqueProcessId == uniquePid) && (info.HandleValue == hObject))
                    {
                        pObject = info.Object;
                        break;
                    }

                    if (Environment.Is64BitProcess)
                        pHandleBase = new IntPtr(pHandleBase.ToInt64() + nUnitSize);
                    else
                        pHandleBase = new IntPtr(pHandleBase.ToInt32() + nUnitSize);
                }

                Marshal.FreeHGlobal(pInfoBuffer);
            }

            return pObject;
        }
    }
}
