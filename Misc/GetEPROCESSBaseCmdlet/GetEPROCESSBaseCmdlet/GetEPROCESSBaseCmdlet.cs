using GetEPROCESSBaseCmdlet.Interop;
using GetEPROCESSBaseCmdlet.Library;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace GetEPROCESSBaseCmdlet
{
    using NTSTATUS = Int32;

    [Cmdlet(VerbsCommon.Get, "EPROCESSBase")]
    public sealed class GetEPROCESSBaseCmdlet : Cmdlet
    {
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true)]
        public Int32 Id { get; set; }

        [Parameter]
        public SwitchParameter AsHexString { get; set; }


        protected override void ProcessRecord()
        {
            IntPtr pEprocess;
            string message;
            string processName;
            var objattr = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
            var cid = new CLIENT_ID { UniqueProcess = new IntPtr(Id) };
            NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.QueryLimitedInformation,
                in objattr,
                in cid);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                message = string.Format("Failed to get a handle from the specified process (NTSTATUS = 0x{0})",
                    ntstatus.ToString("X8"));
                WriteError(new ErrorRecord(new Win32Exception(message),
                    "NtOpenProcess",
                    ErrorCategory.OpenError,
                    hProcess));
                return;
            }
            else
            {
                message = string.Format("Got a handle from the specified process (PID: {0}, Handle: 0x{1})",
                    cid.UniqueProcess,
                    hProcess.ToString("X"));
                WriteVerbose(message);
            }

            do
            {
                WriteVerbose("Trying to lookup the handle information");
                pEprocess = Helpers.GetHandleAddress(
                    Process.GetCurrentProcess().Id,
                    hProcess);

                try
                {
                    processName = Process.GetProcessById(Id).ProcessName.Trim();
                }
                catch
                {
                    processName = null;
                }
            } while (false);

            WriteVerbose("Close the handle");
            NativeMethods.NtClose(hProcess);

            if (pEprocess == new IntPtr(-1))
            {
                message = string.Format("Failed to get EPROCESS for {0} (PID: {1})",
                    string.IsNullOrEmpty(processName) ? "N/A" : processName,
                    cid.UniqueProcess);
                WriteError(new ErrorRecord(new ItemNotFoundException(message),
                    "NtQuerySystemInformation",
                    ErrorCategory.ObjectNotFound,
                    pEprocess));
            }
            else
            {
                var ptrString = string.Format("0x{0}",
                    pEprocess.ToString(Environment.Is64BitProcess ? "X16" : "X8"));
                message = string.Format("EPROCESS for {0} (PID: {1}) is at {2}",
                    string.IsNullOrEmpty(processName) ? "N/A" : processName,
                    cid.UniqueProcess,
                    ptrString);
                WriteVerbose(message);

                if (pEprocess == IntPtr.Zero)
                    WriteWarning("Since Win11 24H2, SeDebugPrivilege is required to get EPROCESS address.");

                if (AsHexString)
                    WriteObject(ptrString);
                else
                    WriteObject(pEprocess);
            }
        }
    }
}
