using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using HandleScanner.Interop;

namespace HandleScanner.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static void DumpHandleInformation(
            int pid,
            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> info,
            string typeFilter,
            string nameFilter,
            bool verbose,
            out int nNumberOfEntries)
        {
            string processName;
            string lineFormat;
            Dictionary<int, string> objectNames;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
            var outputBuilder = new StringBuilder();
            var filterdTypes = new Dictionary<int, string>();
            var filterdInfo = new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();
            var comparison = StringComparison.OrdinalIgnoreCase;
            var labels = new string[5] { "Handle", "Type", "Address", "Access", "Object Name" };
            var widths = new int[5] {
                labels[0].Length,      // Handle
                labels[1].Length,      // Type
                (IntPtr.Size * 2) + 2, // Address
                10,                    // Access
                labels[4].Length       // Object Name
            };
            nNumberOfEntries = 0;

            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                processName = "N/A";
            }

            if (string.IsNullOrEmpty(typeFilter))
            {
                filterdTypes = Globals.TypeTable;
            }
            else
            {
                foreach (var entry in Globals.TypeTable)
                {
                    if (entry.Value.IndexOf(typeFilter, comparison) >= 0)
                        filterdTypes.Add(entry.Key, entry.Value);
                }
            }

            foreach (var entry in info)
            {
                if (filterdTypes.ContainsKey(entry.ObjectTypeIndex))
                    filterdInfo.Add(entry);
            }

            objectNames = GetHandleNameTable(pid, nameFilter, filterdInfo);

            foreach (var entry in filterdInfo)
            {
                if ((entry.HandleValue.ToString("X").Length + 2) > widths[0])
                    widths[0] = entry.HandleValue.ToString("X").Length + 2;

                if (!verbose && !objectNames.ContainsKey((int)entry.HandleValue))
                    continue;

                if (filterdTypes[entry.ObjectTypeIndex].Length > widths[1])
                    widths[1] = filterdTypes[entry.ObjectTypeIndex].Length;
            }

            lineFormat = string.Format(
                "{{0,{0}}} {{1,-{1}}} {{2,-{2}}} {{3,-{3}}} {{4,-{4}}}\n",
                widths[0], widths[1], widths[2], widths[3], widths[4]);

            if ((!verbose && (objectNames.Count > 0)) || (verbose && (filterdInfo.Count > 0)))
            {
                outputBuilder.AppendFormat("\n[Handle(s) for {0} (PID: {1})]\n\n", processName, pid);
                outputBuilder.AppendFormat(
                    lineFormat,
                    labels[0], labels[1], labels[2], labels[3], labels[4]);
                outputBuilder.AppendFormat(
                    lineFormat,
                    new string('=', widths[0]),
                    new string('=', widths[1]),
                    new string('=', widths[2]),
                    new string('=', widths[3]),
                    new string('=', widths[4]));

                foreach (var entry in filterdInfo)
                {
                    if (!verbose)
                    {
                        if (!objectNames.ContainsKey((int)entry.HandleValue))
                            continue;
                    }

                    outputBuilder.AppendFormat(
                        lineFormat,
                        string.Format("0x{0}", entry.HandleValue.ToString("X")),
                        Globals.TypeTable[entry.ObjectTypeIndex],
                        string.Format("0x{0}", entry.Object.ToString(addressFormat)),
                        string.Format("0x{0}", entry.GrantedAccess.ToString("X8")),
                        objectNames.ContainsKey((int)entry.HandleValue) ? objectNames[(int)entry.HandleValue] : "(N/A)");

                    nNumberOfEntries++;
                }

                Console.WriteLine(outputBuilder.ToString());
            }

            outputBuilder.Clear();
        }


        public static bool EnableTokenPrivileges(
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                requiredPrivs,
                out adjustedPrivs);
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            var allEnabled = true;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                if (requiredPrivs.Count == 0)
                    break;

                allEnabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allEnabled)
                    break;

                foreach (var priv in requiredPrivs)
                {
                    adjustedPrivs.Add(priv, false);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key, priv))
                        {
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.ENABLED) != 0)
                            {
                                adjustedPrivs[priv] = true;
                            }
                            else
                            {
                                IntPtr pTokenPrivileges = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
                                var tokenPrivileges = new TOKEN_PRIVILEGES(1);

                                if (NativeMethods.LookupPrivilegeValue(
                                    null,
                                    priv,
                                    out tokenPrivileges.Privileges[0].Luid))
                                {
                                    tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.ENABLED;
                                    Marshal.StructureToPtr(tokenPrivileges, pTokenPrivileges, true);

                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        pTokenPrivileges,
                                        Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                        IntPtr.Zero,
                                        out int _);
                                    adjustedPrivs[priv] = (adjustedPrivs[priv] && (Marshal.GetLastWin32Error() == 0));
                                }

                                Marshal.FreeHGlobal(pTokenPrivileges);
                            }

                            break;
                        }
                    }

                    if (!adjustedPrivs[priv])
                        allEnabled = false;
                }
            } while (false);

            return allEnabled;
        }


        public static Dictionary<int, string> GetHandleNameTable(
            int pid,
            string nameFilter,
            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> info)
        {
            IntPtr hProcess;
            var table = new Dictionary<int, string>();

            if (pid == Process.GetCurrentProcess().Id)
            {
                hProcess = new IntPtr(-1);
            }
            else
            {
                hProcess = NativeMethods.OpenProcess(
                    ACCESS_MASK.PROCESS_DUP_HANDLE,
                    false,
                    pid);
            }

            if (hProcess != IntPtr.Zero)
            {
                foreach (var entry in info)
                {
                    string objectName;
                    IntPtr hObject = new IntPtr(entry.HandleValue);

                    if (hProcess != new IntPtr(-1))
                    {
                        NTSTATUS ntstatus = NativeMethods.NtDuplicateObject(
                            hProcess,
                            hObject,
                            new IntPtr(-1),
                            out hObject,
                            ACCESS_MASK.NO_ACCESS,
                            0u,
                            DUPLICATE_OPTION_FLAGS.SAME_ACCESS);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                            continue;
                    }

                    if (Helpers.CompareIgnoreCase(Globals.TypeTable[entry.ObjectTypeIndex], "File"))
                        objectName = Helpers.GetFileObjectName(hObject);
                    else if (Helpers.CompareIgnoreCase(Globals.TypeTable[entry.ObjectTypeIndex], "Process"))
                        objectName = Helpers.GetProcessObjectName(hObject);
                    else if (Helpers.CompareIgnoreCase(Globals.TypeTable[entry.ObjectTypeIndex], "Thread"))
                        objectName = Helpers.GetThreadObjectName(hObject);
                    else if (Helpers.CompareIgnoreCase(Globals.TypeTable[entry.ObjectTypeIndex], "Token"))
                        objectName = Helpers.GetTokenObjectName(hObject);
                    else
                        objectName = Helpers.GetObjectName(hObject);

                    if (hProcess != new IntPtr(-1))
                        NativeMethods.NtClose(hObject);

                    if (!string.IsNullOrEmpty(objectName))
                    {
                        var comparison = StringComparison.OrdinalIgnoreCase;

                        if (string.IsNullOrEmpty(nameFilter))
                            table.Add((int)entry.HandleValue, objectName);
                        else if (objectName.IndexOf(nameFilter, comparison) >= 0)
                            table.Add((int)entry.HandleValue, objectName);
                    }
                }

                if (hProcess != new IntPtr(-1))
                    NativeMethods.NtClose(hProcess);
            }

            return table;
        }


        public static bool ImpersonateAsSmss(List<string> privs)
        {
            int smss;
            var status = false;

            try
            {
                smss = (Process.GetProcessesByName("smss")[0]).Id;
            }
            catch
            {
                return status;
            }

            do
            {
                IntPtr hProcess = NativeMethods.OpenProcess(
                    ACCESS_MASK.PROCESS_QUERY_LIMITED_INFORMATION,
                    true,
                    smss);

                if (hProcess == IntPtr.Zero)
                    break;

                status = NativeMethods.OpenProcessToken(
                    hProcess,
                    ACCESS_MASK.TOKEN_DUPLICATE,
                    out IntPtr hToken);
                NativeMethods.NtClose(hProcess);

                if (!status)
                    break;

                status = NativeMethods.DuplicateTokenEx(
                    hToken,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.Impersonation,
                    out IntPtr hDupToken);
                NativeMethods.NtClose(hToken);

                if (!status)
                    break;

                EnableTokenPrivileges(hDupToken, privs, out Dictionary<string, bool> _);
                status = ImpersonateThreadToken(hDupToken);
                NativeMethods.NtClose(hDupToken);
            } while (false);

            return status;
        }


        public static bool ImpersonateThreadToken(IntPtr hImpersonationToken)
        {
            IntPtr pImpersonationLevel = Marshal.AllocHGlobal(4);
            bool status = NativeMethods.ImpersonateLoggedOnUser(hImpersonationToken);

            if (status)
            {
                NTSTATUS ntstatus = NativeMethods.NtQueryInformationToken(
                    WindowsIdentity.GetCurrent().Token,
                    TOKEN_INFORMATION_CLASS.TokenImpersonationLevel,
                    pImpersonationLevel,
                    4u,
                    out uint _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (status)
                {
                    var level = Marshal.ReadInt32(pImpersonationLevel);

                    if (level >= (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation)
                        status = true;
                    else
                        status = false;
                }
            }

            Marshal.FreeHGlobal(pImpersonationLevel);

            return status;
        }
    }
}
