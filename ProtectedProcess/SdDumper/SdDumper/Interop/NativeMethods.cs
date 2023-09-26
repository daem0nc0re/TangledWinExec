using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SdDumper.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        /*
         * advapi32.dll
         */
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            IntPtr NewState, // ref TOKEN_PRIVILEGES
            int BufferLength,
            IntPtr PreviousState, // out TOKEN_PRIVILEGES
            IntPtr ReturnLength); // out int

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            int RequestedStringSDRevision, // Currently this value must be SDDL_REVISION_1 (= 1).
            SECURITY_INFORMATION SecurityInformation,
            out IntPtr StringSecurityDescriptor, // Should be freed with LocalFree later.
            IntPtr /* out uint */ pStringSecurityDescriptorLen);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor,
            int StringSDRevision, // Currently this value must be SDDL_REVISION_1 (= 1).
            out IntPtr SecurityDescriptor,
            out uint SecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor,
            int StringSDRevision, // Currently this value must be SDDL_REVISION_1 (= 1).
            out IntPtr SecurityDescriptor,
            IntPtr pSecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TokenAccessFlags dwDesiredAccess,
            IntPtr lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidAcl(IntPtr pAcl);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidSecurityDescriptor(IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupAccountSid(
            string strSystemName,
            IntPtr pSid,
            StringBuilder pName,
            ref int cchName,
            StringBuilder pReferencedDomainName,
            ref int cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName,
            ref LUID lpLuid,
            StringBuilder lpName,
            ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            TokenAccessFlags DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            UIntPtr hKey,
            string subKey,
            REG_OPTION ulOptions,
            KEY_ACCESS samDesired,
            out IntPtr hkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        /*
         * kernel32.dll
         */
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            ACCESS_MASK dwDesiredAccess,
            FILE_SHARE dwShareMode,
            IntPtr lpSecurityAttributes,
            CREATE_DESPOSITION dwCreationDisposition,
            FILE_ATTRIBUTE dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern FILE_ATTRIBUTE GetFileAttributes(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ACCESS_MASK processAccess,
            bool bInheritHandle,
            int processId);

        /*
         * ntdll.dll
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateFile(
            out IntPtr FileHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr IoStatusBlock,
            IntPtr AllocationSize,
            FILE_ATTRIBUTE FileAttributes,
            FILE_SHARE ShareAccess,
            FILE_CREATE_DISPOSITION CreateDisposition,
            FILE_CREATE_OPTIONS CreateOptions,
            IntPtr EaBuffer,
            uint EaLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenDirectoryObject(
            out IntPtr DirectoryHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenEvent(
            out IntPtr EventHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenEventPair(
            out IntPtr EventPairHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenIoCompletion(
            out IntPtr IoCompletionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenJobObject(
            out IntPtr JobHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenKey(
            out IntPtr KeyHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenKeyedEvent(
            out IntPtr KeyedEventHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenMutant(
            out IntPtr MutantHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenPartition(
            out IntPtr PartitionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenRegistryTransaction(
            out IntPtr RegistryTransactionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenSection(
            out IntPtr SectionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenSemaphore(
            out IntPtr SemaphoreHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenSession(
            out IntPtr SessionHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenSymbolicLinkObject(
            out IntPtr LinkHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenTimer(
            out IntPtr TimerHandle,
            ACCESS_MASK DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryDirectoryObject(
            IntPtr DirectoryHandle,
            IntPtr Buffer,
            uint Length,
            BOOLEAN ReturnSingleEntry,
            BOOLEAN RestartScan,
            ref uint Context,
            IntPtr /* out uint */ pReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQuerySecurityObject(
            IntPtr Handle,
            SECURITY_INFORMATION SecurityInformation,
            IntPtr SecurityDescriptor,
            uint Length,
            out uint LengthNeeded);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr pTokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength); // Should not be null pointer

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetSecurityObject(
            IntPtr Handle,
            SECURITY_INFORMATION SecurityInformation,
            IntPtr /* PSECURITY_DESCRIPTOR */ SecurityDescriptor);
    }
}
