# SdDumper

Tool to dump and analyze SecurityDescriptor information.
Currently, following objects are supported.

* Process
* File
* Directory
* Registry

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -h

SdDumper - SecurityDescriptor utilitiy.

Usage: SdDumper.exe [Options]

        -h, --help     : Displays this help message.
        -a, --analyze  : Specifies SDDL to analyze.
        -f, --filepath : Specifies file or directory path.
        -p, --pid      : Specifies process ID.
        -r, --registry : Specifies registry key.
        -S, --system   : Flag to act as SYSTEM.
        -d, --debug    : Flag to enable SeDebugPrivilege.

PS C:\Users\admin>
```

## Analyze SDDL

To analyze SDDL, set SDDL query as `-a` option's value as follows:

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -a "D:(A;;CC;;;BU)(A;;CCDC;;;SY)(A;;GR;;;BA)"

[>] Trying to analyze SDDL.
    [*] SDDL : D:(A;;CC;;;BU)(A;;CCDC;;;SY)(A;;GR;;;BA)
[*] SECURITY_DESCRIPTOR :
    [*] Owner : N/A
    [*] Group : N/A
    [*] DACL  :
        [*] AceCount  : 3
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD
            [*] SID    : S-1-5-32-545
                [*] Account  : BUILTIN\Users
                [*] SID Type : SidTypeAlias
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, CREATE_DELETE
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : GENERIC_READ
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
    [*] SACL  : N/A
[*] Done

PS C:\Users\admin>
```


## Dump SecurityDescriptor information

To dump SecurityDescriptor information, set PID as `-p` option's value.
If the caller does not have `SeSecurityPrivilege`, you cannot dump SACL information as follows:

```
PS C:\Users\admin> whoami /priv | findstr /i sesecuritypriv

PS C:\Users\admin> C:\Tools\SdDumper.exe -p 1080

[>] Trying to dump SecurityDescriptor for the specified process.
    [*] Process ID   : 1080
    [*] Process Name : Notepad
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:S-1-5-21-36110069-1586757501-3586480897-1001G:S-1-5-21-36110069-1586757501-3586480897-513D:(A;;0x1fffff;;;S-1-5-21-36110069-1586757501-3586480897-1001)(A;;0x1fffff;;;SY)(A;;0x121411;;;S-1-5-5-0-126280)
[*] SECURITY_DESCRIPTOR :
    [*] Owner : S-1-5-21-36110069-1586757501-3586480897-1001
        [*] Account  : DESKTOP-53V8DCQ\admin
        [*] SID Type : SidTypeUser
    [*] Group : S-1-5-21-36110069-1586757501-3586480897-513
        [*] Account  : DESKTOP-53V8DCQ\None
        [*] SID Type : SidTypeGroup
    [*] DACL  :
        [*] AceCount  : 3
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : PROCESS_ALL_ACCESS
            [*] SID    : S-1-5-21-36110069-1586757501-3586480897-1001
                [*] Account  : DESKTOP-53V8DCQ\admin
                [*] SID Type : SidTypeUser
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : PROCESS_ALL_ACCESS
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, READ_PROPERTY, QUERY_INFORMATION, QUERY_LIMITED_INFORMATION, READ_CONTROL, SYNCHRONIZE
            [*] SID    : S-1-5-5-0-126280
                [*] Account  : NT AUTHORITY\LogonSessionId_0_126280
                [*] SID Type : SidTypeLogonSession
    [*] SACL  : N/A
        [!] SeSecurityPrivilege is required.
[*] Done.

PS C:\Users\admin>
```

If you want to dump the information of file or directory, use `-f` option as follows:

```
PS C:\Users\admin> whoami /priv | findstr /i sesecuritypriv
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled

PS C:\Users\admin> C:\Tools\SdDumper.exe -f C:\Windows\System32\kernel32.dll

[>] Trying to dump SecurityDescriptor for the specified path.
    [*] Path : C:\Windows\System32\kernel32.dll
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)S:AI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)
[*] SECURITY_DESCRIPTOR :
    [*] Owner : S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
        [*] Account  : NT SERVICE\TrustedInstaller
        [*] SID Type : SidTypeWellKnownGroup
    [*] Group : S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
        [*] Account  : NT SERVICE\TrustedInstaller
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL  :
        [*] AceCount  : 6
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : FILE_ALL_ACCESS
            [*] SID    : S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
                [*] Account  : NT SERVICE\TrustedInstaller
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, SELF_WRITE, FILE_EXECUTE
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, SELF_WRITE, FILE_EXECUTE
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x03] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, SELF_WRITE, FILE_EXECUTE
            [*] SID    : S-1-5-32-545
                [*] Account  : BUILTIN\Users
                [*] SID Type : SidTypeAlias
        [*] ACE[0x04] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, SELF_WRITE, FILE_EXECUTE
            [*] SID    : S-1-15-2-1
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x05] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, SELF_WRITE, FILE_EXECUTE
            [*] SID    : S-1-15-2-2
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
    [*] SACL  :
        [*] AceCount  : 1
        [*] ACE[0x00] :
            [*] Type   : SYSTEM_AUDIT
            [*] Flags  : FAILED_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG
            [*] Access : CREATE_DELETE, LIST_CHILDREN, READ_PROPERTY, CONTROL_ACCESS, DELETE, WRITE_DAC, WRITE_OWNER
            [*] SID    : S-1-1-0
                [*] Account  : Everyone
                [*] SID Type : SidTypeWellKnownGroup
[*] Done.

PS C:\Users\admin>
```

For registry, use `-r` option as follows:

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -r hklm\system

[>] Trying to dump SecurityDescriptor for the specified registry key.
    [*] Root Key : HKEY_LOCAL_MACHINE
    [*] Sub Key  : system
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:BAG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;CI;KR;;;AC)(A;CI;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)S:AINO_ACCESS_CONTROL
[*] SECURITY_DESCRIPTOR :
    [*] Owner : S-1-5-32-544
        [*] Account  : BUILTIN\Administrators
        [*] SID Type : SidTypeAlias
    [*] Group : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL  :
        [*] AceCount  : 6
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : CONTAINER_INHERIT_ACE
            [*] Access : KEY_EXECUTE_READ
            [*] SID    : S-1-5-32-545
                [*] Account  : BUILTIN\Users
                [*] SID Type : SidTypeAlias
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : CONTAINER_INHERIT_ACE
            [*] Access : KEY_ALL_ACCESS
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : CONTAINER_INHERIT_ACE
            [*] Access : KEY_ALL_ACCESS
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x03] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : CONTAINER_INHERIT_ACE
            [*] Access : KEY_ALL_ACCESS
            [*] SID    : S-1-3-0
                [*] Account  : CREATOR OWNER
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x04] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : CONTAINER_INHERIT_ACE
            [*] Access : KEY_EXECUTE_READ
            [*] SID    : S-1-15-2-1
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x05] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : CONTAINER_INHERIT_ACE
            [*] Access : KEY_EXECUTE_READ
            [*] SID    : S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681
                [*] Account  : N/A
                [*] SID Type : SidTypeUnknown
    [*] SACL  : N/A
[*] Done.

PS C:\Users\admin>
```

If you want execute as `NT AUTHORITY\SYSTEM`, set `-S` flag.

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -p 688 -S

[>] Trying to dump SecurityDescriptor for the specified process.
    [*] Process ID   : 688
    [*] Process Name : lsass
[>] Trying to impersonate as SYSTEM.
[+] Impersonation is successful.
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:BAG:SYD:(A;;0x1fffff;;;SY)(A;;0x121411;;;BA)S:(AU;SAFA;RP;;;WD)
[*] SECURITY_DESCRIPTOR :
    [*] Owner : S-1-5-32-544
        [*] Account  : BUILTIN\Administrators
        [*] SID Type : SidTypeAlias
    [*] Group : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeUser
    [*] DACL  :
        [*] AceCount  : 2
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : PROCESS_ALL_ACCESS
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeUser
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, READ_PROPERTY, QUERY_INFORMATION, QUERY_LIMITED_INFORMATION, READ_CONTROL, SYNCHRONIZE
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
    [*] SACL  :
        [*] AceCount  : 1
        [*] ACE[0x00] :
            [*] Type   : SYSTEM_AUDIT
            [*] Flags  : FAILED_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG
            [*] Access : READ_PROPERTY
            [*] SID    : S-1-1-0
                [*] Account  : Everyone
                [*] SID Type : SidTypeWellKnownGroup
[*] Done.

PS C:\Users\admin>
```

To enable `SeDebugPrivilege`, set `-d` flag:

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -p 624 -d

[>] Trying to dump SecurityDescriptor for the specified process.
    [*] Process ID   : 624
    [*] Process Name : winlogon
[>] Trying to SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:BAG:SYD:(A;;0x1fffff;;;SY)(A;;0x121411;;;BA)S:AI
[*] SECURITY_DESCRIPTOR :
    [*] Owner : S-1-5-32-544
        [*] Account  : BUILTIN\Administrators
        [*] SID Type : SidTypeAlias
    [*] Group : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL  :
        [*] AceCount  : 2
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : PROCESS_ALL_ACCESS
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : CREATE_CHILD, READ_PROPERTY, QUERY_INFORMATION, QUERY_LIMITED_INFORMATION, READ_CONTROL, SYNCHRONIZE
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
    [*] SACL  :
        [*] AceCount  : 0
[*] Done.

PS C:\Users\admin>
```