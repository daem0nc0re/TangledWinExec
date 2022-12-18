# SdDumper

Tool to dump and analyze SecurityDescriptor information.

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -h

SdDumper - SecurityDescriptor utilitiy.

Usage: SdDumper.exe [Options]

        -h, --help     : Displays this help message.
        -a, --analyze  : Specifies SDDL to analyze.
        -f, --filepath : Specifies file or directory path.
        -n, --ntobj    : Specifies NT object path.
        -p, --pid      : Specifies process ID.
        -r, --registry : Specifies registry key.
        -l, --list     : Flag to enumerate NT object directory. Use with -n flag.
        -t, --token    : Flag to get primary token's information. Use with -p flag.
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
    [*] DACL :
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
    [*] SACL : N/A
[*] Done

PS C:\Users\admin>
```


## Dump SecurityDescriptor information

To dump SecurityDescriptor information, set PID as `-p` option's value.
If the caller does not have `SeSecurityPrivilege`, you cannot dump SACL information as follows:

```
PS C:\Users\admin> whoami /priv | findstr /i sesecuritypriv

PS C:\Users\admin> C:\Tools\SdDumper.exe -p 5040

[>] Trying to dump SecurityDescriptor for the specified process.
    [*] Process ID   : 5040
    [*] Process Name : Notepad
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:S-1-5-21-36110069-1586757501-3586480897-1001G:S-1-5-21-36110069-1586757501-3586480897-513D:(A;;0x1fffff;;;S-1-5-21-36110069-1586757501-3586480897-1001)(A;;0x1fffff;;;SY)(A;;0x121411;;;S-1-5-5-0-117275)
[*] SECURITY_DESCRIPTOR :
    [*] Owner :
        [*] SID      : S-1-5-21-36110069-1586757501-3586480897-1001
        [*] Account  : DESKTOP-53V8DCQ\admin
        [*] SID Type : SidTypeUser
    [*] Group :
        [*] SID      : S-1-5-21-36110069-1586757501-3586480897-513
        [*] Account  : DESKTOP-53V8DCQ\None
        [*] SID Type : SidTypeGroup
    [*] DACL :
        [*] AceCount  : 3
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : ALL_ACCESS
            [*] SID    : S-1-5-21-36110069-1586757501-3586480897-1001
                [*] Account  : DESKTOP-53V8DCQ\admin
                [*] SID Type : SidTypeUser
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : ALL_ACCESS
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : TERMINATE, VM_READ, QUERY_INFORMATION, QUERY_LIMITED_INFORMATION, READ_CONTROL, SYNCHRONIZE
            [*] SID    : S-1-5-5-0-117275
                [*] Account  : NT AUTHORITY\LogonSessionId_0_117275
                [*] SID Type : SidTypeLogonSession
    [*] SACL : N/A (SeSecurityPrivilege is required)
[*] Done.

PS C:\Users\admin>
```

To dump ACL information from process token, set `-t` flag with `-p` option as follows:

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -p 2276 -t

[>] Trying to dump primary token's ACL information for the specified process.
    [*] Process ID   : 2276
    [*] Process Name : MsMpEng
[*] Primary Token Information:
    [*] TrustLevel :
        [*] SID   : S-1-19-512-1536
        [*] Level : TRUST LEVEL\ProtectedLight-AntiMalware
    [*] Owner :
        [*] SID      : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeWellKnownGroup
    [*] Group :
        [*] SID      : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL :
        [*] AceCount  : 3
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : GENERIC_ALL
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : READ_CONTROL
            [*] SID    : S-1-3-4
                [*] Account  : OWNER RIGHTS
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : GENERIC_ALL
            [*] SID    : S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736
                [*] Account  : NT SERVICE\WinDefend
                [*] SID Type : SidTypeWellKnownGroup
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
    [*] Type : File
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)S:AI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)
[*] SECURITY_DESCRIPTOR :
    [*] Owner :
        [*] SID      : S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
        [*] Account  : NT SERVICE\TrustedInstaller
        [*] SID Type : SidTypeWellKnownGroup
    [*] Group :
        [*] SID      : S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
        [*] Account  : NT SERVICE\TrustedInstaller
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL :
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
            [*] Access : FILE_READ_DATA, FILE_READ_EA, FILE_STANDARD_EXECUTE
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : FILE_READ_DATA, FILE_READ_EA, FILE_STANDARD_EXECUTE
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x03] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : FILE_READ_DATA, FILE_READ_EA, FILE_STANDARD_EXECUTE
            [*] SID    : S-1-5-32-545
                [*] Account  : BUILTIN\Users
                [*] SID Type : SidTypeAlias
        [*] ACE[0x04] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : FILE_READ_DATA, FILE_READ_EA, FILE_STANDARD_EXECUTE
            [*] SID    : S-1-15-2-1
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x05] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : FILE_READ_DATA, FILE_READ_EA, FILE_STANDARD_EXECUTE
            [*] SID    : S-1-15-2-2
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
    [*] SACL :
        [*] AceCount  : 1
        [*] ACE[0x00] :
            [*] Type   : SYSTEM_AUDIT
            [*] Flags  : FAILED_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG
            [*] Access : FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER
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
    [*] Owner :
        [*] SID      : S-1-5-32-544
        [*] Account  : BUILTIN\Administrators
        [*] SID Type : SidTypeAlias
    [*] Group :
        [*] SID      : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL :
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
    [*] SACL : N/A (NO_ACCESS_CONTROL)
[*] Done.

PS C:\Users\admin>
```

To dump NT object's SecurityDescriptor, specifies NT object path with `-n` option.
NT object type is resolved automatically:

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -n \KnownDlls

[>] Trying to dump SecurityDescriptor for the specified NT object path.
    [*] Path : \KnownDlls
    [*] Type : Directory
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:BAG:SYD:(A;;CCDCLCSWSDRCWDWO;;;BA)(A;;CCDCRC;;;WD)(A;;CCDCRC;;;AC)(A;;CCDCRC;;;RC)(A;;CCDCRC;;;S-1-15-2-2)S:(TL;;CCDCRC;;;S-1-19-512-8192)
[*] SECURITY_DESCRIPTOR :
    [*] Owner :
        [*] SID      : S-1-5-32-544
        [*] Account  : BUILTIN\Administrators
        [*] SID Type : SidTypeAlias
    [*] Group :
        [*] SID      : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL :
        [*] AceCount  : 5
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : DIRECTORY_ALL_ACCESS
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : DIRECTORY_QUERY, DIRECTORY_TRAVERSE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-1-0
                [*] Account  : Everyone
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : DIRECTORY_QUERY, DIRECTORY_TRAVERSE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-15-2-1
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x03] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : DIRECTORY_QUERY, DIRECTORY_TRAVERSE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-5-12
                [*] Account  : NT AUTHORITY\RESTRICTED
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x04] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : DIRECTORY_QUERY, DIRECTORY_TRAVERSE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-15-2-2
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
    [*] SACL :
        [*] AceCount  : 1
        [*] ACE[0x00] :
            [*] Type   : SYSTEM_PROCESS_TRUST_LABEL
            [*] Flags  : NONE
            [*] Access : DIRECTORY_QUERY, DIRECTORY_TRAVERSE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-19-512-8192
                [*] Trust Label : TRUST LEVEL\ProtectedLight-WinTcb
[*] Done.

PS C:\Users\admin> C:\Tools\SdDumper.exe -n \KnownDlls\kernel32.dll

[>] Trying to dump SecurityDescriptor for the specified NT object path.
    [*] Path : \KnownDlls\kernel32.dll
    [*] Type : Section
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:BAG:SYD:(A;;CCDCLCSWRC;;;WD)(A;;CCDCLCSWRC;;;AC)(A;;CCDCLCSWRC;;;S-1-15-2-2)(A;;CCDCLCSWRC;;;RC)(A;;CCDCLCSWRPSDRCWDWO;;;BA)S:AI(ML;;NW;;;LW)(TL;;CCDCLCSWRC;;;S-1-19-512-8192)
[*] SECURITY_DESCRIPTOR :
    [*] Owner :
        [*] SID      : S-1-5-32-544
        [*] Account  : BUILTIN\Administrators
        [*] SID Type : SidTypeAlias
    [*] Group :
        [*] SID      : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL :
        [*] AceCount  : 5
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : SECTION_QUERY, SECTION_MAP_WRITE, SECTION_MAP_READ, SECTION_MAP_EXECUTE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-1-0
                [*] Account  : Everyone
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : SECTION_QUERY, SECTION_MAP_WRITE, SECTION_MAP_READ, SECTION_MAP_EXECUTE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-15-2-1
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : SECTION_QUERY, SECTION_MAP_WRITE, SECTION_MAP_READ, SECTION_MAP_EXECUTE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-15-2-2
                [*] Account  : APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x03] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : SECTION_QUERY, SECTION_MAP_WRITE, SECTION_MAP_READ, SECTION_MAP_EXECUTE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-5-12
                [*] Account  : NT AUTHORITY\RESTRICTED
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x04] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : SECTION_ALL_ACCESS
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
    [*] SACL :
        [*] AceCount  : 2
        [*] ACE[0x00] :
            [*] Type   : SYSTEM_MANDATORY_LABEL
            [*] Flags  : NONE
            [*] Access : SECTION_QUERY
            [*] SID    : S-1-16-4096
                [*] Account  : Mandatory Label\Low Mandatory Level
                [*] SID Type : SidTypeLabel
        [*] ACE[0x01] :
            [*] Type   : SYSTEM_PROCESS_TRUST_LABEL
            [*] Flags  : NONE
            [*] Access : SECTION_QUERY, SECTION_MAP_WRITE, SECTION_MAP_READ, SECTION_MAP_EXECUTE, STANDARD_RIGHTS_EXECUTE_READWRITE
            [*] SID    : S-1-19-512-8192
                [*] Trust Label : TRUST LEVEL\ProtectedLight-WinTcb
[*] Done.

PS C:\Users\admin>
```

When you set `-l` flag as well as `-n` option, list NT object directory items.
If the specified path is not `Directory` object or not exists, tries to check parent directory automatically:

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -l -n \

[>] Trying to enumerate NT object directory.
    [*] Path : \
    [*] Type : Directory

    Object Type          Object Name
    ==================== ===========
    Mutant               PendingRenameMutex
    Directory            ObjectTypes
    FilterConnectionPort storqosfltport

--snip--

    SymbolicLink         OSDataRoot
    Event                SAM_SERVICE_STARTED
    Directory            Driver
    SymbolicLink         DriverStores

[*] Done.

PS C:\Users\admin> C:\Tools\SdDumper.exe -l -n \KernelObjects\notexist

[>] Trying to enumerate NT object directory.
    [*] Path : \KernelObjects
    [*] Type : Directory

    Object Type  Object Name
    ============ ===========
    SymbolicLink MemoryErrors
    Event        LowNonPagedPoolCondition
    Session      Session1
    Event        SuperfetchScenarioNotify
    Event        SuperfetchParametersChanged
    SymbolicLink PhysicalMemoryChange
    SymbolicLink HighCommitCondition
    Mutant       BcdSyncMutant
    SymbolicLink HighMemoryCondition
    Event        HighNonPagedPoolCondition
    Partition    MemoryPartition0
    KeyedEvent   CritSecOutOfMemoryEvent
    Event        SystemErrorPortReady
    SymbolicLink MaximumCommitCondition
    SymbolicLink LowCommitCondition
    Event        HighPagedPoolCondition
    SymbolicLink LowMemoryCondition
    Session      Session0
    Event        LowPagedPoolCondition
    Event        PrefetchTracesReady

[*] Done.

PS C:\Users\admin>
```

If you want execute as `NT AUTHORITY\SYSTEM`, set `-S` flag.

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -p 712 -S

[>] Trying to dump SecurityDescriptor for the specified process.
    [*] Process ID   : 712
    [*] Process Name : lsass
[>] Trying to impersonate as SYSTEM.
[+] Impersonation is successful.
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:BAG:SYD:(A;;0x1fffff;;;SY)(A;;0x121411;;;BA)S:(AU;SAFA;RP;;;WD)
[*] SECURITY_DESCRIPTOR :
    [*] Owner :
        [*] SID      : S-1-5-32-544
        [*] Account  : BUILTIN\Administrators
        [*] SID Type : SidTypeAlias
    [*] Group :
        [*] SID      : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeUser
    [*] DACL :
        [*] AceCount  : 2
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : ALL_ACCESS
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeUser
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : TERMINATE, VM_READ, QUERY_INFORMATION, QUERY_LIMITED_INFORMATION, READ_CONTROL, SYNCHRONIZE
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
    [*] SACL :
        [*] AceCount  : 1
        [*] ACE[0x00] :
            [*] Type   : SYSTEM_AUDIT
            [*] Flags  : FAILED_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG
            [*] Access : VM_READ
            [*] SID    : S-1-1-0
                [*] Account  : Everyone
                [*] SID Type : SidTypeWellKnownGroup
[*] Done.

PS C:\Users\admin>
```

To enable `SeDebugPrivilege`, set `-d` flag:

```
PS C:\Users\admin> C:\Tools\SdDumper.exe -p 644 -d

[>] Trying to dump SecurityDescriptor for the specified process.
    [*] Process ID   : 644
    [*] Process Name : winlogon
[>] Trying to SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:BAG:SYD:(A;;0x1fffff;;;SY)(A;;0x121411;;;BA)S:AI
[*] SECURITY_DESCRIPTOR :
    [*] Owner :
        [*] SID      : S-1-5-32-544
        [*] Account  : BUILTIN\Administrators
        [*] SID Type : SidTypeAlias
    [*] Group :
        [*] SID      : S-1-5-18
        [*] Account  : NT AUTHORITY\SYSTEM
        [*] SID Type : SidTypeWellKnownGroup
    [*] DACL :
        [*] AceCount  : 2
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : ALL_ACCESS
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeWellKnownGroup
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : NONE
            [*] Access : TERMINATE, VM_READ, QUERY_INFORMATION, QUERY_LIMITED_INFORMATION, READ_CONTROL, SYNCHRONIZE
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
    [*] SACL :
        [*] AceCount  : 0
[*] Done.

PS C:\Users\admin>
```