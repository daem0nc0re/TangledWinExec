# Protected Process

This directory is for Protected Process related PoCs and tools.

## Table Of Contents

* [Protected Process](#protected-process)
    * [Usage](#usage)
        * [PPEditor](#ppeditor)
            * [getpps](#getpps)
            * [setpps](#setpps)
        * [SdDumper](#sddumper)
            * [Analyze SDDL](#analyze-sddl)
            * [Dump SecurityDescriptor Information](#dump-securitydescriptor-information)
            * [Edit SecurityDescriptor](#edit-securitydescriptor-information)
    * [References](#references)

## Usage
### PPEditor

[Back to Top](#protected-process)

[Project](./PPEditor)

> __Warning__
> 
> In some environment, Debug build does not work.
> Release build is preferred.

This is a Kernel-mode WinDbg extension to edit Protection Level for processes.

```
0: kd> .load C:\dev\PPEditor.dll

PPEditor - Kernel Mode WinDbg extension for Protected Process investigation.

Commands :
    + !getpps : List Protected Processes in the target system.
    + !setpps : Set Protection Level for target processes.

[*] To see command help, execute "!<Command> help" or "!<Command> /?".
```

#### getpps

This command enumerates process information in the target system.

```
0: kd> !getpps /?

!getpps - List Protected Process.

Usage :
    (1) !getpps             : List all processes.
    (2) !getpps /p          : List Protected Processes.
    (3) !getpps <PID>       : List a process has a specific PID.
    (4) !getpps <Filter>    : List processes with search filter.
    (5) !getpps /p <Filter> : List Protected Processes with search filter.

[*] Search filter is used for forward matching and case insensitive.
```

To list all processes, simply execute `!getpps`:

```
0: kd> !getpps

     PID        nt!_EPROCESS                  Protection Process Name
======== =================== =========================== ============
       0 0xfffff801`29a4d630                        None Idle
       4 0xffffb20b`38a89040         Protected-WinSystem System
      88 0xffffb20b`38ae9080         Protected-WinSystem Registry
     312 0xffffb20b`3c02d400       ProtectedLight-WinTcb smss.exe
     332 0xffffb20b`3d26e340                        None svchost.exe

--snip--

[*] Done.
```

If you want to enumerate Protected Processes only, set `/p` flag as follows:

```
0: kd> !getpps /p

     PID        nt!_EPROCESS                  Protection Process Name
======== =================== =========================== ============
       4 0xffffb20b`38a89040         Protected-WinSystem System
      88 0xffffb20b`38ae9080         Protected-WinSystem Registry
     312 0xffffb20b`3c02d400       ProtectedLight-WinTcb smss.exe
     396 0xffffb20b`3c02e080       ProtectedLight-WinTcb csrss.exe
     468 0xffffb20b`3ca40400       ProtectedLight-WinTcb wininit.exe
     476 0xffffb20b`3ca1f2c0       ProtectedLight-WinTcb csrss.exe
     608 0xffffb20b`3c9e5080       ProtectedLight-WinTcb services.exe
    2000 0xffffb20b`3d649380  ProtectedLight-AntiMalware MsMpEng.exe
    3552 0xffffb20b`3dd8c340      ProtectedLight-Windows svchost.exe
    4856 0xffffb20b`3e544080            Protected-WinTcb SgrmBroker.exe

[*] Done.
```

To check a specific PID, set the PID in decimal format.
This option also shows values of `nt!_EPROCESS.SignatureLevel` and `nt!_EPROCESS.SectionSignatureLevel`:

```
0: kd> !getpps 3552

     PID        nt!_EPROCESS                  Protection Process Name
======== =================== =========================== ============
    3552 0xffffb20b`3dd8c340      ProtectedLight-Windows svchost.exe

[*] SignatureLevel        : 0x38
[*] SectionSignatureLevel : 0x08

[*] Done.
```

If you want filter process name, set search filter as follows.
Search filter is used for forward matching and case insensitive:

```
0: kd> !getpps svchost

     PID        nt!_EPROCESS                  Protection Process Name
======== =================== =========================== ============
     332 0xffffb20b`3d26e340                        None svchost.exe
     352 0xffffb20b`3d2753c0                        None svchost.exe

--snip--

    2464 0xffffb20b`3d93a440                        None svchost.exe
    3552 0xffffb20b`3dd8c340      ProtectedLight-Windows svchost.exe
    4476 0xffffb20b`3e157080                        None svchost.exe

[*] Done.
```

Search filter can be used with `/p` flag:

```
0: kd> !getpps /p svchost

     PID        nt!_EPROCESS                  Protection Process Name
======== =================== =========================== ============
    3552 0xffffb20b`3dd8c340      ProtectedLight-Windows svchost.exe

[*] Done.
```


#### setpps

This command set Protection Level for a specific process.

```
0: kd> !setpps /?

!setpps - List Protected Process.

Usage : !setpps <PID> <Protection>

    + PID        : Specifies target PID by decimal format.
    + Protection : Specifies the Protection Level in the format "None" or "<Type>-<Signer>".
                   Type should be "ProtectedLight" or "Protected".
                   Signer should be "Authenticode", "CodeGen", "AntiMalware", "Lsa",
                   "Windows", "WinTcb", "WinSystem" or "App".

[*] Protection Level is used for case insensitive.
```

To use this command, set PID in decimal format and Protection Level as follows:

```
0: kd> !setpps 500 protectedlight-antimalware

[*] notepad.exe (PID : 500) @ 0xffffb20b`3e7e5380
[>] Setting ProtectedLight-AntiMalware protection level.
[*] SignatureLevel : 0x00, SectionSignatureLevel : 0x00
[*] If you want to change SignatureLevel or SectionSignatureLevel, set them manually with following commands.
    [*] For SignatureLevel        : eb 0xffffb20b`3e7e5380+0x6f8 0x??
    [*] For SectionSignatureLevel : eb 0xffffb20b`3e7e5380+0x6f9 0x??
[*] Done.
```


### SdDumper

[Back to Top](#protected-process)

[Project](./SdDumper)

This tool is to dump and analyze SecurityDescriptor information.

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

#### Analyze SDDL

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


#### Dump SecurityDescriptor information

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


#### Edit SecurityDescriptor information

If you want to set new Security Descriptor to objects, set SDDL as `-e` option.
This option supports file or directry objects (`-f` option), nt objects (`-n` option) and registry objects (`-r` option).

For example, to remove DACL for `NT AUTHORITY\Authenticated Users`, execute as follows:

```
C:\Tools>echo test > test.txt

C:\Tools>whoami
desktop-53v8dcq\admin

C:\Tools>echo test > test.txt

C:\Tools>dir test.txt
 Volume in drive C has no label.
 Volume Serial Number is 92CC-F021

 Directory of C:\Tools

01/15/2023  09:17 PM                 7 test.txt
               1 File(s)              7 bytes
               0 Dir(s)  44,001,705,984 bytes free

C:\Tools>icacls test.txt
test.txt BUILTIN\Administrators:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         BUILTIN\Users:(I)(RX)
         NT AUTHORITY\Authenticated Users:(I)(M)

Successfully processed 1 files; Failed processing 0 files

C:\Tools>SdDumper.exe -f test.txt -e D:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)

[>] Trying to dump SecurityDescriptor for the specified path.
    [*] Path : C:\Tools\test.txt
    [*] Type : File
[>] Checking the sepecified SDDL.
    [*] SDDL : D:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)
[+] SDDL is valid (Size = 96 Bytes).
[>] Trying to set new Security Descriptor to the specfied object.
[+] Security Descriptor is set successfully.
[*] Done.


C:\Tools>icacls test.txt
test.txt BUILTIN\Administrators:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files

C:\Tools>
```

Owner information cannot be chaged with non-owner account.
So if you want to change owner information to specail accounts such as `NT SERVICE\TrustedInstaller`, use with other tools such as [TrustExec](https://github.com/daem0nc0re/PrivFu#trustexec) or [S4uDelegator](https://github.com/daem0nc0re/PrivFu#s4udelegator) in my [PrivFu repository](https://github.com/daem0nc0re/PrivFu):

```
PS C:\Tools> .\TrustExec.exe -m exec -f -s

[>] Trying to get SYSTEM.
[>] Trying to impersonate as smss.exe.
[+] SeCreateTokenPrivilege is enabled successfully.
[+] SeAssignPrimaryTokenPrivilege is enabled successfully.
[>] Trying to impersonate thread token.
    |-> Current Thread ID : 3124
[+] Impersonation is successful.
[>] Trying to create an elevated primary token.
[+] An elevated primary token is created successfully.
[>] Trying to create a token assigned process.

Microsoft Windows [Version 10.0.22000.318]
(c) Microsoft Corporation. All rights reserved.

C:\Tools>whoami
nt authority\system

C:\Tools>whoami /groups | findstr /i trusted
NT SERVICE\TrustedInstaller            Well-known group S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 Enabled by default, Enabled group, Group owner

C:\Tools>SdDumper.exe -f test.txt -e O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464

[>] Trying to dump SecurityDescriptor for the specified path.
    [*] Path : C:\Tools\test.txt
    [*] Type : File
[>] Checking the sepecified SDDL.
    [*] SDDL : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
[+] SDDL is valid (Size = 52 Bytes).
[>] Trying to set new Security Descriptor to the specfied object.
[+] Security Descriptor is set successfully.
[*] Done.


C:\Tools>SdDumper.exe -f test.txt

[>] Trying to dump SecurityDescriptor for the specified path.
    [*] Path : C:\Tools\test.txt
    [*] Type : File
[+] Got valid SecuritySescriptor string.
    [*] SDDL : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-21-36110069-1586757501-3586480897-513D:(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)
[*] SECURITY_DESCRIPTOR :
    [*] Owner :
        [*] SID      : S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
        [*] Account  : NT SERVICE\TrustedInstaller
        [*] SID Type : SidTypeWellKnownGroup
    [*] Group :
        [*] SID      : S-1-5-21-36110069-1586757501-3586480897-513
        [*] Account  : DESKTOP-53V8DCQ\None
        [*] SID Type : SidTypeGroup
    [*] DACL :
        [*] AceCount  : 3
        [*] ACE[0x00] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : INHERITED_ACE
            [*] Access : FILE_ALL_ACCESS
            [*] SID    : S-1-5-32-544
                [*] Account  : BUILTIN\Administrators
                [*] SID Type : SidTypeAlias
        [*] ACE[0x01] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : INHERITED_ACE
            [*] Access : FILE_ALL_ACCESS
            [*] SID    : S-1-5-18
                [*] Account  : NT AUTHORITY\SYSTEM
                [*] SID Type : SidTypeUser
        [*] ACE[0x02] :
            [*] Type   : ACCESS_ALLOWED
            [*] Flags  : INHERITED_ACE
            [*] Access : FILE_READ_DATA, FILE_READ_EA, FILE_STANDARD_EXECUTE
            [*] SID    : S-1-5-32-545
                [*] Account  : BUILTIN\Users
                [*] SID Type : SidTypeAlias
    [*] SACL : N/A (NO_ACCESS_CONTROL)
[*] Done.


C:\Tools>
```


## References

[Back to Top](#protected-process)

* [Unknown Known DLLs](http://publications.alex-ionescu.com/Recon/Recon%202018%20-%20Unknown%20Known%20DLLs%20and%20other%20code%20integrity%20trust%20violations.pdf)

* [Unreal Mode : Breaking Protected Processes](https://www.nosuchcon.org/talks/2014/D3_05_Alex_ionescu_Breaking_protected_processes.pdf)

* [The Evolution of Protected Processes – Part 1: Pass-the-Hash Mitigations in Windows 8.1](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/)

* [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.crowdstrike.com/blog/evolution-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and/)

* [Protected Processes Part 3 : Windows PKI Internals (Signing Levels, Scenarios, Root Keys, EKUs & Runtime Signers)](https://www.crowdstrike.com/blog/protected-processes-part-3-windows-pki-internals-signing-levels-scenarios-signers-root-keys/)

* [Windows Exploitation Tricks: Exploiting Arbitrary Object Directory Creation for Local Elevation of Privilege](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html)

* [Injecting Code into Windows Protected Processes using COM - Part 1](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html)

* [Injecting Code into Windows Protected Processes using COM - Part 2](https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html)

* [Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/)

* [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/)

* [Debugging Protected Processes](https://itm4n.github.io/debugging-protected-processes/)

* [The End of PPLdump](https://itm4n.github.io/the-end-of-ppldump/)

* [Protecting Windows protected processes](https://www.elastic.co/blog/protecting-windows-protected-processes)

* [Relevance of Security Features Introduced in Modern Windows OS](https://aaltodoc.aalto.fi/bitstream/handle/123456789/38990/master_Aquilino_Broderick_2019.pdf?sequence=1&isAllowed=y)

* [Bypassing LSA Protection (aka Protected Process Light) without Mimikatz on Windows 10](https://redcursor.com.au/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10/)

* [Debugging the undebuggable and finding a CVE in Microsoft Defender for Endpoint](https://medium.com/falconforce/debugging-the-undebuggable-and-finding-a-cve-in-microsoft-defender-for-endpoint-ce36f50bb31)
