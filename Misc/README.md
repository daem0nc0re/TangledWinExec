# Misc

This directory is for helper tools.

## CalcRor13Hash

This tool is to calculate ROR13 hash of API name or DLL name for shellcoding.
If you want to calculate the hash for ASCII string, set name with `-a` option.

```
PS C:\Dev> .\CalcRor13Hash.exe -a GetProcAddress

[*] Input (ASCII) : GetProcAddress
[*] ROR13 Hash    : 0x7C0DFCAA

PS C:\Dev> .\CalcRor13Hash.exe -a GETPROCADDRESS

[*] Input (ASCII) : GETPROCADDRESS
[*] ROR13 Hash    : 0x1ACAEE7A
```

To caluculate for Unicode string, set name with `-u` option:

```
PS C:\Dev> .\CalcRor13Hash.exe -u kernel32.dll

[*] Input (Unicode) : kernel32.dll
[*] ROR13 Hash      : 0xBF5AFD6F
```

## EaDumper

This tool is for dumping extended attribute information from file:

```
PS C:\Dev> .\EaDumper.exe -h

EaDumper - Tool to dump EA information.

Usage: EaDumper.exe [Options]

        -h, --help : Displays this help message.
        -f, --file : Specifies target file path.
```

To use this tool, simply set target file name with `-f` option as follows:

```
PS C:\Dev> .\EaDumper.exe -f C:\Windows\System32\WerFaultSecure.exe

[>] Trying to dump EA information.
    [*] File Path : C:\Windows\System32\WerFaultSecure.exe
[*] Entries[0x00]
    [*] Flags    : NONE
    [*] EA Name  : $KERNEL.PURGE.ESBCACHE
    [*] EA Value :

                   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

        00000000 | 6C 00 00 00 03 00 02 0E-6D EC BB 6B 4B 6A D7 01 | l....... mì»kKjx.
        00000010 | 80 5B B6 92 03 0C D9 01-42 00 00 00 4E 00 27 01 | .[¶...U. B...N.'.
        00000020 | 0C 80 00 00 20 6E 3B FF-13 06 93 8A 50 CF 53 4E | .....n;ÿ ....PISN
        00000030 | D6 22 14 1B 63 35 44 AE-5A AE 5C 31 12 57 11 A2 | Ö"..c5Dr Zr\1.W.¢
        00000040 | 1B DD 34 75 FC 27 00 0C-80 00 00 20 6F 39 5B B9 | .Y4uü'.. ....o9[.
        00000050 | 0D 17 13 51 27 6B B2 33-01 29 FD DE 96 E7 71 B8 | ...Q'k.3 .)y_.çq,
        00000060 | 3B 2A 9B 54 E7 76 24 1F-E9 18 A8 5D             | ;*.Tçv$. é."]


    [*] Parsed EA Cache Data
        [*] Major Version        : 3
        [*] Minor Version        : 2
        [*] Signing Level        : WINDOWS_TCB
        [*] USN Journal ID       : 0x01D76A4B6BBBEC6D
        [*] Last Black List Time : 2022/12/10 04:22:27
        [*] Flags                : TrustedSignature, ProtectedLightVerification
        [*] Extra Data[0x00]
            [*] Blob Type      : SignerHash
            [*] Hash Algorithm : SHA256
            [*] Hash Value     : 6E3BFF1306938A50CF534ED622141B633544AE5AAE5C31125711A21BDD3475FC
        [*] Extra Data[0x01]
            [*] Blob Type      : FileHash
            [*] Hash Algorithm : SHA256
            [*] Hash Value     : 6F395BB90D171351276BB2330129FDDE96E771B83B2A9B54E776241FE918A85D

[*] Entries[0x01]
    [*] Flags    : NONE
    [*] EA Name  : $CI.CATALOGHINT
    [*] EA Value :

                   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

        00000000 | 01 00 61 00 4D 69 63 72-6F 73 6F 66 74 2D 57 69 | ..a.Micr osoft-Wi
        00000010 | 6E 64 6F 77 73 2D 43 6C-69 65 6E 74 2D 44 65 73 | ndows-Cl ient-Des
        00000020 | 6B 74 6F 70 2D 52 65 71-75 69 72 65 64 2D 50 61 | ktop-Req uired-Pa
        00000030 | 63 6B 61 67 65 30 35 31-36 7E 33 31 62 66 33 38 | ckage051 6~31bf38
        00000040 | 35 36 61 64 33 36 34 65-33 35 7E 61 6D 64 36 34 | 56ad364e 35~amd64
        00000050 | 7E 7E 31 30 2E 30 2E 31-39 30 34 31 2E 32 38 34 | ~~10.0.1 9041.284
        00000060 | 36 2E 63 61 74                                  | 6.cat


[*] Done.
```

## HandleScanner

This tool is for scanning handles used by processes in system:

```
PS C:\Dev> .\HandleScanner.exe -h

HandleScanner - Tool to scan handles from process.

Usage: HandleScanner.exe [Options]

        -h, --help    : Displays this help message.
        -n, --name    : Specifies string to filter handle name.
        -p, --pid     : Specifies PID to scan. Default is all processes.
        -t, --type    : Specifies string to filter handle type.
        -d, --debug   : Flag to enable SeDebugPrivilege.
        -s, --scan    : Flag to scan handle.
        -S, --system  : Flag to act as SYSTEM.
        -v, --verbose : Flag to output verbose information.

[!] -s option is required.
```

If you scan a specific process, set PID as `-p` options's parameter and `-s` flag.
When you don't specify PID, this tool will try to get handle information from all processes:

```
PS C:\Dev> .\HandleScanner.exe -s -p 692

[Handle(s) for winlogon (PID: 692)]

Handle Type            Address            Access     Object Name
====== =============== ================== ========== ===========
  0x40 Directory       0xFFFF9A0FDDABD2A0 0x00000003 \KnownDlls
  0x4C File            0xFFFFAC09FA313EE0 0x00100020 \Windows\System32
  0x50 EtwRegistration 0xFFFFAC09F8CFC280 0x00000804 \Windows\System32
  0x54 EtwRegistration 0xFFFFAC09F8CFC6E0 0x00000804 \Windows\System32
  0x5C Mutant          0xFFFFAC09F7EB0910 0x001F0001 \Sessions\1\BaseNamedObjects\SM0:692:304:WilStaging_02
  0x60 Directory       0xFFFF9A0FDD5C71A0 0x0000000F \Sessions\1\BaseNamedObjects
  0x64 Semaphore       0xFFFFAC09F845A9B0 0x001F0003 \Sessions\1\BaseNamedObjects\SM0:692:304:WilStaging_02_p0
  0x68 Semaphore       0xFFFFAC09F845AA50 0x001F0003 \Sessions\1\BaseNamedObjects\SM0:692:304:WilStaging_02_p0h
  0x6C EtwRegistration 0xFFFFAC09F8CFD780 0x00000804 \Sessions\1\BaseNamedObjects\SM0:692:304:WilStaging_02_p0h
  0x98 Key             0xFFFF9A0FDDDC04B0 0x00020019 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Nls\Sorting\Versions
  0x9C EtwRegistration 0xFFFFAC09FA3F1440 0x00000804 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Nls\Sorting\Versions
  0xA0 Key             0xFFFF9A0FDDDBFA10 0x000F003F \REGISTRY\MACHINE
  0xA4 EtwRegistration 0xFFFFAC09FA3F2400 0x00000804 \REGISTRY\MACHINE
  0xA8 EtwRegistration 0xFFFFAC09FA3F10C0 0x00000804 \REGISTRY\MACHINE
  0xAC Key             0xFFFF9A0FDDDBB0C0 0x00020019 \REGISTRY\MACHINE
  0xB0 Key             0xFFFF9A0FDDDBB1D0 0x00020019 \REGISTRY\MACHINE\SOFTWARE\Microsoft\Ole
  0xB8 Key             0xFFFF9A0FDDDBBC70 0x00020019 \REGISTRY\USER\.DEFAULT\Software\Classes\Local Settings\Software\Microsoft
  0xBC Key             0xFFFF9A0FDDDC0D30 0x00020019 \REGISTRY\USER\.DEFAULT\Software\Classes\Local Settings
 0x104 Key             0xFFFF9A0FDDDBB720 0x00000001 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager
 0x108 EtwRegistration 0xFFFFAC09FA3F1360 0x00000804 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager
 0x10C EtwRegistration 0xFFFFAC09FA3F26A0 0x00000804 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager
 0x110 EtwRegistration 0xFFFFAC09FA3F1EC0 0x00000804 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager
 0x114 EtwRegistration 0xFFFFAC09FA3F1600 0x00000804 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager
 0x134 Key             0xFFFF9A0FDDDC1E30 0x000F003F \REGISTRY\MACHINE\SOFTWARE\Classes
 0x138 Key             0xFFFF9A0FDDDC14A0 0x00000009 \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
 0x13C Key             0xFFFF9A0FDDDC19F0 0x00020019 \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 0x15C Thread          0xFFFFAC09FA3CA080 0x001FFFFF winlogon (PID: 692, TID: 696)
 0x160 EtwRegistration 0xFFFFAC09FA6F0240 0x00000804 winlogon (PID: 692, TID: 696)
 0x164 EtwRegistration 0xFFFFAC09FA6EF0C0 0x00000804 winlogon (PID: 692, TID: 696)
 0x16C Event           0xFFFFAC09F845AF50 0x001F0003 \BaseNamedObjects\WinlogonLogoff
 0x178 ALPC Port       0xFFFFAC09F8FA9090 0x001F0001 \RPC Control\WMsgKRpc0B92B1
 0x17C EtwRegistration 0xFFFFAC09FA3F2CC0 0x00000804 \RPC Control\WMsgKRpc0B92B1
 0x184 Event           0xFFFFAC09F845CCB0 0x001F0003 \BaseNamedObjects\BootShellComplete
 0x188 Desktop         0xFFFFAC09F8BE9670 0x000F01FF \Disconnect
 0x198 WindowStation   0xFFFFAC09FA5F87F0 0x000F037F \Sessions\1\Windows\WindowStations\WinSta0
 0x19C Desktop         0xFFFFAC09F8BE9490 0x000F01FF \Winlogon
 0x1A0 Event           0xFFFFAC09FAD56160 0x001F0003 \Sessions\1\BaseNamedObjects\ShellDesktopSwitchEvent
 0x1A4 WindowStation   0xFFFFAC09FA5F87F0 0x000F037F \Sessions\1\Windows\WindowStations\WinSta0
 0x1AC Key             0xFFFF9A0FDF435D90 0x00020019 \REGISTRY\USER\.DEFAULT\Control Panel\International
 0x1B0 Desktop         0xFFFFAC09F8BE9850 0x000F01FF \Default
 0x1B4 Event           0xFFFFAC09F8451B30 0x00100000 \BaseNamedObjects\TermSrvReadyEvent
 0x1B8 Section         0xFFFF9A0FDF7CBB70 0x00000004 \Sessions\1\Windows\ThemeSection
 0x1BC EtwRegistration 0xFFFFAC09FA6F05C0 0x00000804 \Sessions\1\Windows\ThemeSection
 0x20C Key             0xFFFF9A0FDF43BE40 0x000F003F \REGISTRY\USER
 0x230 Mutant          0xFFFFAC09F7EB0550 0x001F0001 \Sessions\1\BaseNamedObjects\SM0:692:120:WilError_03
 0x234 Semaphore       0xFFFFAC09F8465590 0x001F0003 \Sessions\1\BaseNamedObjects\SM0:692:120:WilError_03_p0
 0x238 Semaphore       0xFFFFAC09F8465B30 0x001F0003 \Sessions\1\BaseNamedObjects\SM0:692:120:WilError_03_p0h
 0x23C EtwRegistration 0xFFFFAC09FA7F0B40 0x00000804 \Sessions\1\BaseNamedObjects\SM0:692:120:WilError_03_p0h
 0x240 Key             0xFFFF9A0FDF662090 0x00020019 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Nls\Sorting\Ids
 0x244 Key             0xFFFF9A0FDF661A30 0x00000001 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Winlogon\Notifications\Components\GPClient
 0x248 Section         0xFFFF9A0FDF7CBF30 0x00000004 \Sessions\1\Windows\Theme206627367
 0x260 Key             0xFFFF9A0FDDDBE090 0x00000008 \REGISTRY\USER\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion
 0x264 EtwRegistration 0xFFFFAC09FA752F60 0x00000804 \REGISTRY\USER\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion
 0x268 Section         0xFFFF9A0FDF7CC770 0x00000004 \Windows\Theme97627645
 0x28C Event           0xFFFFAC09FABCAB00 0x001F0003 \Sessions\1\BaseNamedObjects\ThemesStartEvent
 0x2B0 Token           0xFFFF9A0FDF82F630 0x0000000B NT AUTHORITY\SYSTEM (AuthId: 0x3E7, Type: Primary)
 0x2B4 Token           0xFFFF9A0FDF830060 0x0000002F NT AUTHORITY\SYSTEM (AuthId: 0x3E7, Type: Primary)
 0x2B8 Key             0xFFFF9A0FE5A8AA40 0x000F003F \REGISTRY\USER\S-1-5-21-3896868301-3921591151-1374190648-1001
 0x2D4 Process         0xFFFFAC09FA7D5080 0x001FFFFF dwm.exe (PID: 800)
 0x324 File            0xFFFFAC09FACDF110 0x00100001 \Windows\System32\en-US\user32.dll.mui
 0x328 Key             0xFFFF9A0FDF660E80 0x00000001 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Winlogon\Notifications\Components\Profiles
 0x32C Key             0xFFFF9A0FDF660B50 0x00000001 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Winlogon\Notifications\Components\Sens
 0x330 EtwRegistration 0xFFFFAC09FA7F2C80 0x00000804 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Winlogon\Notifications\Components\Sens
 0x334 Key             0xFFFF9A0FDF661E70 0x00000001 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Winlogon\Notifications\Components\SessionEnv
 0x338 Key             0xFFFF9A0FDF660C60 0x00000001 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Winlogon\Notifications\Components\TermSrv
 0x35C Key             0xFFFF9A0FDFF96520 0x00020019 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\crypt32
 0x380 Token           0xFFFF9A0FE00F4060 0x000F01FF dev22h2\user (AuthId: 0x1FCA4, Type: Primary)
 0x39C Token           0xFFFF9A0FE00F8060 0x000F01FF dev22h2\user (AuthId: 0x1FB93, Type: Primary)
 0x3A0 Key             0xFFFF9A0FDFFA0480 0x00020019 \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
 0x3A4 EtwRegistration 0xFFFFAC09FACAACA0 0x00000804 \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
 0x3A8 Token           0xFFFF9A0FE013E7B0 0x0000000E dev22h2\user (AuthId: 0x1FCA4, Type: Impersonation)
 0x3B0 Token           0xFFFF9A0FE01316F0 0x0000000E dev22h2\user (AuthId: 0x1FCA4, Type: Impersonation)
 0x3B4 Token           0xFFFF9A0FE0140600 0x0000000E dev22h2\user (AuthId: 0x1FCA4, Type: Impersonation)
 0x3D4 Token           0xFFFF9A0FE013E7B0 0x0000000E dev22h2\user (AuthId: 0x1FCA4, Type: Impersonation)
 0x3D8 Key             0xFFFF9A0FDFCE2C60 0x000F003F \REGISTRY\USER\S-1-5-21-3896868301-3921591151-1374190648-1001
 0x3F4 Key             0xFFFF9A0FE0603970 0x00020019 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\NetworkProvider\HwOrder
 0x3F8 Key             0xFFFF9A0FE0603B90 0x00020019 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\NetworkProvider\ProviderOrder
 0x40C Event           0xFFFFAC09FB4B6E70 0x001F0003 \BaseNamedObjects\000000000001fca4_WlballoonKerberosNotificationEventName
 0x410 Event           0xFFFFAC09FB4B7910 0x001F0003 \BaseNamedObjects\000000000001fb93_WlballoonKerberosNotificationEventName
 0x41C Event           0xFFFFAC09FB4B84F0 0x001F0003 \BaseNamedObjects\000000000001fb93_WlballoonKerberosCloudPasswordExpired
 0x420 Event           0xFFFFAC09FB4B7CD0 0x001F0003 \BaseNamedObjects\000000000001fca4_WlballoonKerberosCloudPasswordExpired
 0x42C Event           0xFFFFAC09FB4B7550 0x001F0003 \BaseNamedObjects\000000000001fca4_WlballoonNTLMNotificationEventName
 0x430 Event           0xFFFFAC09FB4B75F0 0x001F0003 \BaseNamedObjects\000000000001fb93_WlballoonNTLMNotificationEventName
 0x43C Event           0xFFFFAC09FB4B8130 0x001F0003 \BaseNamedObjects\000000000001fca4_WlballoonSmartCardUnlockNotificationEventName
 0x440 Event           0xFFFFAC09FB4B8310 0x001F0003 \BaseNamedObjects\000000000001fb93_WlballoonSmartCardUnlockNotificationEventName
 0x44C Event           0xFFFFAC09FB4B79B0 0x001F0003 \BaseNamedObjects\000000000001fca4_WlballoonAlternateCredsNotificationEventName
 0x450 Event           0xFFFFAC09FB4B81D0 0x001F0003 \BaseNamedObjects\000000000001fb93_WlballoonAlternateCredsNotificationEventName
 0x468 File            0xFFFFAC09FB77CA90 0x00100001 \Windows\System32\en-US\winlogon.exe.mui
 0x47C Key             0xFFFF9A0FE1D9B890 0x00020019 \REGISTRY\USER\S-1-5-21-3896868301-3921591151-1374190648-1001\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
 0x48C Thread          0xFFFFAC09F7CE8080 0x001FFFFF winlogon (PID: 692, TID: 2332)


[*] Done.
```

Default setting hides handle information which failed to specify object name.
To show all object information, set `-v` flag as follows:

```
PS C:\Dev> .\HandleScanner.exe -s -p 692 -v

[Handle(s) for winlogon (PID: 692)]

Handle Type                 Address            Access     Object Name
====== ==================== ================== ========== ===========
   0x4 Event                0xFFFFAC09FA578660 0x001F0003 (N/A)
   0x8 Event                0xFFFFAC09FA57E960 0x001F0003 (N/A)
   0xC Event                0xFFFFAC09FA57EBE0 0x001F0003 (N/A)
  0x10 WaitCompletionPacket 0xFFFFAC09FA1CF8F0 0x00000001 (N/A)

--snip--

 0x460 Semaphore            0xFFFFAC09FB54C460 0x00100003 (N/A)
 0x464 Semaphore            0xFFFFAC09FB54C4E0 0x00100003 (N/A)
 0x468 File                 0xFFFFAC09FB77CA90 0x00100001 \Windows\System32\en-US\winlogon.exe.mui
 0x46C WaitCompletionPacket 0xFFFFAC09FB8B4B30 0x00000001 (N/A)
 0x470 Event                0xFFFFAC09FB7D2260 0x001F0003 (N/A)
 0x47C Key                  0xFFFF9A0FE1D9B890 0x00020019 \REGISTRY\USER\S-1-5-21-3896868301-3921591151-1374190648-1001\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
 0x488 Event                0xFFFFAC09FCB3B0E0 0x001F0003 (N/A)
 0x48C Thread               0xFFFFAC09F7CE8080 0x001FFFFF winlogon (PID: 692, TID: 2332)


[*] Done.
```

To filter the result with object type, set filter word as `-t` option's parameter as follows:

```
PS C:\Dev> .\HandleScanner.exe -s -p 692 -t file

[Handle(s) for winlogon (PID: 692)]

Handle Type Address            Access     Object Name
====== ==== ================== ========== ===========
  0x4C File 0xFFFFAC09FA313EE0 0x00100020 \Windows\System32
 0x324 File 0xFFFFAC09FACDF110 0x00100001 \Windows\System32\en-US\user32.dll.mui
 0x468 File 0xFFFFAC09FB77CA90 0x00100001 \Windows\System32\en-US\winlogon.exe.mui


[*] Done.

PS C:\Dev> .\HandleScanner.exe -s -p 692 -t file -v

[Handle(s) for winlogon (PID: 692)]

Handle Type Address            Access     Object Name
====== ==== ================== ========== ===========
  0x4C File 0xFFFFAC09FA313EE0 0x00100020 \Windows\System32
 0x200 File 0xFFFFAC09FA69A5F0 0x00100003 (N/A)
 0x210 File 0xFFFFAC09FA6A0090 0x00100001 (N/A)
 0x254 File 0xFFFFAC09FA826340 0x00100001 (N/A)
 0x324 File 0xFFFFAC09FACDF110 0x00100001 \Windows\System32\en-US\user32.dll.mui
 0x468 File 0xFFFFAC09FB77CA90 0x00100001 \Windows\System32\en-US\winlogon.exe.mui


[*] Done.
```

You can filter with object name by `-n` option as follows:

```
PS C:\Dev> .\HandleScanner.exe -s -t proc -n winlogon


[Handle(s) for lsass (PID: 1424)]

Handle Type    Address            Access     Object Name
====== ======= ================== ========== ===========
 0x918 Process 0xFFFF918DC898D080 0x00001478 winlogon.exe (PID: 692)
 0x944 Process 0xFFFF918DC898D080 0x00001478 winlogon.exe (PID: 692)
 0xB98 Process 0xFFFF918DC898D080 0x00001478 winlogon.exe (PID: 692)


[Handle(s) for svchost (PID: 3784)]

Handle Type    Address            Access     Object Name
====== ======= ================== ========== ===========
 0x1C4 Process 0xFFFF918DC898D080 0x00001478 winlogon.exe (PID: 692)
 0x1CC Process 0xFFFF918DC898D080 0x00001478 winlogon.exe (PID: 692)
 0x1D8 Process 0xFFFF918DC898D080 0x0000147A winlogon.exe (PID: 692)

[+] Found 6 handle(s).
[*] Done.
```

To enable SeDebugPrivilege, set `-d` flag.
When you set `-S` flag, this tool tries to act as SYSTEM.



## HashResolveTester

This tool is for testing API resolve with ROR13 hash:

```
C:\Dev>HashResolveTester.exe -h

HashResolveTester - Test GetProcAddress with ROR13 hash.

Usage: HashResolveTester.exe [Options]

        -h, --help    : Displays this help message.
        -l, --library : Specifies DLL name.
        -H, --hash    : Specifies ROR13 hash for the target function. Must be specified in hex format.

[!] -l option is required.
```

In my tools, ROR13 hashes for API resolve procedure are generated with upper case ASCII string.
So this tool try to resolve API address and name for a ROR13 hash generated with upper case ASCII string:

```
C:\Dev>CalcRor13Hash.exe -a GETPROCADDRESS

[*] Input (ASCII) : GETPROCADDRESS
[*] ROR13 Hash    : 0x1ACAEE7A


C:\Dev>C:\dev\Projects\TangledWinExec\Misc\CalcRor13Hash\CalcRor13Hash\bin\Release\CalcRor13Hash.exe -a GetProcAddress

[*] Input (ASCII) : GetProcAddress
[*] ROR13 Hash    : 0x7C0DFCAA


C:\Dev>HashResolveTester.exe -l kernel32 -H 0x1ACAEE7A

[*] kernel32 @ 0x00007FFBA0810000
[*] 0x1ACAEE7A => 0x00007FFBA082B690 (kernel32!GetProcAddress)


C:\Dev>C:\dev\Projects\TangledWinExec\Misc\HashResolveTester\HashResolveTester\bin\Release\HashResolveTester.exe -l kernel32 -H 0x7C0DFCAA

[*] kernel32 @ 0x00007FFBA0810000
[-] Failed to get function address by hash.
```

## PeRipper

This tool is for dumping executable code from PE file.

```
PS C:\Dev> .\PeRipper.exe -h

PeRipper - Tool to get byte data from PE file.

Usage: PeRipper.exe [Options]

        -h, --help           : Displays this help message.
        -a, --analyze        : Flag to get PE file's information.
        -d, --dump           : Flag to dump data bytes.
        -e, --export         : Flag to export raw data bytes to a file.
        -f, --format         : Specifies output format of dump data. "cs", "c" and "py" are allowed.
        -s, --size           : Specifies data size to rip.
        -p, --pe             : Specifies a PE file to load.
        -r, --rawoffset      : Specifies base address to rip with PointerToRawData.
        -v, --virtualaddress : Specifies base address to rip with VirtualAddress.
```

To check a target PE file's section and export function's information, set `-a` flag as well as a target PE file with `-p` option:

```
PS C:\Dev> .\PeRipper.exe -p C:\Windows\System32\ntdll.dll -a

[*] Raw Data Size : 2187392 (0x216080) bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x1000 bytes
[*] EntryPoint:
    [*] PointerToRawData : 0x00000000
    [*] VirtualAddress   : 0x00000000
[*] Region Information:

[Section Information (11 sections)]

   Name Offset (Raw) Offset (VA) SizeOfRawData VirtualSize Flags
======= ============ =========== ============= =========== =====
  .text   0x00001000  0x00001000      0x12E000    0x12D2CE CNT_CODE, MEM_EXECUTE, MEM_READ
   PAGE   0x0012F000  0x0012F000        0x1000       0x5BF CNT_CODE, MEM_EXECUTE, MEM_READ
     RT   0x00130000  0x00130000        0x1000       0x1CF CNT_CODE, MEM_EXECUTE, MEM_READ
  fothk   0x00131000  0x00131000        0x1000      0x1000 CNT_CODE, MEM_EXECUTE, MEM_READ
 .rdata   0x00132000  0x00132000       0x4E000     0x4D155 CNT_INITIALIZED_DATA, MEM_READ
  .data   0x00180000  0x00180000        0x4000      0xB338 CNT_INITIALIZED_DATA, MEM_READ, MEM_WRITE
 .pdata   0x00184000  0x0018C000        0xF000      0xECE8 CNT_INITIALIZED_DATA, MEM_READ
.mrdata   0x00193000  0x0019B000        0x4000      0x3540 CNT_INITIALIZED_DATA, MEM_READ, MEM_WRITE
 .00cfg   0x00197000  0x0019F000        0x1000        0x28 CNT_INITIALIZED_DATA, MEM_READ
  .rsrc   0x00198000  0x001A0000       0x76000     0x75070 CNT_INITIALIZED_DATA, MEM_READ
 .reloc   0x0020E000  0x00216000        0x1000       0x628 CNT_INITIALIZED_DATA, MEM_DISCARDABLE, MEM_READ

[Function Table (5054 entries)]

Offset (Raw) Offset (VA)   Size Export Name
============ =========== ====== ===========
  0x00001008  0x00001008   0xFA (N/A)
  0x00001130  0x00001130  0x119 (N/A)
  0x00001250  0x00001250   0x4A (N/A)
  0x000012B0  0x000012B0   0x5C (N/A)
  0x00001320  0x00001320  0x197 RtlQueryProcessDebugInformation
  0x000014C0  0x000014C0   0xE0 (N/A)

--snip--

  0x0009FA60  0x0009FA60   0x18 NtDelayExecution, ZwDelayExecution
  0x0009FA80  0x0009FA80   0x18 NtQueryDirectoryFile, ZwQueryDirectoryFile
  0x0009FAA0  0x0009FAA0   0x18 NtQuerySystemInformation, RtlGetNativeSystemInformation, ZwQuerySystemInformation

--snip--

  0x0012F510  0x0012F510   0xAF (N/A)
  0x00130010  0x00130010   0xD1 RtlAllocateMemoryBlockLookaside
  0x00130150  0x00130150   0x1C RtlFreeMemoryBlockLookaside
  0x0013016C  0x0013016C   0x63 (N/A)

[*] Done.
```

To dump bytes from a target PE file, set `-d` flag as follows.
Base address and size must be specified in hex format.
If you want to use virutal address as base address, set the value with `-v` option:

```
PS C:\Dev> .\PeRipper.exe -p C:\Windows\System32\notepad.exe -d -v 0x1000 -s 0x40

[*] Raw Data Size : 201216 (0x31200) bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] VirtualAddress (0x00001000) is in .text section.
[*] Dump 0x40 bytes in Hex Dump format:

                       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

    0000000000001000 | CC CC CC CC CC CC CC CC-4C 8B DC 48 81 EC 88 00 | IIIIIIII L.ÜH.ì..
    0000000000001010 | 00 00 48 8B 05 57 F4 02-00 48 33 C4 48 89 44 24 | ..H..Wô. .H3ÄH.D$
    0000000000001020 | 70 48 8B 84 24 B8 00 00-00 45 33 C9 49 89 43 D8 | pH..$,.. .E3ÉI.CO
    0000000000001030 | 45 33 C0 48 8B 84 24 B0-00 00 00 83 64 24 6C 00 | E3AH..$° ....d$l.

[*] Done.
```

If you want to use raw data offset as base address, set the value with `-r` option:

```
PS C:\Dev> .\PeRipper.exe -p C:\Windows\System32\notepad.exe -d -r 0x400 -s 0x40

[*] Raw Data Size : 201216 (0x31200) bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] PointerToRawData (0x00000400) is in .text section.
[*] Dump 0x40 bytes in Hex Dump format:

                       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

    0000000000000400 | CC CC CC CC CC CC CC CC-4C 8B DC 48 81 EC 88 00 | IIIIIIII L.ÜH.ì..
    0000000000000410 | 00 00 48 8B 05 57 F4 02-00 48 33 C4 48 89 44 24 | ..H..Wô. .H3ÄH.D$
    0000000000000420 | 70 48 8B 84 24 B8 00 00-00 45 33 C9 49 89 43 D8 | pH..$,.. .E3ÉI.CO
    0000000000000430 | 45 33 C0 48 8B 84 24 B0-00 00 00 83 64 24 6C 00 | E3AH..$° ....d$l.

[*] Done.
```

To dump data as some programing language format, set `-f` option.
It supports `cs` (CSharp), `c` (C/C++) and `py` (Python):

```
PS C:\Dev> .\PeRipper.exe -p C:\Windows\System32\notepad.exe -d -r 0x400 -s 0x40 -f cs

[*] Raw Data Size : 201216 (0x31200) bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] PointerToRawData (0x00000400) is in .text section.
[*] Dump 0x40 bytes in CSharp format:

var data = new byte[] {
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x4C, 0x8B, 0xDC, 0x48,
    0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x57, 0xF4, 0x02,
    0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0x8B, 0x84,
    0x24, 0xB8, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9, 0x49, 0x89, 0x43, 0xD8,
    0x45, 0x33, 0xC0, 0x48, 0x8B, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00, 0x83,
    0x64, 0x24, 0x6C, 0x00
};

[*] Done.

PS C:\Dev> .\PeRipper.exe -p C:\Windows\System32\notepad.exe -d -r 0x400 -s 0x40 -f c

[*] Raw Data Size : 201216 (0x31200) bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] PointerToRawData (0x00000400) is in .text section.
[*] Dump 0x40 bytes in C Language format:

unsigned char data[] = {
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x4C, 0x8B, 0xDC, 0x48,
    0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x57, 0xF4, 0x02,
    0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0x8B, 0x84,
    0x24, 0xB8, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9, 0x49, 0x89, 0x43, 0xD8,
    0x45, 0x33, 0xC0, 0x48, 0x8B, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00, 0x83,
    0x64, 0x24, 0x6C, 0x00
};

[*] Done.

PS C:\Dev> .\PeRipper.exe -p C:\Windows\System32\notepad.exe -d -r 0x400 -s 0x40 -f py

[*] Raw Data Size : 201216 (0x31200) bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] PointerToRawData (0x00000400) is in .text section.
[*] Dump 0x40 bytes in Python format:

data = bytearray(
    b"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xDC\x48"
    b"\x81\xEC\x88\x00\x00\x00\x48\x8B\x05\x57\xF4\x02"
    b"\x00\x48\x33\xC4\x48\x89\x44\x24\x70\x48\x8B\x84"
    b"\x24\xB8\x00\x00\x00\x45\x33\xC9\x49\x89\x43\xD8"
    b"\x45\x33\xC0\x48\x8B\x84\x24\xB0\x00\x00\x00\x83"
    b"\x64\x24\x6C\x00"
)

[*] Done.
```

To export raw data bytes into a file, set `-e` flag insted of `-d` flag.
Exported files are named as `bytes_from_module.bin` or `bytes_from_module_{index}.bin`:

```
PS C:\Dev> .\PeRipper.exe -p C:\Windows\System32\notepad.exe -e -r 0x80 -s 0x40

[*] Raw Data Size : 201216 (0x31200) bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] The specified base address is in header region.
[*] Export 0x40 bytes raw data to C:\Dev\bytes_from_module.bin.
[*] Done.

PS C:\Dev> Format-Hex .\bytes_from_module.bin


           Path: C:\Dev\bytes_from_module.bin

           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00000000   A2 13 95 77 E6 72 FB 24 E6 72 FB 24 E6 72 FB 24  ¢.wærû$ærû$ærû$
00000010   EF 0A 68 24 D6 72 FB 24 F2 19 FF 25 EC 72 FB 24  ï.h$Örû$ò..%ìrû$
00000020   F2 19 F8 25 E5 72 FB 24 F2 19 FA 25 EF 72 FB 24  ò.ø%årû$ò.ú%ïrû$
00000030   E6 72 FA 24 CE 77 FB 24 F2 19 F3 25 F9 72 FB 24  ærú$Îwû$ò.ó%ùrû$
```


## ProcAccessCheck

This tool simply check what is maximum process access for current user:

```
PS C:\Dev> .\ProcAccessCheck.exe -h

ProcAccessCheck - Tool to check maximum access rights for process.

Usage: ProcAccessCheck.exe [Options]

        -h, --help   : Displays this help message.
        -p, --pid    : Specifies process ID.
        -s, --system : Flag to act as SYSTEM.
        -d, --debug  : Flag to enable SeDebugPrivilege.
```

To check maximum access rights for a specific process, set PID by `-p` option as follows:

```
PS C:\Dev> Get-Process msmpeng

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1008     160   382364     362860              3720   0 MsMpEng


PS C:\Dev> .\ProcAccessCheck.exe -p 3720

[*] Trying to check maximum access for the specified process.
    [*] Process ID   : 3720
    [*] Process Name : MsMpEng
[*] Current User Information:
    [*] Account Name    : dev22h2\user
    [*] Integrity Level : Mandatory Label\Medium Mandatory Level
[>] Trying to get process handle.
[+] Granted Access : SYNCHRONIZE
[+] Dropped Access : (NONE)
[*] Done.
```

If you want to enable `SeDebugPrivilege`, set `-d` flag.
To act as `NT AUTHORITY\SYSTEM`, set `-s` flag:

```
PS C:\Dev> Get-Process msmpeng

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    955     102   223020     216124      19.03   3720   0 MsMpEng


PS C:\Dev> .\ProcAccessCheck.exe -p 3720 -s

[>] Trying to impersonate as SYSTEM.
[+] Impersonated as SYSTEM successfully.
[*] Trying to check maximum access for the specified process.
    [*] Process ID   : 3720
    [*] Process Name : MsMpEng
[*] Current User Information:
    [*] Account Name    : NT AUTHORITY\SYSTEM
    [*] Integrity Level : Mandatory Label\System Mandatory Level
[>] Trying to get process handle.
[+] Granted Access : PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_LIMITED_INFORMATION, SYNCHRONIZE
[+] Dropped Access : PROCESS_SUSPEND_RESUME
[*] Done.
```


## PEUtil

This script implements some simple functions for quick PE file analysis.
See [README.md](./PEUtils/README.md) for details.