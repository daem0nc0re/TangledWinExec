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
PS C:\Dev> .\PeRipper.exe -p C:\Windows\System32\notepad.exe -a

[*] Raw Data Size : 201216 (0x31200) bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] EntryPoint:
    [*] VirtualAddress   : 0x00023F40
    [*] PointerToRawData : 0x00023340
[*] Sections (Count = 7):
    [*] .text Section:
        [*] VirtualAddress   : 0x00001000
        [*] PointerToRawData : 0x00000400
        [*] VirtualSize      : 0x247FF
        [*] SizeOfRawData    : 0x24800
    [*] .rdata Section:
        [*] VirtualAddress   : 0x00026000
        [*] PointerToRawData : 0x00024C00
        [*] VirtualSize      : 0x9280
        [*] SizeOfRawData    : 0x9400
    [*] .data Section:
        [*] VirtualAddress   : 0x00030000
        [*] PointerToRawData : 0x0002E000
        [*] VirtualSize      : 0x2728
        [*] SizeOfRawData    : 0xE00
    [*] .pdata Section:
        [*] VirtualAddress   : 0x00033000
        [*] PointerToRawData : 0x0002EE00
        [*] VirtualSize      : 0x10EC
        [*] SizeOfRawData    : 0x1200
    [*] .didat Section:
        [*] VirtualAddress   : 0x00035000
        [*] PointerToRawData : 0x00030000
        [*] VirtualSize      : 0x178
        [*] SizeOfRawData    : 0x200
    [*] .rsrc Section:
        [*] VirtualAddress   : 0x00036000
        [*] PointerToRawData : 0x00030200
        [*] VirtualSize      : 0xBD8
        [*] SizeOfRawData    : 0xC00
    [*] .reloc Section:
        [*] VirtualAddress   : 0x00037000
        [*] PointerToRawData : 0x00030E00
        [*] VirtualSize      : 0x2D4
        [*] SizeOfRawData    : 0x400
[*] Export functions (Count = 0):
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

char data[] = {
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
