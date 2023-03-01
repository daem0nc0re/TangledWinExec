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
PS C:\Dev> .\PeRipper.exe -p .\InjectLib.dll -a

[*] Raw Data Size : 10752 bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] EntryPoint:
    [*] VirtualAddress   : 0x00001420
    [*] PointerToRawData : 0x00000820
[*] Sections (Count = 6):
    [*] .text Section:
        [*] VirtualAddress   : 0x00001000
        [*] PointerToRawData : 0x00000400
        [*] SizeOfRawData    : 0x1000
    [*] .rdata Section:
        [*] VirtualAddress   : 0x00002000
        [*] PointerToRawData : 0x00001400
        [*] SizeOfRawData    : 0xE00
    [*] .data Section:
        [*] VirtualAddress   : 0x00003000
        [*] PointerToRawData : 0x00002200
        [*] SizeOfRawData    : 0x200
    [*] .pdata Section:
        [*] VirtualAddress   : 0x00004000
        [*] PointerToRawData : 0x00002400
        [*] SizeOfRawData    : 0x200
    [*] .rsrc Section:
        [*] VirtualAddress   : 0x00005000
        [*] PointerToRawData : 0x00002600
        [*] SizeOfRawData    : 0x200
    [*] .reloc Section:
        [*] VirtualAddress   : 0x00006000
        [*] PointerToRawData : 0x00002800
        [*] SizeOfRawData    : 0x200
[*] Export functions (Count = 1):
    [*] InvokeMessageBox function:
        [*] VirtualAddress   : 0x00001000
        [*] PointerToRawData : 0x00000400
[*] Done.
```

To dump bytes from a target PE file, set `-d` flag as follows.
Base address and size must be specified in hex format.
If you want to use virutal address as base address, set the value with `-v` option:

```
PS C:\Dev> .\PeRipper.exe -p .\InjectLib.dll -d -v 0x1000 -s 0x40

[*] Raw Data Size : 10752 bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] VirtualAddress (0x00001000) is in .text section.
[*] Dump 0x40 bytes in Hex Dump format:

                       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

    0000000000001000 | 40 53 48 81 EC 50 06 00-00 48 8B 05 F8 1F 00 00 | @SH.ìP.. .H..o...
    0000000000001010 | 48 33 C4 48 89 84 24 40-06 00 00 FF 15 DF 0F 00 | H3ÄH..$@ ...ÿ.ß..
    0000000000001020 | 00 33 D2 48 8D 4C 24 20-41 B8 08 02 00 00 8B D8 | .3OH.L$. A,.....O
    0000000000001030 | E8 77 0D 00 00 33 D2 48-8D 8C 24 30 02 00 00 41 | èw...3OH ..$0...A
```

If you want to use raw data offset as base address, set the value with `-r` option:

```
PS C:\Dev> .\PeRipper.exe -p .\InjectLib.dll -d -r 0x400 -s 0x40

[*] Raw Data Size : 10752 bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] PointerToRawData (0x00000400) is in .text section.
[*] Dump 0x40 bytes in Hex Dump format:

                       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

    0000000000000400 | 40 53 48 81 EC 50 06 00-00 48 8B 05 F8 1F 00 00 | @SH.ìP.. .H..o...
    0000000000000410 | 48 33 C4 48 89 84 24 40-06 00 00 FF 15 DF 0F 00 | H3ÄH..$@ ...ÿ.ß..
    0000000000000420 | 00 33 D2 48 8D 4C 24 20-41 B8 08 02 00 00 8B D8 | .3OH.L$. A,.....O
    0000000000000430 | E8 77 0D 00 00 33 D2 48-8D 8C 24 30 02 00 00 41 | èw...3OH ..$0...A
```

To dump data as some programing language format, set `-f` option.
It supports `cs` (CSharp), `c` (C/C++) and `py` (Python):

```
PS C:\Dev> .\PeRipper.exe -p .\InjectLib.dll -d -r 0x400 -s 0x40 -f cs

[*] Raw Data Size : 10752 bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] PointerToRawData (0x00000400) is in .text section.
[*] Dump 0x40 bytes in CSharp format:

var data = new byte[] {
    0x40, 0x53, 0x48, 0x81, 0xEC, 0x50, 0x06, 0x00, 0x00, 0x48, 0x8B, 0x05,
    0xF8, 0x1F, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84, 0x24, 0x40,
    0x06, 0x00, 0x00, 0xFF, 0x15, 0xDF, 0x0F, 0x00, 0x00, 0x33, 0xD2, 0x48,
    0x8D, 0x4C, 0x24, 0x20, 0x41, 0xB8, 0x08, 0x02, 0x00, 0x00, 0x8B, 0xD8,
    0xE8, 0x77, 0x0D, 0x00, 0x00, 0x33, 0xD2, 0x48, 0x8D, 0x8C, 0x24, 0x30,
    0x02, 0x00, 0x00, 0x41
};


PS C:\Dev> .\PeRipper.exe -p .\InjectLib.dll -d -r 0x400 -s 0x40 -f c

[*] Raw Data Size : 10752 bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] PointerToRawData (0x00000400) is in .text section.
[*] Dump 0x40 bytes in C Language format:

char data[] = {
    0x40, 0x53, 0x48, 0x81, 0xEC, 0x50, 0x06, 0x00, 0x00, 0x48, 0x8B, 0x05,
    0xF8, 0x1F, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84, 0x24, 0x40,
    0x06, 0x00, 0x00, 0xFF, 0x15, 0xDF, 0x0F, 0x00, 0x00, 0x33, 0xD2, 0x48,
    0x8D, 0x4C, 0x24, 0x20, 0x41, 0xB8, 0x08, 0x02, 0x00, 0x00, 0x8B, 0xD8,
    0xE8, 0x77, 0x0D, 0x00, 0x00, 0x33, 0xD2, 0x48, 0x8D, 0x8C, 0x24, 0x30,
    0x02, 0x00, 0x00, 0x41
};


PS C:\Dev> .\PeRipper.exe -p .\InjectLib.dll -d -r 0x400 -s 0x40 -f py

[*] Raw Data Size : 10752 bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] PointerToRawData (0x00000400) is in .text section.
[*] Dump 0x40 bytes in Python format:

data = bytearray(
    b"\x40\x53\x48\x81\xEC\x50\x06\x00\x00\x48\x8B\x05"
    b"\xF8\x1F\x00\x00\x48\x33\xC4\x48\x89\x84\x24\x40"
    b"\x06\x00\x00\xFF\x15\xDF\x0F\x00\x00\x33\xD2\x48"
    b"\x8D\x4C\x24\x20\x41\xB8\x08\x02\x00\x00\x8B\xD8"
    b"\xE8\x77\x0D\x00\x00\x33\xD2\x48\x8D\x8C\x24\x30"
    b"\x02\x00\x00\x41"
)
```

To export raw data bytes into a file, set `-e` flag insted of `-d` flag.
Exported files are named as `bytes_from_module.bin` or `bytes_from_module_{index}.bin`:

```
PS C:\Dev> .\PeRipper.exe -p .\InjectLib.dll -e -r 0x80 -s 0x40

[*] Raw Data Size : 10752 bytes
[*] Architecture  : AMD64
[*] Header Size   : 0x400 bytes
[*] The specified base address is in header region.
[*] Export 64 bytes raw data to C:\Dev\bytes_from_module.bin.

PS C:\Dev> Format-Hex .\bytes_from_module.bin


           Path: C:\Dev\bytes_from_module.bin

           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00000000   A8 F6 F9 A2 EC 97 97 F1 EC 97 97 F1 EC 97 97 F1  ¨öù¢ìñìñìñ
00000010   E5 EF 04 F1 EE 97 97 F1 A3 EB 96 F0 EE 97 97 F1  åï.ñîñ£ëðîñ
00000020   A3 EB 92 F0 E7 97 97 F1 A3 EB 93 F0 E4 97 97 F1  £ëðçñ£ëðäñ
00000030   A3 EB 94 F0 EF 97 97 F1 A7 EF 96 F0 E9 97 97 F1  £ëðïñ§ïðéñ
```
