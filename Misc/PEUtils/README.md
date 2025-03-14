# PEUtils

This script implements some simple functions for quick PE file analysis.
To import the script, simply execute `Import-Module` cmdlet as follows:

```
PS C:\Works> Import-Module .\PEUtils.psm1
```

Tested in following environments:

* Windows 11 - PowerShell 5.1.x
* macOS - PowerShell 7.4.1

Currently implemented following functions:

| Function | Description |
| :--- | :--- |
| `Get-PeFileInformation` | This function analyze a PE file's header and return a object to retrieve header information |
| `Find-DwordFromExecutable` | This function tries to find a 32bit value from PE file. |
| `Find-QwordFromExecutable` | This function tries to find a 64bit value from PE file. |
| `Find-StringFromExecutable` | This function tries to find a string (both of ASCII and Unicode) from PE file. String is case insensitive. |

## Get-PeFileInformation

Use as follows:

```
PS C:\Works> $pe = Get-PeFileInformation -Path C:\Windows\System32\ntdll.dll -DecodeRichHeader
PS C:\Works> $pe.DosHeader


e_magic    : MZ
e_cblp     : 144
e_cp       : 3
e_crlc     : 0
e_cparhdr  : 4
e_minalloc : 0
e_maxalloc : 65535
e_ss       : 0
e_sp       : 184
e_csum     : 0
e_ip       : 0
e_cs       : 0
e_lfarlc   : 64
e_ovno     : 0
e_res1     : {0, 0, 0, 0}
e_oemid    : 0
e_oeminfo  : 0
e_res2     : {0, 0, 0, 0...}
e_lfanew   : 248



PS C:\Works> $pe | Get-Member


   TypeName: System.Management.Automation.PSCustomObject

Name           MemberType   Definition
----           ----------   ----------
Equals         Method       bool Equals(System.Object obj)
GetHashCode    Method       int GetHashCode()
GetType        Method       type GetType()
ToString       Method       string ToString()
DosHeader      NoteProperty System.Management.Automation.PSCustomObject DosHeader=@{e_magic=MZ; e_cblp=144; e_cp=3; ...
NtHeaders      NoteProperty System.Management.Automation.PSCustomObject NtHeaders=@{Signature=PE; FileHeader=; Optio...
RichHeader     NoteProperty System.Management.Automation.PSCustomObject RichHeader=@{Header=DanS; Padding=System.UIn...
SectionHeaders NoteProperty Object[] SectionHeaders=System.Object[]


PS C:\Works> $pe.NtHeaders

Signature FileHeader
--------- ----------
PE        @{Machine=ARM64; NumberOfSections=18; TimeDateStamp=1431909726; PointerToSymbolTable=0; NumberOfSymbols=0;...


PS C:\Works> $pe.RichHeader


Header   : DanS
Padding  : {0, 0, 0}
Entry0   : @{Version=0; Id=0; Count=5}
Entry1   : @{Version=33140; Id=264; Count=658}
Entry2   : @{Version=33140; Id=260; Count=271}
Entry3   : @{Version=33140; Id=259; Count=120}
Entry4   : @{Version=33140; Id=261; Count=57}
Entry5   : @{Version=33140; Id=253; Count=1}
Entry6   : @{Version=33140; Id=256; Count=2}
Entry7   : @{Version=33140; Id=255; Count=1}
Entry8   : @{Version=33140; Id=258; Count=1}
Trailer  : Rich
CheckSum : 886920656



PS C:\Works> $pe.NtHeaders.Signature
PE
PS C:\Works> $pe.NtHeaders.FileHeader


Machine              : ARM64
NumberOfSections     : 18
TimeDateStamp        : 1431909726
PointerToSymbolTable : 0
NumberOfSymbols      : 0
SizeOfOptionalHeader : 240
Characteristics      : ExecutableImage, LargeAddressAware, Dll



PS C:\Works> $pe.NtHeaders.OptionalHeader


Magic                       : NT64
MajorLinkerVersion          : 14
MinorLinkerVersion          : 38
SizeOfCode                  : 3077632
SizeOfInitializedData       : 1206272
SizeOfUninitializedData     : 0
AddressOfEntryPoint         : 0
BaseOfCode                  : 4096
ImageBase                   : 6442450944
SectionAlignment            : 4096
FileAlignment               : 512
MajorOperatingSystemVersion : 10
MinorOperatingSystemVersion : 0
MajorImageVersion           : 10
MinorImageVersion           : 0
MajorSubsystemVersion       : 10
MinorSubsystemVersion       : 0
Win32VersionValue           : 0
SizeOfImage                 : 4329472
SizeOfHeaders               : 1536
CheckSum                    : 4313264
Subsystem                   : WindowsCui
DllCharacteristics          : HighEntropyVa, DynamicBase, NxCompat, GuardCf
SizeOfStackReserve          : 262144
SizeOfStackCommit           : 4096
SizeOfHeapReserve           : 1048576
SizeOfHeapCommit            : 4096
LoaderFlags                 : 0
NumberOfRvaAndSizes         : 16
Directory                   : @{Export=; Import=; Resource=; Exception=; Security=; BaseReloc=; Debug=; Architecture=;
                              GlobalPtr=; Tls=; LoadConfig=; BoundImport=; Iat=; DelayImport=; ComDescriptor=;
                              Reserved=}



PS C:\Works> $pe.NtHeaders.OptionalHeader.Directory


Export        : @{VirtualAddress=3523456; Size=90048}
Import        : @{VirtualAddress=0; Size=0}
Resource      : @{VirtualAddress=3825664; Size=494208}
Exception     : @{VirtualAddress=3690496; Size=62272}
Security      : @{VirtualAddress=4224512; Size=47296}
BaseReloc     : @{VirtualAddress=4321280; Size=3924}
Debug         : @{VirtualAddress=3298288; Size=112}
Architecture  : @{VirtualAddress=0; Size=0}
GlobalPtr     : @{VirtualAddress=0; Size=0}
Tls           : @{VirtualAddress=0; Size=0}
LoadConfig    : @{VirtualAddress=3297968; Size=320}
BoundImport   : @{VirtualAddress=0; Size=0}
Iat           : @{VirtualAddress=0; Size=0}
DelayImport   : @{VirtualAddress=0; Size=0}
ComDescriptor : @{VirtualAddress=0; Size=0}
Reserved      : @{VirtualAddress=0; Size=0}



PS C:\Works> $pe.SectionHeaders | Select-Object -Property Name, VirtualAddress, PointerToRawData, Characteristics | Format-Table

Name     VirtualAddress PointerToRawData                             Characteristics
----     -------------- ----------------                             ---------------
.text              4096             1536                CntCode, MemExecute, MemRead
.specffs        3035136          3030016                CntCode, MemExecute, MemRead
.zhexpth        3043328          3034624                CntCode, MemExecute, MemRead
SCPCFG          3051520          3039232                CntCode, MemExecute, MemRead
SCPCFGFP        3059712          3044352                CntCode, MemExecute, MemRead
SCPCFGNP        3067904          3049472                CntCode, MemExecute, MemRead
SCPCFGES        3076096          3054592                CntCode, MemExecute, MemRead
RT              3084288          3059712                CntCode, MemExecute, MemRead
PAGE            3096576          3068928                CntCode, MemExecute, MemRead
fothk           3104768          3075072                CntCode, MemExecute, MemRead
.rdata          3108864          3079168                 CntInitializedData, MemRead
.data           3616768          3584000       CntInitializedData, MemRead, MemWrite
.pdata          3690496          3593216                 CntInitializedData, MemRead
.mrdata         3760128          3662336       CntInitializedData, MemRead, MemWrite
.00cfg          3801088          3702784                 CntInitializedData, MemRead
.a64xrm         3805184          3703296                 CntInitializedData, MemRead
.rsrc           3825664          3723776                 CntInitializedData, MemRead
.reloc          4321280          4218368 CntInitializedData, MemDiscardable, MemRead


PS C:\Works>
```

If you want to check raw rich header, remove `-DecodeRichHeader` flag as follows:

```
PS C:\Works> $pe = Get-PeFileInformation -Path C:\Windows\System32\ntdll.dll
PS C:\Works> $pe.RichHeader


Header   : 1739797652
Padding  : {886920656, 886920656, 886920656}
Entry0   : @{Version=21968; Id=13533; Count=886920661}
Entry1   : @{Version=54436; Id=13781; Count=886921026}
Entry2   : @{Version=54436; Id=13785; Count=886920415}
Entry3   : @{Version=54436; Id=13790; Count=886920616}
Entry4   : @{Version=54436; Id=13784; Count=886920681}
Entry5   : @{Version=54436; Id=13344; Count=886920657}
Entry6   : @{Version=54436; Id=13789; Count=886920658}
Entry7   : @{Version=54436; Id=13346; Count=886920657}
Entry8   : @{Version=54436; Id=13791; Count=886920657}
Trailer  : Rich
CheckSum : 886920656



PS C:\Works>
```

If you want to convert between raw file offset and virutal offset, use `ToRawOffset` method or `ToVirtualOffset` method.
These methods would help binary patching with PowerShell.

```
PS C:\Works> 0x400000
4194304
PS C:\Works> $pe.ToRawOffset(0x400000)

Section RawOffset
------- ---------
.rsrc     4092416


PS C:\Works> $pe.ToVirtualOffset(4092416)

Section VirtualOffset
------- -------------
.rsrc         4194304
```


## Find-DwordFromExecutable, Find-DwordFromExecutable, Find-StringFromExecutable

These functions are to find a specific value from PE file.
Set PE file path to `-Path` parameter and some value to `-Value` parameter.
String search a bit slow (it would take tens of seconds).

```
PS C:\Works> Find-DwordFromExecutable -Path C:\Windows\System32\ntdll.dll -Value 0x35C380

RawOffset VirtualOffset Section
--------- ------------- -------
      384           384 (PE Header)


PS C:\Works> Find-QwordFromExecutable -Path C:\Windows\System32\ntdll.dll -Value 0x15FC00035C380

RawOffset VirtualOffset Section
--------- ------------- -------
      384           384 (PE Header)


PS C:\Works> Find-StringFromExecutable -Path C:\Windows\System32\ntdll.dll -Value "registry" | Format-Table

RawOffset VirtualOffset Section Encoding Value
--------- ------------- ------- -------- -----
  3128002       3157698 .rdata  Unicode  Registry
  3131114       3160810 .rdata  Unicode  REGISTRY
  3133090       3162786 .rdata  Unicode  Registry
  3133298       3162994 .rdata  Unicode  Registry
  3134258       3163954 .rdata  Unicode  Registry
  3134530       3164226 .rdata  Unicode  Registry
  3134738       3164434 .rdata  Unicode  Registry
  3141188       3170884 .rdata  ASCII    registry
  3141826       3171522 .rdata  Unicode  Registry
  3144818       3174514 .rdata  Unicode  Registry

--snip--
```
