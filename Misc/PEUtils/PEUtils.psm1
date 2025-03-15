Set-StrictMode -Version Latest

#
# Type Definitions
#
Add-Type -Language CSharp -TypeDefinition @"
using System;

public enum ImageHeaderMagic : ushort
{
    NT32 = 0x10B,
    NT64 = 0x20B,
    ROM = 0x107
}


public enum ImageFileMachine : ushort
{
    UNKNOWN = 0,
    I386 = 0x014C,
    R3000BE = 0x0160,
    R3000LE = 0x0162,
    R4000 = 0x0166,
    R10000 = 0x0168,
    WCEMIPSV2 = 0x0169,
    ALPHA = 0x0184,
    SH3 = 0x01A2,
    SH3DSP = 0x01A3,
    SH3E = 0x01A4,
    SH4 = 0x01A6,
    SH5 = 0x01A8,
    ARM = 0x01C0,
    THUMB = 0x01C2,
    ARM2 = 0x01C4,
    AM33 = 0x01D3,
    POWERPC = 0x01F0,
    POWERPCFP = 0x01F1,
    IA64 = 0x0200,
    MIPS16 = 0x0266,
    ALPHA64 = 0x0284,
    MIPSFPU = 0x0366,
    MIPSFPU16 = 0x0466,
    AXP64 = 0x0284,
    TRICORE = 0x0520,
    CEF = 0x0CEF,
    EBC = 0x0EBC,
    AMD64 = 0x8664,
    M32R = 0x9041,
    ARM64 = 0xAA64,
    CEE = 0xC0EE
}


public enum ImageSybsystemType : ushort
{
    Unknown = 0,
    Native = 1,
    WindowsGui = 2,
    WindowsCui = 3,
    Os2Cui = 5,
    PosixCui = 7,
    WindowsCeGui = 9,
    EfiApllication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13,
    Xbox = 14,
    WindowsBootApplication = 16
}


[Flags]
public enum ImageFileCharacteristics : ushort
{
    RelocsStripped = 0x0001,
    ExecutableImage = 0x0002,
    LineNumsStripped = 0x0004,
    LocalSymsStripped = 0x0008,
    AggresiveWsTrim = 0x0010,
    LargeAddressAware = 0x0020,
    BytesReservedLo = 0x0080,
    Machine32Bit = 0x0100,
    DebugStripped = 0x0200,
    RemovableRunFromSwap = 0x0400,
    NetRunFromSwap = 0x0800,
    System = 0x1000,
    Dll = 0x2000,
    UpSystemOnly = 0x4000,
    BytesReservedHi = 0x8000
}


[Flags]
public enum ImageCharacteristics : ushort
{
    Reserved0 = 0x0001,
    Reserved1 = 0x0002,
    Reserved2 = 0x0004,
    Reserved3 = 0x0008,
    HighEntropyVa = 0x0020,
    DynamicBase = 0x0040,
    ForceIntegrity = 0x0080,
    NxCompat = 0x0100,
    NoIsolation = 0x0200,
    NoSeh = 0x0400,
    NoBind = 0x0800,
    AppContainer = 0x1000,
    WdmDriver = 0x2000,
    GuardCf = 0x4000,
    TerminalServerAware = 0x8000
}


[Flags]
public enum SectionCharacteristics : uint
{
    NoPad = 0x00000008,
    CntCode = 0x00000020,
    CntInitializedData = 0x00000040,
    CntUninitializedData = 0x00000080,
    LnkInfo = 0x00000200,
    LnkRemove = 0x00000800,
    LnkComdat = 0x00001000,
    NoDeferSpecExc = 0x00004000,
    Gprel = 0x00008000,
    MemFarData = 0x00008000,
    MemPurgeable = 0x00020000,
    Mem16Bit = 0x00020000,
    MemLocked = 0x00040000,
    MemPreload = 0x00080000,
    Align1Bytes = 0x00100000,
    Align2Bytes = 0x00200000,
    Align4Bytes = 0x00300000,
    Align8Bytes = 0x00400000,
    Align16Bytes = 0x00500000,
    Align32Bytes = 0x00600000,
    Align64Bytes = 0x00700000,
    Align128Bytes = 0x00800000,
    Align256Bytes = 0x00900000,
    Align512Bytes = 0x00A00000,
    Align1024Bytes = 0x00B00000,
    Align2048Bytes = 0x00C00000,
    Align4096Bytes = 0x00D00000,
    Align8192Bytes = 0x00E00000,
    AlignMask = 0x00F00000,
    LnkNrelocOvfl = 0x01000000,
    MemDiscardable = 0x02000000,
    MemNotCached = 0x04000000,
    MemNotPaged = 0x08000000,
    MemShared = 0x10000000,
    MemExecute = 0x20000000,
    MemRead = 0x40000000,
    MemWrite = 0x80000000
}
"@

#
# Helper Functions
#
function Get-ImageDosHeader {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [byte[]]$FileBytes
    )

    if ($FileBytes.Length -lt 0x40) {
        throw "Input data is too small."
        return $null
    }

    $magic = [System.BitConverter]::ToUInt16($FileBytes, 0)

    if ([System.BitConverter]::ToUInt16($FileBytes, 0) -ne 0x5A4D) {
        throw "Invalid DOS header magic."
        return $null
    }

    $magicString = [System.Text.Encoding]::ASCII.GetString(([System.BitConverter]::GetBytes($magic))).TrimEnd("`0")
    $returnObject = [PSCustomObject]@{
        e_magic = $magicString
        e_cblp = [System.BitConverter]::ToUInt16($FileBytes, 0x2)
        e_cp = [System.BitConverter]::ToUInt16($FileBytes, 0x4)
        e_crlc = [System.BitConverter]::ToUInt16($FileBytes, 0x6)
        e_cparhdr = [System.BitConverter]::ToUInt16($FileBytes, 0x8)
        e_minalloc = [System.BitConverter]::ToUInt16($FileBytes, 0xA)
        e_maxalloc = [System.BitConverter]::ToUInt16($FileBytes, 0xC)
        e_ss = [System.BitConverter]::ToUInt16($FileBytes, 0xE)
        e_sp = [System.BitConverter]::ToUInt16($FileBytes, 0x10)
        e_csum = [System.BitConverter]::ToUInt16($FileBytes, 0x12)
        e_ip = [System.BitConverter]::ToUInt16($FileBytes, 0x14)
        e_cs = [System.BitConverter]::ToUInt16($FileBytes, 0x16)
        e_lfarlc = [System.BitConverter]::ToUInt16($FileBytes, 0x18)
        e_ovno = [System.BitConverter]::ToUInt16($FileBytes, 0x1A)
        e_res1 = New-Object UInt16[] 4
        e_oemid = [System.BitConverter]::ToUInt16($FileBytes, 0x24)
        e_oeminfo = [System.BitConverter]::ToUInt16($FileBytes, 0x26)
        e_res2 = New-Object UInt16[] 10
        e_lfanew = [System.BitConverter]::ToUInt32($FileBytes, 0x3C)
    }

    for ($idx = 0; $idx -lt 4; $idx++) {
        $returnObject.e_res1[$idx] = [System.BitConverter]::ToUInt16($FileBytes, 0x1C + ($idx * 2))
    }

    for ($idx = 0; $idx -lt 10; $idx++) {
        $returnObject.e_res2[$idx] = [System.BitConverter]::ToUInt16($FileBytes, 0x28 + ($idx * 2))
    }

    $returnObject
}


function Get-ImageRichHeader {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [byte[]]$FileBytes,

        [switch]$Decode
    )

    $returnObject = $null
    $e_lfanew = (Get-ImageDosHeader -FileBytes $FileBytes).e_lfanew
    $headMagic = [System.BitConverter]::ToUInt32($FileBytes, 0x80)

    for ($idx = 0x80; $idx -le ($e_lfanew - 0x8); $idx += 4) {
        $tailMagic = [System.BitConverter]::ToUInt32($FileBytes, $idx)
        $xorKey = [System.BitConverter]::ToUInt32($FileBytes, $idx + 4)
        $xorKeyHiWord = [UInt16](($xorKey -shr 16) -band 0xFFFF)
        $xorKeyLowWord = [UInt16]($xorKey -band 0xFFFF)

        if ($tailMagic -ne 0x68636952) {
            continue
        }

        if (($headMagic -bxor $xorKey) -eq 0x536E6144) {
            $tailMagicString = [System.Text.Encoding]::ASCII.GetString($FileBytes, $idx, 4).TrimEnd("`0")
            $nEntryBytes = $idx - 0x90

            if ($Decode) {
                $returnObject = [PSCustomObject]@{
                    Header = [System.Text.Encoding]::ASCII.GetString([System.BitConverter]::GetBytes($headMagic -bxor $xorKey)).TrimEnd("`0")
                    Padding = [UInt32[]]@(
                        ([System.BitConverter]::ToUInt32($FileBytes, 0x84) -bxor $xorKey),
                        ([System.BitConverter]::ToUInt32($FileBytes, 0x88) -bxor $xorKey),
                        ([System.BitConverter]::ToUInt32($FileBytes, 0x8C) -bxor $xorKey)
                    )
                }

                for ($oft = 0; $oft -lt $nEntryBytes; $oft += 8) {
                    $propName = "Entry$($oft -shr 3)"
                    $propValue = [PSCustomObject]@{
                        Version = [System.BitConverter]::ToUInt16($FileBytes, $oft + 0x90) -bxor $xorKeyLowWord
                        Id = [System.BitConverter]::ToUInt16($FileBytes, $oft + 0x92) -bxor $xorKeyHiWord
                        Count = [System.BitConverter]::ToUInt32($FileBytes, $oft + 0x94) -bxor $xorKey
                    }
                    Add-Member -MemberType NoteProperty -InputObject $returnObject -Name $propName -Value $propValue
                }
            } else {
                $returnObject = [PSCustomObject]@{
                    Header = $headMagic
                    Padding = [UInt32[]]@(
                        [System.BitConverter]::ToUInt32($FileBytes, 0x84),
                        [System.BitConverter]::ToUInt32($FileBytes, 0x88),
                        [System.BitConverter]::ToUInt32($FileBytes, 0x8C)
                    )
                }

                for ($oft = 0; $oft -lt $nEntryBytes; $oft += 8) {
                    $propName = "Entry$($oft -shr 3)"
                    $propValue = [PSCustomObject]@{
                        Version = [System.BitConverter]::ToUInt16($FileBytes, $oft + 0x90)
                        Id = [System.BitConverter]::ToUInt16($FileBytes, $oft + 0x92)
                        Count = [System.BitConverter]::ToUInt32($FileBytes, $oft + 0x94)
                    }
                    Add-Member -MemberType NoteProperty -InputObject $returnObject -Name $propName -Value $propValue
                }
            }

            Add-Member -MemberType NoteProperty -InputObject $returnObject -Name "Trailer" -Value $tailMagicString
            Add-Member -MemberType NoteProperty -InputObject $returnObject -Name "CheckSum" -Value $xorKey
            break
        }
    }

    $returnObject
}


function Get-ImageNtHeaders {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [byte[]]$FileBytes
    )

    $e_lfanew = (Get-ImageDosHeader -FileBytes $FileBytes).e_lfanew

    if (($e_lfanew + 0xF8) -gt $FileBytes.Length) {
        throw "File size is too small."
        return $null
    }

    $magic = [ImageHeaderMagic][System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x18)

    if (($magic -eq [ImageHeaderMagic]::NT32) -or ($magic -eq [ImageHeaderMagic]::NT64)) {
        $nPeSize = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x54)
    } else {
        throw "Invalid NT header magic."
        return $null
    }

    if ($nPeSize -gt $FileBytes.Length) {
        throw "File size is too small."
        return $null
    }

    $signature = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew)

    if ($signature -ne 0x4550) {
        throw "Invalid PE magic."
        return $null
    }

    $signatureString = [System.Text.Encoding]::ASCII.GetString(([System.BitConverter]::GetBytes($signature))).TrimEnd("`0")
    $fileHeader = [PSCustomObject]@{
        Machine = [ImageFileMachine][System.BitConverter]::ToInt16($FileBytes, $e_lfanew + 0x4)
        NumberOfSections = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x6)
        TimeDateStamp = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x8)
        PointerToSymbolTable = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xC)
        NumberOfSymbols = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x10)
        SizeOfOptionalHeader = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x14)
        Characteristics = [ImageFileCharacteristics][System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x16)
    }

    if ($magic -eq [ImageHeaderMagic]::NT64) {
        $optionalHeader = [PSCustomObject]@{
            Magic = $magic
            MajorLinkerVersion = $FileBytes[$e_lfanew + 0x1A]
            MinorLinkerVersion = $FileBytes[$e_lfanew + 0x1B]
            SizeOfCode = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x1C)
            SizeOfInitializedData = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x20)
            SizeOfUninitializedData = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x24)
            AddressOfEntryPoint = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x28)
            BaseOfCode = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x2C)
            ImageBase = [System.BitConverter]::ToUInt64($FileBytes, $e_lfanew + 0x30)
            SectionAlignment = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x38)
            FileAlignment = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x3C)
            MajorOperatingSystemVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x40)
            MinorOperatingSystemVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x42)
            MajorImageVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x44)
            MinorImageVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x46)
            MajorSubsystemVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x48)
            MinorSubsystemVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x4A)
            Win32VersionValue = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x4C)
            SizeOfImage = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x50)
            SizeOfHeaders = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x54)
            CheckSum = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x58)
            Subsystem = [ImageSybsystemType][System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x5C)
            DllCharacteristics = [ImageCharacteristics][System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x5E)
            SizeOfStackReserve = [System.BitConverter]::ToUInt64($FileBytes, $e_lfanew + 0x60)
            SizeOfStackCommit = [System.BitConverter]::ToUInt64($FileBytes, $e_lfanew + 0x68)
            SizeOfHeapReserve = [System.BitConverter]::ToUInt64($FileBytes, $e_lfanew + 0x70)
            SizeOfHeapCommit = [System.BitConverter]::ToUInt64($FileBytes, $e_lfanew + 0x78)
            LoaderFlags = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x80)
            NumberOfRvaAndSizes = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x84)
            Directory = [PSCustomObject]@{
                Export = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x88)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x8C)
                }
                Import = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x90)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x94)
                }
                Resource = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x98)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x9C)
                }
                Exception = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xA0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xA4)
                }
                Security = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xA8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xAC)
                }
                BaseReloc = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xB0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xB4)
                }
                Debug = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xB8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xBC)
                }
                Architecture = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xC0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xC4)
                }
                GlobalPtr = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xC8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xCC)
                }
                Tls = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xD0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xD4)
                }
                LoadConfig = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xD8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xDC)
                }
                BoundImport = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xE0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xE4)
                }
                Iat = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xE8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xEC)
                }
                DelayImport = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xF0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xF4)
                }
                ComDescriptor = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xF8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xFC)
                }
                Reserved = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x100)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x104)
                }
            }
        }
    } else {
        $optionalHeader = [PSCustomObject]@{
            Magic = $magic
            MajorLinkerVersion = $FileBytes[$e_lfanew + 0x1A]
            MinorLinkerVersion = $FileBytes[$e_lfanew + 0x1B]
            SizeOfCode = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x1C)
            SizeOfInitializedData = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x20)
            SizeOfUninitializedData = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x24)
            AddressOfEntryPoint = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x28)
            BaseOfCode = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x2C)
            BaseOfData = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x30)
            ImageBase = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x34)
            SectionAlignment = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x38)
            FileAlignment = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x3C)
            MajorOperatingSystemVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x40)
            MinorOperatingSystemVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x42)
            MajorImageVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x44)
            MinorImageVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x46)
            MajorSubsystemVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x48)
            MinorSubsystemVersion = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x4A)
            Win32VersionValue = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x4C)
            SizeOfImage = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x50)
            SizeOfHeaders = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x54)
            CheckSum = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x58)
            Subsystem = [ImageSybsystemType][System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x5C)
            DllCharacteristics = [ImageCharacteristics][System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x5E)
            SizeOfStackReserve = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x60)
            SizeOfStackCommit = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x64)
            SizeOfHeapReserve = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x68)
            SizeOfHeapCommit = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x6C)
            LoaderFlags = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x70)
            NumberOfRvaAndSizes = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x74)
            Directory = [PSCustomObject]@{
                Export = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x78)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x7C)
                }
                Import = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x80)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x84)
                }
                Resource = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x88)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x8C)
                }
                Exception = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x90)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x94)
                }
                Security = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x98)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0x9C)
                }
                BaseReloc = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xA0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xA4)
                }
                Debug = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xA8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xAC)
                }
                Architecture = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xB0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xB4)
                }
                GlobalPtr = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xB8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xBC)
                }
                Tls = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xC0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xC4)
                }
                LoadConfig = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xC8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xCC)
                }
                BoundImport = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xD0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xD4)
                }
                Iat = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xD8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xDC)
                }
                DelayImport = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xE0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xE4)
                }
                ComDescriptor = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xE8)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xEC)
                }
                Reserved = [PSCustomObject]@{
                    VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xF0)
                    Size = [System.BitConverter]::ToUInt32($FileBytes, $e_lfanew + 0xF4)
                }
            }
        }
    }
    
    [PSCustomObject]@{
        Signature = $signatureString
        FileHeader = $fileHeader
        OptionalHeader = $optionalHeader
    }
}


function Get-ImageSectionHeaders {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [byte[]]$FileBytes
    )

    $e_lfanew = (Get-ImageDosHeader -FileBytes $FileBytes).e_lfanew
    $nPeHeaderSize = (Get-ImageNtHeaders -FileBytes $FileBytes).OptionalHeader.SizeOfHeaders
    $nSectionHeaderSize = 0x28
    $sectionHeaders = @()

    if ($nPeHeaderSize -gt $FileBytes.Length) {
        Write-Warning "Invalid PE header."
        return $null
    }

    $nNumberOfSections = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x6)
    $nOptionalHeaderSize = [System.BitConverter]::ToUInt16($FileBytes, $e_lfanew + 0x14)
    $nSectionOffset = $e_lfanew + 0x18 + $nOptionalHeaderSize

    for ($idx = 0; $idx -lt $nNumberOfSections; $idx++) {
        $nCurrentHeaderOffset = $nSectionOffset + ($idx * $nSectionHeaderSize)
        $headerObject = [PSCustomObject]@{
            Name = [System.Text.Encoding]::ASCII.GetString($FileBytes, $nCurrentHeaderOffset, 8).TrimEnd("`0")
            VirtualSize = [System.BitConverter]::ToUInt32($FileBytes, $nCurrentHeaderOffset + 0x8)
            VirtualAddress = [System.BitConverter]::ToUInt32($FileBytes, $nCurrentHeaderOffset + 0xC)
            SizeOfRawData = [System.BitConverter]::ToUInt32($FileBytes, $nCurrentHeaderOffset + 0x10)
            PointerToRawData = [System.BitConverter]::ToUInt32($FileBytes, $nCurrentHeaderOffset + 0x14)
            PointerToRelocations = [System.BitConverter]::ToUInt32($FileBytes, $nCurrentHeaderOffset + 0x18)
            PointerToLinenumbers = [System.BitConverter]::ToUInt32($FileBytes, $nCurrentHeaderOffset + 0x1C)
            NumberOfRelocations = [System.BitConverter]::ToUInt16($FileBytes, $nCurrentHeaderOffset + 0x20)
            NumberOfLinenumbers = [System.BitConverter]::ToUInt16($FileBytes, $nCurrentHeaderOffset + 0x22)
            Characteristics = [SectionCharacteristics][System.BitConverter]::ToUInt32($FileBytes, $nCurrentHeaderOffset + 0x24)
        }
        $sectionHeaders += $headerObject
    }

    $sectionHeaders
}


#
# Export Functions
#
function Get-PeFileInformation {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,

        [switch]$DecodeRichHeader
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fileBytes = [System.IO.File]::ReadAllBytes($fullPath)
    $dosHeader = Get-ImageDosHeader -FileBytes $fileBytes
    $richHeader = Get-ImageRichHeader -File $fileBytes -Decode:$DecodeRichHeader
    $ntHeaders = Get-ImageNtHeaders -FileBytes $fileBytes
    $sectionHeaders = Get-ImageSectionHeaders -FileBytes $fileBytes
    $returnObject = $null

    if ($richHeader -ne $null) {
        $returnObject = [PSCustomObject]@{
            DosHeader = $dosHeader
            RichHeader = $richHeader
            NtHeaders = $ntHeaders
            SectionHeaders = $sectionHeaders
        }
    } else {
        $returnObject = [PSCustomObject]@{
            DosHeader = $dosHeader
            NtHeaders = $ntHeaders
            SectionHeaders = $sectionHeaders
        }
    }

    $toVirtualOffset = {
        param([UInt32]$RawOffset)

        $virtualOffsetObject = [PSCustomObject]@{
            Section = "(Out of Range)"
            VirtualOffset = $RawOffset
        }

        if ($RawOffset -lt $this.NtHeaders.OptionalHeader.SizeOfHeaders) {
            $virtualOffsetObject.Section = "(PE Header)"
        } else {
            foreach ($header in $this.SectionHeaders) {
                if (($RawOffset -ge $header.PointerToRawData) -and
                    ($RawOffset -lt ($header.PointerToRawData + $header.SizeOfRawData))) {
                    $virtualOffsetObject.Section = $header.Name
                    $virtualOffsetObject.VirtualOffset = $RawOffset - $header.PointerToRawData + $header.VirtualAddress
                    break
                }
            }
        }

        $virtualOffsetObject
    }

    $toRawOffset = {
        param([UInt32]$VirtualOffset)

        $rawOffsetObject = [PSCustomObject]@{
            Section = "(Out of Range)"
            RawOffset = $VirtualOffset
        }
        $nRawHeaderSize = $this.NtHeaders.OptionalHeader.SizeOfHeaders
        $nVirutalHeaderSize = [UInt32](($nRawHeaderSize + 0x1000) -band 0xFFFFF000)

        if ($VirtualOffset -lt $nVirutalHeaderSize) {
            $rawOffsetObject.Section = "(PE Header)"
        } else {
            foreach ($header in $this.SectionHeaders) {
                $nVirtualSectionSize = [UInt32](($header.VirtualSize + 0x1000) -band 0xFFFFF000)

                if (($VirtualOffset -ge $header.VirtualAddress) -and
                    ($VirtualOffset -lt ($header.VirtualAddress + $nVirtualSectionSize))) {
                    $rawOffsetObject.Section = $header.Name
                    $rawOffsetObject.RawOffset = $VirtualOffset - $header.VirtualAddress + $header.PointerToRawData
                    break
                }
            }
        }

        $rawOffsetObject
    }

    Add-Member -MemberType ScriptMethod -InputObject $returnObject -Name "ToVirtualOffset" -Value $toVirtualOffset
    Add-Member -MemberType ScriptMethod -InputObject $returnObject -Name "ToRawOffset" -Value $toRawOffset

    $returnObject
}


function Find-DwordFromExecutable {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Path,
        [Parameter(Mandatory=$true,Position=1)]
        [Int32]$Value
    )

    $returnObject = @()
    $Path = [System.IO.Path]::GetFullPath($Path)
    $FileBytes = [System.IO.File]::ReadAllBytes($Path)
    $nPeHeaderSize = (Get-ImageNtHeaders -FileBytes $FileBytes).OptionalHeader.SizeOfHeaders
    $headers = Get-ImageSectionHeaders -FileBytes $FileBytes

    for ($idx = 0; $idx -le ($FileBytes.Length - 4); $idx += 4) {
        $target = [System.BitConverter]::ToInt32($FileBytes, $idx)

        if ($target -ne $Value) {
            continue
        }

        $oftObject = [PSCustomObject]@{
            RawOffset = $idx
            VirtualOffset = 0
            Section = "(UNKNOWN)"
        }

        if ($idx -lt $nPeHeaderSize) {
            $oftObject.VirtualOffset = $idx
            $oftObject.Section = "(PE Header)"
        } else {
            foreach ($header in $headers) {
                if (($idx -ge $header.PointerToRawData) -and
                    ($idx -lt ($header.PointerToRawData + $header.SizeOfRawData))) {
                    $oftObject.VirtualOffset = $idx - $header.PointerToRawData + $header.VirtualAddress
                    $oftObject.Section = $header.Name
                    break
                }
            }
        }
        
        $returnObject += $oftObject
    }

    $returnObject
}


function Find-QwordFromExecutable {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Path,
        [Parameter(Mandatory=$true,Position=1)]
        [Int64]$Value
    )

    $returnObject = @()
    $Path = [System.IO.Path]::GetFullPath($Path)
    $FileBytes = [System.IO.File]::ReadAllBytes($Path)
    $nPeHeaderSize = (Get-ImageNtHeaders -FileBytes $FileBytes).OptionalHeader.SizeOfHeaders
    $headers = Get-ImageSectionHeaders -FileBytes $FileBytes

    for ($idx = 0; $idx -le ($FileBytes.Length - 8); $idx += 8) {
        $target = [System.BitConverter]::ToInt64($FileBytes, $idx)

        if ($target -ne $Value) {
            continue
        }

        $oftObject = [PSCustomObject]@{
            RawOffset = $idx
            VirtualOffset = 0
            Section = "(UNKNOWN)"
        }

        if ($idx -lt $nPeHeaderSize) {
            $oftObject.VirtualOffset = $idx
            $oftObject.Section = "(PE Header)"
        } else {
            foreach ($header in $headers) {
                if (($idx -ge $header.PointerToRawData) -and
                    ($idx -lt ($header.PointerToRawData + $header.SizeOfRawData))) {
                    $oftObject.VirtualOffset = $idx - $header.PointerToRawData + $header.VirtualAddress
                    $oftObject.Section = $header.Name
                    break
                }
            }
        }
        
        $returnObject += $oftObject
    }

    $returnObject
}


function Find-StringFromExecutable {
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Path,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Value
    )

    $returnObject = @()
    $Path = [System.IO.Path]::GetFullPath($Path)
    $FileBytes = [System.IO.File]::ReadAllBytes($Path)
    $nPeHeaderSize = (Get-ImageNtHeaders -FileBytes $FileBytes).OptionalHeader.SizeOfHeaders
    $headers = Get-ImageSectionHeaders -FileBytes $FileBytes
    $nAsciiRange = $FileBytes.Length - $Value.Length
    $nUnicodeRange = $FileBytes.Length - ($Value.Length * 2)
    $nAsciiStringLength = $Value.Length
    $nUnicodeStringLength = $Value.Length * 2

    for ($idx = 0; $idx -le $nAsciiRange; $idx++) {
        $asciiString = [System.Text.Encoding]::ASCII.GetString($FileBytes, $idx, $nAsciiStringLength)
        $unicodeString = $null
        $oftObject = [PSCustomObject]@{
            RawOffset = $idx
            VirtualOffset = 0
            Section = [String]::Empty
            Encoding = [String]::Empty
            Value = [String]::Empty
        }

        if ($idx -le $nUnicodeRange) {
            $unicodeString = [System.Text.Encoding]::Unicode.GetString($FileBytes, $idx, $nUnicodeStringLength)
        }

        if ([System.String]::Compare($Value, $asciiString, $true) -eq 0) {
            $oftObject.Encoding = "ASCII"
            $oftObject.Value = $asciiString
        } elseif ([System.String]::Compare($Value, $unicodeString, $true) -eq 0) {
            $oftObject.Encoding = "Unicode"
            $oftObject.Value = $unicodeString
        } else {
            continue
        }

        if ($idx -lt $nPeHeaderSize) {
            $oftObject.VirtualOffset = $idx
            $oftObject.Section = "(PE Header)"
        } else {
            foreach ($header in $headers) {
                if (($idx -ge $header.PointerToRawData) -and
                    ($idx -lt ($header.PointerToRawData + $header.SizeOfRawData))) {
                    $oftObject.VirtualOffset = $idx - $header.PointerToRawData + $header.VirtualAddress
                    $oftObject.Section = $header.Name
                    break
                }
            }
        }

        $returnObject += $oftObject
    }

    $returnObject
}

Export-ModuleMember -Function Get-PeFileInformation
Export-ModuleMember -Function Find-DwordFromExecutable
Export-ModuleMember -Function Find-QwordFromExecutable
Export-ModuleMember -Function Find-StringFromExecutable
