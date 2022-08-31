using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace CommandLineSpoofing.Library
{
    internal class PeFile : IDisposable
    {
        // Windows Definition
        // Enum
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        [Flags]
        public enum SectionFlags : uint
        {
            TYPE_NO_PAD = 0x00000008,
            CNT_CODE = 0x00000020,
            CNT_INITIALIZED_DATA = 0x00000040,
            CNT_UNINITIALIZED_DATA = 0x00000080,
            LNK_INFO = 0x00000200,
            LNK_REMOVE = 0x00000800,
            LNK_COMDAT = 0x00001000,
            NO_DEFER_SPEC_EXC = 0x00004000,
            GPREL = 0x00008000,
            MEM_FARDATA = 0x00008000,
            MEM_PURGEABLE = 0x00020000,
            MEM_16BIT = 0x00020000,
            MEM_LOCKED = 0x00040000,
            MEM_PRELOAD = 0x00080000,
            ALIGN_1BYTES = 0x00100000,
            ALIGN_2BYTES = 0x00200000,
            ALIGN_4BYTES = 0x00300000,
            ALIGN_8BYTES = 0x00400000,
            ALIGN_16BYTES = 0x00500000,
            ALIGN_32BYTES = 0x00600000,
            ALIGN_64BYTES = 0x00700000,
            ALIGN_128BYTES = 0x00800000,
            ALIGN_256BYTES = 0x00900000,
            ALIGN_512BYTES = 0x00A00000,
            ALIGN_1024BYTES = 0x00B00000,
            ALIGN_2048BYTES = 0x00C00000,
            ALIGN_4096BYTES = 0x00D00000,
            ALIGN_8192BYTES = 0x00E00000,
            ALIGN_MASK = 0x00F00000,
            LNK_NRELOC_OVFL = 0x01000000,
            MEM_DISCARDABLE = 0x02000000,
            MEM_NOT_CACHED = 0x04000000,
            MEM_NOT_PAGED = 0x08000000,
            MEM_SHARED = 0x10000000,
            MEM_EXECUTE = 0x20000000,
            MEM_READ = 0x40000000,
            MEM_WRITE = 0x80000000
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        // Struct
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;    // Magic number
            public ushort e_cblp;     // Bytes on last page of file
            public ushort e_cp;       // Pages in file
            public ushort e_crlc;     // Relocations
            public ushort e_cparhdr;  // Size of header in paragraphs
            public ushort e_minalloc; // Minimum extra paragraphs needed
            public ushort e_maxalloc; // Maximum extra paragraphs needed
            public ushort e_ss;       // Initial (relative) SS value
            public ushort e_sp;       // Initial SP value
            public ushort e_csum;     // Checksum
            public ushort e_ip;       // Initial IP value
            public ushort e_cs;       // Initial (relative) CS value
            public ushort e_lfarlc;   // File address of relocation table
            public ushort e_ovno;     // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;   // Reserved words
            public ushort e_oemid;    // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;  // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;   // Reserved words
            public int e_lfanew;      // File address of new exe header

            private string GetMagic
            {
                get { return new string(e_magic); }
            }

            public bool IsValid
            {
                get { return GetMagic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_NT_HEADERS32
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_NT_HEADERS64
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public SectionFlags Characteristics;
        }

        // Global Variables
        private readonly IntPtr Buffer;
        private readonly int SizeOfBuffer;
        private readonly string Arch;
        private readonly IMAGE_DOS_HEADER DosHeader;
        private readonly IMAGE_NT_HEADERS32 NtHeader32;
        private readonly IMAGE_NT_HEADERS64 NtHeader64;
        private readonly List<IMAGE_SECTION_HEADER> SectionHeaders;

        // Constructor
        public PeFile(string _filePath)
        {
            this.Buffer = LoadFileData(_filePath, out this.SizeOfBuffer);

            if (this.Buffer == IntPtr.Zero)
                throw new InvalidDataException(string.Format(
                    "Failed to load \"{0}\".",
                    _filePath));

            if (!GetDosHeader(out this.DosHeader))
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format(
                    "Failed to get DOS Header from \"{0}\".",
                    _filePath));
            }

            IntPtr lpNtHeader = new IntPtr(this.Buffer.ToInt64() + this.DosHeader.e_lfanew);
            ushort arch = (ushort)Marshal.ReadInt16(
                lpNtHeader,
                Marshal.SizeOf(typeof(int)));

            if (arch == 0x8664)
            {
                this.Arch = "x64";
                this.NtHeader32 = new IMAGE_NT_HEADERS32();
                this.NtHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                    lpNtHeader,
                    typeof(IMAGE_NT_HEADERS64));
            }
            else if (arch == 0x014C)
            {
                this.Arch = "x86";
                this.NtHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                    lpNtHeader,
                    typeof(IMAGE_NT_HEADERS32));
                this.NtHeader64 = new IMAGE_NT_HEADERS64();
            }
            else
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format(
                    "Failed to get NT Header from \"{0}\" or unsupported architecture.",
                    _filePath));
            }

            if (!GetSectionHeaders(out this.SectionHeaders))
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format(
                    "Failed to get Section Headers from \"{0}\".",
                    _filePath));
            }

            var lastSection = this.SectionHeaders[this.SectionHeaders.Count - 1];
            var boundary = lastSection.PointerToRawData + lastSection.SizeOfRawData;

            if (this.SizeOfBuffer < boundary)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format(
                    "Image size is invalid. \"{0}\" may be corrupted.",
                    _filePath));
            }
        }


        public PeFile(byte[] data)
        {
            this.Buffer = LoadFileData(data, out this.SizeOfBuffer);

            if (this.Buffer == IntPtr.Zero)
                throw new InvalidDataException("Failed to load file data.");

            if (!GetDosHeader(out this.DosHeader))
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Failed to get DOS Header from loaded data.");
            }

            IntPtr lpNtHeader = new IntPtr(this.Buffer.ToInt64() + this.DosHeader.e_lfanew);
            ushort arch = (ushort)Marshal.ReadInt16(
                lpNtHeader,
                Marshal.SizeOf(typeof(int)));

            if (arch == 0x8664)
            {
                this.Arch = "x64";
                this.NtHeader32 = new IMAGE_NT_HEADERS32();
                this.NtHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                    lpNtHeader,
                    typeof(IMAGE_NT_HEADERS64));
            }
            else if (arch == 0x014C)
            {
                this.Arch = "x86";
                this.NtHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                    lpNtHeader,
                    typeof(IMAGE_NT_HEADERS32));
                this.NtHeader64 = new IMAGE_NT_HEADERS64();
            }
            else
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Failed to get NT Header from loaded data or unsupported architecture.");
            }

            if (!GetSectionHeaders(out this.SectionHeaders))
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Failed to get Section Headers from loaded data.");
            }

            var lastSection = this.SectionHeaders[this.SectionHeaders.Count - 1];
            var boundary = lastSection.PointerToRawData + lastSection.SizeOfRawData;

            if (this.SizeOfBuffer < boundary)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Image size is invalid. Loaded data may be corrupted.");
            }
        }


        // Destructor
        public void Dispose()
        {
            if (this.Buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(this.Buffer);
        }


        // Functions
        public uint ConvertRvaToOffset(uint rva)
        {
            foreach (var section in this.SectionHeaders)
            {
                if (rva < (section.VirtualAddress + section.SizeOfRawData))
                {
                    return (rva - section.VirtualAddress + section.PointerToRawData);
                }
            }

            return 0u;
        }


        public uint GetAddressOfEntryPoint()
        {
            if (this.Arch == "x86")
                return this.NtHeader32.OptionalHeader.AddressOfEntryPoint;
            else
                return this.NtHeader64.OptionalHeader.AddressOfEntryPoint;
        }


        public string GetArchitecture()
        {
            return this.Arch;
        }


        public uint GetBaseOfCode()
        {
            if (this.Arch == "x86")
                return this.NtHeader32.OptionalHeader.BaseOfCode;
            else
                return this.NtHeader64.OptionalHeader.BaseOfCode;
        }


        private bool GetDosHeader(out IMAGE_DOS_HEADER _dosHeader)
        {
            try
            {
                _dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                    this.Buffer,
                    typeof(IMAGE_DOS_HEADER));
            }
            catch
            {
                _dosHeader = new IMAGE_DOS_HEADER();

                return false;
            }

            return _dosHeader.IsValid;
        }


        public Dictionary<string, IntPtr> GetExports()
        {
            var results = new Dictionary<string, IntPtr>();
            uint tableRva;

            if (this.Arch == "x64")
            {
                tableRva = this.NtHeader64.OptionalHeader.ExportTable.VirtualAddress;
            }
            else if (this.Arch == "x86")
            {
                tableRva = this.NtHeader32.OptionalHeader.ExportTable.VirtualAddress;
            }
            else
            {
                return results;
            }

            var exportDir = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                new IntPtr(Buffer.ToInt64() + this.ConvertRvaToOffset(tableRva)),
                typeof(IMAGE_EXPORT_DIRECTORY));
            var offsetNameTable = this.ConvertRvaToOffset(exportDir.AddressOfNames);
            var offsetOrdinalTable = this.ConvertRvaToOffset(exportDir.AddressOfNameOrdinals);
            var offsetFunctionTable = this.ConvertRvaToOffset(exportDir.AddressOfFunctions);
            uint offsetName;
            string functionName;
            short functionOrdinal;
            uint functionRva;

            for (var idx = 0; idx < exportDir.NumberOfNames; idx++)
            {
                offsetName = this.ConvertRvaToOffset(
                    (uint)ReadInt32(new IntPtr(
                        offsetNameTable +
                        Marshal.SizeOf(typeof(int)) * idx)));
                functionName = this.ReadAnsiString(new IntPtr(offsetName));
                functionOrdinal = this.ReadInt16(
                    new IntPtr(offsetOrdinalTable +
                    Marshal.SizeOf(typeof(short)) * idx));
                functionRva = (uint)this.ReadInt32(new IntPtr(
                    offsetFunctionTable +
                    Marshal.SizeOf(typeof(int)) * functionOrdinal));

                results.Add(
                    functionName,
                    new IntPtr((long)this.ConvertRvaToOffset(functionRva)));
            }

            return results;
        }


        public string GetExportImageName()
        {
            uint tableRva;

            if (this.Arch == "x64")
            {
                tableRva = this.NtHeader64.OptionalHeader.ExportTable.VirtualAddress;
            }
            else if (this.Arch == "x86")
            {
                tableRva = this.NtHeader32.OptionalHeader.ExportTable.VirtualAddress;
            }
            else
            {
                return null;
            }

            var exportDir = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                new IntPtr(this.Buffer.ToInt64() + this.ConvertRvaToOffset(tableRva)),
                typeof(IMAGE_EXPORT_DIRECTORY));

            var pointer = new IntPtr(this.ConvertRvaToOffset(exportDir.Name));
            string imageName;

            try
            {
                imageName = this.ReadAnsiString(pointer);

                return imageName;
            }
            catch
            {
                return null;
            }
        }


        public IntPtr GetExportTablePointer()
        {
            if (this.Arch == "x64")
            {
                return new IntPtr(
                    (long)this.NtHeader64.OptionalHeader.ExportTable.VirtualAddress);
            }
            else if (this.Arch == "x86")
            {
                return new IntPtr(
                    (long)this.NtHeader32.OptionalHeader.ExportTable.VirtualAddress);
            }
            else
            {
                return IntPtr.Zero;
            }
        }


        public IntPtr GetImageBase()
        {
            if (this.Arch == "x64")
            {
                return new IntPtr((long)this.NtHeader64.OptionalHeader.ImageBase);
            }
            else if (this.Arch == "x86")
            {
                return new IntPtr((long)this.NtHeader32.OptionalHeader.ImageBase);
            }
            else
            {
                return IntPtr.Zero;
            }
        }


        public IntPtr GetDataPointer()
        {
            return this.Buffer;
        }


        public int GetDataSize()
        {
            return this.SizeOfBuffer;
        }


        public IntPtr GetSectionBaseAddress(string sectionName)
        {
            foreach (var header in this.SectionHeaders)
            {
                if (sectionName == header.Name)
                    return new IntPtr(header.PointerToRawData);
            }

            return IntPtr.Zero;
        }


        public SectionFlags GetSectionCharacteristics(string sectionName)
        {
            foreach (var header in this.SectionHeaders)
            {
                if (sectionName == header.Name)
                    return header.Characteristics;
            }

            return 0u;
        }


        private bool GetSectionHeaders(out List<IMAGE_SECTION_HEADER> _sectionHeaders)
        {
            _sectionHeaders = new List<IMAGE_SECTION_HEADER>();
            var pFileHeader = new IntPtr(
                this.Buffer.ToInt64() +
                this.DosHeader.e_lfanew +
                Marshal.SizeOf(typeof(int)));

            try
            {
                IMAGE_FILE_HEADER fileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(
                    pFileHeader,
                    typeof(IMAGE_FILE_HEADER));
                ushort nSectionCount = fileHeader.NumberOfSections;
                IntPtr pSectionHeaders = new IntPtr(
                    this.Buffer.ToInt64() +
                    this.DosHeader.e_lfanew +
                    0x18 +
                    fileHeader.SizeOfOptionalHeader);

                for (var idx = 0; idx < nSectionCount; idx++)
                {
                    _sectionHeaders.Add((IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        new IntPtr(pSectionHeaders.ToInt64() + idx * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))),
                        typeof(IMAGE_SECTION_HEADER)));
                }

                return true;
            }
            catch
            {
                return false;
            }
        }


        public string[] GetSectionNames()
        {
            var sectionNames = new List<string>();

            foreach (var header in this.SectionHeaders)
                sectionNames.Add(header.Name);

            return sectionNames.ToArray();
        }


        public uint GetSectionPointerToRawData(string sectionName)
        {
            foreach (var header in this.SectionHeaders)
            {
                if (sectionName == header.Name)
                    return header.PointerToRawData;
            }

            return 0u;
        }


        public uint GetSectionSizeOfRawData(string sectionName)
        {
            foreach (var header in this.SectionHeaders)
            {
                if (sectionName == header.Name)
                    return header.SizeOfRawData;
            }

            return 0u;
        }


        public uint GetSectionVirtualAddress(string sectionName)
        {
            foreach (var header in this.SectionHeaders)
            {
                if (sectionName == header.Name)
                    return header.VirtualAddress;
            }

            return 0u;
        }


        public uint GetSectionVirtualSize(string sectionName)
        {
            foreach (var header in this.SectionHeaders)
            {
                if (sectionName == header.Name)
                    return header.VirtualSize;
            }

            return 0u;
        }


        public uint GetSizeOfImage()
        {
            if (this.Arch == "x64")
            {
                return this.NtHeader64.OptionalHeader.SizeOfImage;
            }
            else if (this.Arch == "x86")
            {
                return this.NtHeader32.OptionalHeader.SizeOfImage;
            }
            else
            {
                throw new InvalidDataException("Unsupported architecture is detected.");
            }
        }


        public uint GetSizeOfHeaders()
        {
            if (this.Arch == "x64")
            {
                return this.NtHeader64.OptionalHeader.SizeOfHeaders;
            }
            else if (this.Arch == "x86")
            {
                return this.NtHeader32.OptionalHeader.SizeOfHeaders;
            }
            else
            {
                throw new InvalidDataException("Unsupported architecture is detected.");
            }
        }


        public string[] ListSectionHeaderNames()
        {
            var results = new List<string>();

            foreach (var header in this.SectionHeaders)
            {
                results.Add(header.Name);
            }

            return results.ToArray();
        }


        private IntPtr LoadFileData(string _filePath, out int length)
        {
            var fullFilePath = Path.GetFullPath(_filePath);
            IntPtr buffer;
            length = 0;

            if (!File.Exists(fullFilePath))
                return IntPtr.Zero;

            try
            {
                byte[] data = File.ReadAllBytes(fullFilePath);
                buffer = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, buffer, data.Length);
                length = data.Length;

                return buffer;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }


        private IntPtr LoadFileData(byte[] data, out int length)
        {
            IntPtr buffer;
            length = data.Length;

            try
            {
                buffer = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, buffer, data.Length);
                length = data.Length;

                return buffer;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }


        public string ReadAnsiString(IntPtr address)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64());

            return Marshal.PtrToStringAnsi(pointer);
        }


        public string ReadAnsiString(IntPtr address, int offset)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);

            return Marshal.PtrToStringAnsi(pointer);
        }


        public byte ReadByte(IntPtr address)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64());

            return Marshal.ReadByte(pointer);
        }


        public byte ReadByte(IntPtr address, int offset)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);

            return Marshal.ReadByte(pointer);
        }


        public short ReadInt16(IntPtr address)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64());

            return Marshal.ReadInt16(pointer);
        }


        public short ReadInt16(IntPtr address, int offset)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);

            return Marshal.ReadInt16(pointer);
        }


        public int ReadInt32(IntPtr address)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64());

            return Marshal.ReadInt32(pointer);
        }


        public int ReadInt32(IntPtr address, int offset)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);

            return Marshal.ReadInt32(pointer);
        }


        public long ReadInt64(IntPtr address)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64());

            return Marshal.ReadInt64(pointer);
        }


        public long ReadInt64(IntPtr address, int offset)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);

            return Marshal.ReadInt64(pointer);
        }


        public IntPtr ReadIntPtr(IntPtr address)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64());

            if (this.Arch == "x64")
            {
                return new IntPtr(Marshal.ReadInt64(pointer));
            }
            else if (this.Arch == "x86")
            {
                return new IntPtr(Marshal.ReadInt32(pointer));
            }
            else
            {
                return IntPtr.Zero;
            }
        }


        public IntPtr ReadIntPtr(IntPtr address, int offset)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);

            if (this.Arch == "x64")
            {
                return new IntPtr(Marshal.ReadInt64(pointer));
            }
            else if (this.Arch == "x86")
            {
                return new IntPtr(Marshal.ReadInt32(pointer));
            }
            else
            {
                return IntPtr.Zero;
            }
        }


        public string ReadUnicodeString(IntPtr address)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64());

            return Marshal.PtrToStringUni(pointer);
        }


        public string ReadUnicodeString(IntPtr address, int offset)
        {
            var pointer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);

            return Marshal.PtrToStringUni(pointer);
        }


        public IntPtr[] SearchBytes(
            IntPtr basePointer,
            uint range,
            byte[] searchBytes)
        {
            var results = new List<IntPtr>();
            IntPtr pointer;
            bool found;

            for (var count = 0; count < (range - searchBytes.Length); count++)
            {
                found = false;
                pointer = new IntPtr(basePointer.ToInt64() + count);

                for (var position = 0; position < searchBytes.Length; position++)
                {
                    found = (this.ReadByte(pointer, position) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found)
                    results.Add(pointer);
            }

            return results.ToArray();
        }


        public IntPtr[] SearchBytes(
            IntPtr basePointer,
            uint offset,
            uint range,
            byte[] searchBytes)
        {
            var results = new List<IntPtr>();
            IntPtr pointer;
            bool found;

            for (var count = 0; count < (range - searchBytes.Length); count++)
            {
                found = false;
                pointer = new IntPtr(basePointer.ToInt64() + offset + count);

                for (var position = 0; position < searchBytes.Length; position++)
                {
                    found = (this.ReadByte(pointer, position) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found)
                    results.Add(pointer);
            }

            return results.ToArray();
        }


        public IntPtr SearchBytesFirst(
            IntPtr basePointer,
            uint range,
            byte[] searchBytes)
        {
            IntPtr pointer;
            bool found;

            for (var count = 0; count < (range - searchBytes.Length); count++)
            {
                found = false;
                pointer = new IntPtr(basePointer.ToInt64() + count);

                for (var position = 0; position < searchBytes.Length; position++)
                {
                    found = (this.ReadByte(pointer, position) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found)
                    return pointer;
            }

            return IntPtr.Zero;
        }


        public IntPtr SearchBytesFirst(
            IntPtr basePointer,
            uint offset,
            uint range,
            byte[] searchBytes)
        {
            IntPtr pointer;
            bool found;

            for (var count = 0; count < (range - searchBytes.Length); count++)
            {
                found = false;
                pointer = new IntPtr(basePointer.ToInt64() + offset + count);

                for (var position = 0; position < searchBytes.Length; position++)
                {
                    found = (this.ReadByte(pointer, position) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found)
                    return pointer;
            }

            return IntPtr.Zero;
        }
    }
}
