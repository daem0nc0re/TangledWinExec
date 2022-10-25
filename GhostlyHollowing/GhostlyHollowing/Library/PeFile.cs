using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace GhostlyHollowing.Library
{
    internal class PeFile : IDisposable
    {
        /*
         * Windows Definition : Enums
         */
        [Flags]
        public enum COMIMAGE_FLAGS : uint
        {
            FLAG_NONE = 0x00000000,
            FLAG_ILONLY = 0x00000001,
            FLAG_32BITREQUIRED = 0x00000002,
            FLAG_IL_LIBRARY = 0x00000004,
            FLAG_STRONGNAMESIGNED = 0x00000008,
            FLAG_NATIVE_ENTRYPOINT = 0x00000010,
            FLAG_TRACKDEBUGDATA = 0x00010000,
            FLAG_32BITPREFERRED = 0x00020000
        }

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

        public enum IMAGE_FILE_MACHINE : ushort
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

        /*
         * Windows Definition : Structs
         */
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_COR20_HEADER
        {
            public uint cb;
            public ushort MajorRuntimeVersion;
            public ushort MinorRuntimeVersion;
            public IMAGE_DATA_DIRECTORY MetaData;
            public COMIMAGE_FLAGS Flags;
            public uint EntryPointToken;
            public IMAGE_DATA_DIRECTORY Resources;
            public IMAGE_DATA_DIRECTORY StrongNameSignature;
            public IMAGE_DATA_DIRECTORY CodeManagerTable;
            public IMAGE_DATA_DIRECTORY VTableFixups;
            public IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
            public IMAGE_DATA_DIRECTORY ManagedNativeHeader;
        }

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
            public IMAGE_FILE_MACHINE Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
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

        /*
         * Global Variables
         */
        private IntPtr Buffer;
        public readonly bool Is64Bit;
        public readonly bool IsDotNet;
        public readonly IMAGE_FILE_MACHINE Architecture;
        public readonly uint SizeOfBuffer;
        private readonly IMAGE_DOS_HEADER DosHeader;
        private readonly IMAGE_NT_HEADERS32 NtHeader32;
        private readonly IMAGE_NT_HEADERS64 NtHeader64;
        private readonly List<IMAGE_SECTION_HEADER> SectionHeaders;
        private readonly IMAGE_COR20_HEADER DotNetHeader;

        /*
         * Constructor
         */
        public PeFile(string _filePath)
        {
            IntPtr pNtHeader;
            IntPtr pDotNetHeader;
            int nBitness;
            uint nSizeValidation;
            int nOffsetOfOptionalHeader;
            int nOffsetOfTextSection;
            IMAGE_SECTION_HEADER lastSectionHeader;
            int nSizeOfSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            int nSizeOfDotNetHeader = Marshal.SizeOf(typeof(IMAGE_COR20_HEADER));

            this.Buffer = this.LoadFileData(_filePath, out this.SizeOfBuffer);

            if (this.Buffer == IntPtr.Zero)
                throw new InvalidDataException(string.Format("Failed to load \"{0}\".", _filePath));

            nSizeValidation = (uint)Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));

            if (this.SizeOfBuffer < nSizeValidation)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format("File size of \"{0}\" is too small.", _filePath));
            }

            if (!this.GetDosHeader(out this.DosHeader))
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format("Failed to get DOS Header from \"{0}\".", _filePath));
            }

            if (Environment.Is64BitProcess)
                pNtHeader = new IntPtr(this.Buffer.ToInt64() + this.DosHeader.e_lfanew);
            else
                pNtHeader = new IntPtr(this.Buffer.ToInt32() + this.DosHeader.e_lfanew);

            this.Architecture = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pNtHeader, Marshal.SizeOf(typeof(int)));
            nBitness = this.GetArchitectureBitness(Architecture);

            if (nBitness == 64)
            {
                this.Is64Bit = true;
                nOffsetOfOptionalHeader = Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS64), "OptionalHeader").ToInt32();
                nSizeValidation = (uint)(this.DosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));

                if (this.SizeOfBuffer < nSizeValidation)
                {
                    Marshal.FreeHGlobal(this.Buffer);
                    this.Buffer = IntPtr.Zero;

                    throw new InvalidDataException(string.Format("File size of \"{0}\" is too small.", _filePath));
                }

                this.NtHeader32 = new IMAGE_NT_HEADERS32();
                this.NtHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(pNtHeader, typeof(IMAGE_NT_HEADERS64));

                nSizeValidation = (uint)(this.DosHeader.e_lfanew + nOffsetOfOptionalHeader + this.NtHeader64.FileHeader.SizeOfOptionalHeader);
                nSizeValidation += (uint)(this.NtHeader64.FileHeader.NumberOfSections * nSizeOfSectionHeader);
            }
            else if (nBitness == 32)
            {
                this.Is64Bit = false;
                nOffsetOfOptionalHeader = Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS32), "OptionalHeader").ToInt32();
                nSizeValidation = (uint)(this.DosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32)));

                if (this.SizeOfBuffer < nSizeValidation)
                    throw new InvalidDataException(string.Format("File size of \"{0}\" is too small.", _filePath));

                this.NtHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(pNtHeader, typeof(IMAGE_NT_HEADERS32));
                this.NtHeader64 = new IMAGE_NT_HEADERS64();

                nSizeValidation = (uint)(this.DosHeader.e_lfanew + nOffsetOfOptionalHeader + this.NtHeader32.FileHeader.SizeOfOptionalHeader);
                nSizeValidation += (uint)(this.NtHeader32.FileHeader.NumberOfSections * nSizeOfSectionHeader);
            }
            else
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format(
                    "Failed to get NT Header from \"{0}\" or unsupported architecture.",
                    _filePath));
            }

            if (this.SizeOfBuffer < nSizeValidation)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format("File size of \"{0}\" is too small.", _filePath));
            }

            if (!this.GetSectionHeaders(out this.SectionHeaders))
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format(
                    "Failed to get Section Headers from \"{0}\".",
                    _filePath));
            }

            lastSectionHeader = this.SectionHeaders[this.SectionHeaders.Count - 1];
            nSizeValidation = lastSectionHeader.PointerToRawData + lastSectionHeader.SizeOfRawData;

            if (this.SizeOfBuffer < nSizeValidation)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format("File size of \"{0}\" is too small.", _filePath));
            }

            nOffsetOfTextSection = (int)this.GetSectionPointerToRawData(".text");

            if (nOffsetOfTextSection == 0)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(string.Format(".text section is not found from \"{0}\".", _filePath));
            }

            if (Environment.Is64BitProcess)
                pDotNetHeader = new IntPtr(this.Buffer.ToInt64() + nOffsetOfTextSection + 8);
            else
                pDotNetHeader = new IntPtr(this.Buffer.ToInt32() + nOffsetOfTextSection + 8);

            this.IsDotNet = (Marshal.ReadInt32(pDotNetHeader) == nSizeOfDotNetHeader);

            if (this.IsDotNet)
            {
                this.DotNetHeader = (IMAGE_COR20_HEADER)Marshal.PtrToStructure(
                    pDotNetHeader,
                    typeof(IMAGE_COR20_HEADER));

                this.Is64Bit = (this.DotNetHeader.Flags == COMIMAGE_FLAGS.FLAG_ILONLY) && Environment.Is64BitOperatingSystem;
            }
            else
            {
                this.DotNetHeader = new IMAGE_COR20_HEADER();
            }
        }


        public PeFile(byte[] imageDataBytes)
        {
            IntPtr pNtHeader;
            IntPtr pDotNetHeader;
            int nBitness;
            uint nSizeValidation;
            int nOffsetOfOptionalHeader;
            int nOffsetOfTextSection;
            IMAGE_SECTION_HEADER lastSectionHeader;
            int nSizeOfSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            int nSizeOfDotNetHeader = Marshal.SizeOf(typeof(IMAGE_COR20_HEADER));

            this.Buffer = this.LoadFileData(imageDataBytes, out this.SizeOfBuffer);

            if (this.Buffer == IntPtr.Zero)
                throw new InvalidDataException("Failed to load image data.");

            nSizeValidation = (uint)Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));

            if (this.SizeOfBuffer < nSizeValidation)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Loaded data size is too small.");
            }

            if (!this.GetDosHeader(out this.DosHeader))
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Failed to get DOS Header from loaded image data.");
            }

            if (Environment.Is64BitProcess)
                pNtHeader = new IntPtr(this.Buffer.ToInt64() + this.DosHeader.e_lfanew);
            else
                pNtHeader = new IntPtr(this.Buffer.ToInt32() + this.DosHeader.e_lfanew);

            this.Architecture = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pNtHeader, Marshal.SizeOf(typeof(int)));
            nBitness = this.GetArchitectureBitness(Architecture);

            if (nBitness == 64)
            {
                this.Is64Bit = true;
                nOffsetOfOptionalHeader = Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS64), "OptionalHeader").ToInt32();
                nSizeValidation = (uint)(this.DosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));

                if (this.SizeOfBuffer < nSizeValidation)
                {
                    Marshal.FreeHGlobal(this.Buffer);
                    this.Buffer = IntPtr.Zero;

                    throw new InvalidDataException(string.Format("Loaded data size is too small."));
                }

                this.NtHeader32 = new IMAGE_NT_HEADERS32();
                this.NtHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(pNtHeader, typeof(IMAGE_NT_HEADERS64));

                nSizeValidation = (uint)(this.DosHeader.e_lfanew + nOffsetOfOptionalHeader + this.NtHeader64.FileHeader.SizeOfOptionalHeader);
                nSizeValidation += (uint)(this.NtHeader64.FileHeader.NumberOfSections * nSizeOfSectionHeader);
            }
            else if (nBitness == 32)
            {
                this.Is64Bit = false;
                nOffsetOfOptionalHeader = Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS32), "OptionalHeader").ToInt32();
                nSizeValidation = (uint)(this.DosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32)));

                if (this.SizeOfBuffer < nSizeValidation)
                    throw new InvalidDataException("Loaded data size is too small.");

                this.NtHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(pNtHeader, typeof(IMAGE_NT_HEADERS32));
                this.NtHeader64 = new IMAGE_NT_HEADERS64();

                nSizeValidation = (uint)(this.DosHeader.e_lfanew + nOffsetOfOptionalHeader + this.NtHeader32.FileHeader.SizeOfOptionalHeader);
                nSizeValidation += (uint)(this.NtHeader32.FileHeader.NumberOfSections * nSizeOfSectionHeader);
            }
            else
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Failed to get NT Header from loaded image data or unsupported architecture.");
            }

            if (this.SizeOfBuffer < nSizeValidation)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Loaded data size is too small.");
            }

            if (!this.GetSectionHeaders(out this.SectionHeaders))
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Failed to get Section Headers from loaded image data.");
            }

            lastSectionHeader = this.SectionHeaders[this.SectionHeaders.Count - 1];
            nSizeValidation = lastSectionHeader.PointerToRawData + lastSectionHeader.SizeOfRawData;

            if (this.SizeOfBuffer < nSizeValidation)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException("Loaded data size is too small.");
            }

            nOffsetOfTextSection = (int)this.GetSectionPointerToRawData(".text");

            if (nOffsetOfTextSection == 0)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;

                throw new InvalidDataException(".text section is not found from the loaded data.");
            }

            if (Environment.Is64BitProcess)
                pDotNetHeader = new IntPtr(this.Buffer.ToInt64() + nOffsetOfTextSection + 8);
            else
                pDotNetHeader = new IntPtr(this.Buffer.ToInt32() + nOffsetOfTextSection + 8);

            this.IsDotNet = (Marshal.ReadInt32(pDotNetHeader) == nSizeOfDotNetHeader);

            if (this.IsDotNet)
            {
                this.DotNetHeader = (IMAGE_COR20_HEADER)Marshal.PtrToStructure(
                    pDotNetHeader,
                    typeof(IMAGE_COR20_HEADER));

                this.Is64Bit = (this.DotNetHeader.Flags == COMIMAGE_FLAGS.FLAG_ILONLY) && Environment.Is64BitOperatingSystem;
            }
            else
            {
                this.DotNetHeader = new IMAGE_COR20_HEADER();
            }
        }


        /*
         * Destructor
         */
        public void Dispose()
        {
            if (this.Buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;
            }
        }


        /*
         * Class Methods
         */
        public uint ConvertRvaToOffset(uint rva)
        {
            foreach (var section in this.SectionHeaders)
            {
                if (rva < (section.VirtualAddress + section.SizeOfRawData))
                    return (rva - section.VirtualAddress + section.PointerToRawData);
            }

            return 0u;
        }


        public uint GetAddressOfEntryPoint()
        {
            if (this.Is64Bit)
                return this.NtHeader64.OptionalHeader.AddressOfEntryPoint;
            else
                return this.NtHeader32.OptionalHeader.AddressOfEntryPoint;
        }


        private int GetArchitectureBitness(IMAGE_FILE_MACHINE arch)
        {
            if (arch == IMAGE_FILE_MACHINE.I386)
                return 32;
            else if (arch == IMAGE_FILE_MACHINE.ARM)
                return 32;
            else if (arch == IMAGE_FILE_MACHINE.ARM2)
                return 32;
            else if (arch == IMAGE_FILE_MACHINE.IA64)
                return 64;
            else if (arch == IMAGE_FILE_MACHINE.AMD64)
                return 64;
            else if (arch == IMAGE_FILE_MACHINE.ARM64)
                return 64;
            else
                return 0;
        }


        public uint GetBaseOfCode()
        {
            if (this.Is64Bit)
                return this.NtHeader64.OptionalHeader.BaseOfCode;
            else
                return this.NtHeader32.OptionalHeader.BaseOfCode;
        }


        public IntPtr GetBufferPointer()
        {
            return this.Buffer;
        }


        private bool GetDosHeader(out IMAGE_DOS_HEADER _dosHeader)
        {
            try
            {
                _dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                    this.Buffer,
                    typeof(IMAGE_DOS_HEADER));

                return _dosHeader.IsValid;
            }
            catch
            {
                _dosHeader = new IMAGE_DOS_HEADER();

                return false;
            }
        }


        public COMIMAGE_FLAGS GetComImageFlags()
        {
            if (this.IsDotNet)
                return this.DotNetHeader.Flags;
            else
                return COMIMAGE_FLAGS.FLAG_NONE;
        }


        public Dictionary<string, IntPtr> GetExports()
        {
            uint nTableOffset;
            uint nNameRva;
            uint nNameOffset;
            uint nFunctionRva;
            uint nNameTableOffset;
            uint nOrdinalTableOffset;
            uint nFunctionTableOffset;
            string functionName;
            short functionOrdinal;
            IntPtr pExportDirectory;
            IntPtr pFunctionCode;
            IMAGE_EXPORT_DIRECTORY exportDirectory;
            var results = new Dictionary<string, IntPtr>();

            if (this.Is64Bit)
                nTableOffset = this.ConvertRvaToOffset(this.NtHeader64.OptionalHeader.ExportTable.VirtualAddress);
            else
                nTableOffset = this.ConvertRvaToOffset(this.NtHeader32.OptionalHeader.ExportTable.VirtualAddress);

            if (Environment.Is64BitProcess)
                pExportDirectory = new IntPtr(this.Buffer.ToInt64() + nTableOffset);
            else
                pExportDirectory = new IntPtr(this.Buffer.ToInt32() + nTableOffset);

            exportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                pExportDirectory,
                typeof(IMAGE_EXPORT_DIRECTORY));
            nNameTableOffset = this.ConvertRvaToOffset(exportDirectory.AddressOfNames);
            nOrdinalTableOffset = this.ConvertRvaToOffset(exportDirectory.AddressOfNameOrdinals);
            nFunctionTableOffset = this.ConvertRvaToOffset(exportDirectory.AddressOfFunctions);

            for (var idx = 0; idx < exportDirectory.NumberOfNames; idx++)
            {
                if (Environment.Is64BitProcess)
                {
                    nNameRva = (uint)this.ReadInt32(new IntPtr((long)nNameTableOffset + (Marshal.SizeOf(typeof(int)) * idx)));
                    nNameOffset = this.ConvertRvaToOffset(nNameRva);
                    functionName = this.ReadAnsiString(new IntPtr((long)nNameOffset));
                    functionOrdinal = this.ReadInt16(new IntPtr((long)nOrdinalTableOffset + Marshal.SizeOf(typeof(short)) * idx));
                    nFunctionRva = (uint)this.ReadInt32(new IntPtr((long)nFunctionTableOffset + Marshal.SizeOf(typeof(int)) * functionOrdinal));
                    pFunctionCode = new IntPtr((long)this.ConvertRvaToOffset(nFunctionRva));
                }
                else
                {
                    nNameRva = (uint)this.ReadInt32(new IntPtr((int)nNameTableOffset + (Marshal.SizeOf(typeof(int)) * idx)));
                    nNameOffset = this.ConvertRvaToOffset(nNameRva);
                    functionName = this.ReadAnsiString(new IntPtr((int)nNameOffset));
                    functionOrdinal = this.ReadInt16(new IntPtr((int)nOrdinalTableOffset + Marshal.SizeOf(typeof(short)) * idx));
                    nFunctionRva = (uint)this.ReadInt32(new IntPtr((int)nFunctionTableOffset + Marshal.SizeOf(typeof(int)) * functionOrdinal));
                    pFunctionCode = new IntPtr((int)this.ConvertRvaToOffset(nFunctionRva));
                }

                results.Add(functionName, pFunctionCode);
            }

            return results;
        }


        public string GetExportImageName()
        {
            uint nTableOffset;
            IntPtr pExportDirectory;
            IntPtr pNameBuffer;
            string imageName;
            IMAGE_EXPORT_DIRECTORY exportDirectory;

            if (this.Is64Bit)
                nTableOffset = this.ConvertRvaToOffset(this.NtHeader64.OptionalHeader.ExportTable.VirtualAddress);
            else
                nTableOffset = this.ConvertRvaToOffset(this.NtHeader32.OptionalHeader.ExportTable.VirtualAddress);

            if (Environment.Is64BitProcess)
            {
                pExportDirectory = new IntPtr(this.Buffer.ToInt64() + nTableOffset);
                exportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                    pExportDirectory,
                    typeof(IMAGE_EXPORT_DIRECTORY));
                pNameBuffer = new IntPtr((long)this.ConvertRvaToOffset(exportDirectory.Name));
            }
            else
            {
                pExportDirectory = new IntPtr(this.Buffer.ToInt32() + (int)nTableOffset);
                exportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                    pExportDirectory,
                    typeof(IMAGE_EXPORT_DIRECTORY));
                pNameBuffer = new IntPtr((int)this.ConvertRvaToOffset(exportDirectory.Name));
            }

            try
            {
                imageName = this.ReadAnsiString(pNameBuffer);
            }
            catch
            {
                imageName = null;
            }

            return imageName;
        }


        public IntPtr GetExportTablePointer()
        {
            if (this.Is64Bit)
            {
                if (Environment.Is64BitProcess)
                    return new IntPtr((long)this.NtHeader64.OptionalHeader.ExportTable.VirtualAddress);
                else
                    return new IntPtr((int)this.NtHeader64.OptionalHeader.ExportTable.VirtualAddress);
            }
            else
            {
                if (Environment.Is64BitProcess)
                    return new IntPtr((long)this.NtHeader32.OptionalHeader.ExportTable.VirtualAddress);
                else
                    return new IntPtr((int)this.NtHeader32.OptionalHeader.ExportTable.VirtualAddress);
            }
        }


        public IntPtr GetImageBase()
        {
            if (this.Is64Bit)
            {
                if (Environment.Is64BitProcess)
                    return new IntPtr((long)this.NtHeader64.OptionalHeader.ImageBase);
                else
                    return new IntPtr((int)this.NtHeader64.OptionalHeader.ImageBase);
            }
            else
            {
                if (Environment.Is64BitProcess)
                    return new IntPtr((long)this.NtHeader32.OptionalHeader.ImageBase);
                else
                    return new IntPtr((int)this.NtHeader32.OptionalHeader.ImageBase);
            }
        }


        public IntPtr GetSectionBaseAddress(string sectionName)
        {
            foreach (var header in this.SectionHeaders)
            {
                if (sectionName == header.Name)
                {
                    if (Environment.Is64BitProcess)
                        return new IntPtr((long)header.PointerToRawData);
                    else
                        return new IntPtr((int)header.PointerToRawData);
                }
            }

            return IntPtr.Zero;
        }


        public SectionFlags GetSectionCharacteristics(string sectionName)
        {
            var comparison = StringComparison.OrdinalIgnoreCase;

            foreach (var header in this.SectionHeaders)
            {
                if (string.Compare(sectionName, header.Name, comparison) == 0)
                    return header.Characteristics;
            }

            return 0u;
        }


        private bool GetSectionHeaders(out List<IMAGE_SECTION_HEADER> _sectionHeaders)
        {
            IntPtr pFileHeader;
            IntPtr pOptionalHeader;
            IntPtr pSectionHeaders;
            IntPtr pCurrentSectionHeader;
            IMAGE_FILE_HEADER fileHeader;
            IMAGE_SECTION_HEADER sectionHeader;
            ushort nSectionCount;
            int nOffsetOfOptionalHeader;
            int nSizeOfSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

            _sectionHeaders = new List<IMAGE_SECTION_HEADER>();

            if (Environment.Is64BitProcess)
                pFileHeader = new IntPtr(this.Buffer.ToInt64() + this.DosHeader.e_lfanew + Marshal.SizeOf(typeof(int)));
            else
                pFileHeader = new IntPtr(this.Buffer.ToInt32() + this.DosHeader.e_lfanew + Marshal.SizeOf(typeof(int)));

            if (this.Is64Bit)
                nOffsetOfOptionalHeader = Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS64), "OptionalHeader").ToInt32();
            else
                nOffsetOfOptionalHeader = Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS32), "OptionalHeader").ToInt32();

            try
            {
                fileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(pFileHeader, typeof(IMAGE_FILE_HEADER));
                nSectionCount = fileHeader.NumberOfSections;

                if (Environment.Is64BitProcess)
                {
                    pOptionalHeader = new IntPtr(this.Buffer.ToInt64() + this.DosHeader.e_lfanew + nOffsetOfOptionalHeader);
                    pSectionHeaders = new IntPtr(pOptionalHeader.ToInt64() + fileHeader.SizeOfOptionalHeader);
                }
                else
                {
                    pOptionalHeader = new IntPtr(this.Buffer.ToInt32() + this.DosHeader.e_lfanew + nOffsetOfOptionalHeader);
                    pSectionHeaders = new IntPtr(pOptionalHeader.ToInt32() + fileHeader.SizeOfOptionalHeader);
                }

                for (var idx = 0; idx < nSectionCount; idx++)
                {
                    if (Environment.Is64BitProcess)
                        pCurrentSectionHeader = new IntPtr(pSectionHeaders.ToInt64() + (idx * nSizeOfSectionHeader));
                    else
                        pCurrentSectionHeader = new IntPtr(pSectionHeaders.ToInt32() + (idx * nSizeOfSectionHeader));

                    sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pCurrentSectionHeader,
                        typeof(IMAGE_SECTION_HEADER));
                    _sectionHeaders.Add(sectionHeader);
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
            var comparison = StringComparison.OrdinalIgnoreCase;

            foreach (var header in this.SectionHeaders)
            {
                if (string.Compare(sectionName, header.Name, comparison) == 0)
                    return header.PointerToRawData;
            }

            return 0u;
        }


        public uint GetSectionSizeOfRawData(string sectionName)
        {
            var comparison = StringComparison.OrdinalIgnoreCase;

            foreach (var header in this.SectionHeaders)
            {
                if (string.Compare(sectionName, header.Name, comparison) == 0)
                    return header.SizeOfRawData;
            }

            return 0u;
        }


        public uint GetSectionVirtualAddress(string sectionName)
        {
            var comparison = StringComparison.OrdinalIgnoreCase;

            foreach (var header in this.SectionHeaders)
            {
                if (string.Compare(sectionName, header.Name, comparison) == 0)
                    return header.VirtualAddress;
            }

            return 0u;
        }


        public uint GetSectionVirtualSize(string sectionName)
        {
            var comparison = StringComparison.OrdinalIgnoreCase;

            foreach (var header in this.SectionHeaders)
            {
                if (string.Compare(sectionName, header.Name, comparison) == 0)
                    return header.VirtualSize;
            }

            return 0u;
        }


        public uint GetSizeOfImage()
        {
            if (this.Is64Bit)
                return this.NtHeader64.OptionalHeader.SizeOfImage;
            else
                return this.NtHeader32.OptionalHeader.SizeOfImage;
        }


        public uint GetSizeOfHeaders()
        {
            if (this.Is64Bit)
                return this.NtHeader64.OptionalHeader.SizeOfHeaders;
            else
                return this.NtHeader32.OptionalHeader.SizeOfHeaders;
        }


        public string[] ListSectionHeaderNames()
        {
            var results = new List<string>();

            foreach (var header in this.SectionHeaders)
                results.Add(header.Name);

            return results.ToArray();
        }


        private IntPtr LoadFileData(string _filePath, out uint length)
        {
            byte[] data;
            IntPtr buffer;
            var fullFilePath = Path.GetFullPath(_filePath);
            length = 0u;

            if (!File.Exists(fullFilePath))
                return IntPtr.Zero;

            try
            {
                data = File.ReadAllBytes(fullFilePath);
                buffer = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, buffer, data.Length);
                length = (uint)data.Length;

                return buffer;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }


        private IntPtr LoadFileData(byte[] data, out uint length)
        {
            IntPtr buffer;
            length = (uint)data.Length;

            try
            {
                buffer = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, buffer, data.Length);

                return buffer;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }


        public string ReadAnsiString(IntPtr address)
        {
            return this.ReadAnsiString(address, 0);
        }


        public string ReadAnsiString(IntPtr address, int offset)
        {
            IntPtr pStringBuffer;

            if (Environment.Is64BitProcess)
                pStringBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pStringBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return Marshal.PtrToStringAnsi(pStringBuffer);
        }


        public byte ReadByte(IntPtr address)
        {
            return this.ReadByte(address, 0);
        }


        public byte ReadByte(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return Marshal.ReadByte(pBuffer);
        }


        public short ReadInt16(IntPtr address)
        {
            return this.ReadInt16(address, 0);
        }


        public short ReadInt16(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return Marshal.ReadInt16(pBuffer);
        }


        public int ReadInt32(IntPtr address)
        {
            return this.ReadInt32(address, 0);
        }


        public int ReadInt32(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return Marshal.ReadInt32(pBuffer);
        }


        public long ReadInt64(IntPtr address)
        {
            return this.ReadInt64(address, 0);
        }


        public long ReadInt64(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return Marshal.ReadInt64(pBuffer);
        }


        public IntPtr ReadIntPtr(IntPtr address)
        {
            return this.ReadIntPtr(address, 0);
        }


        public IntPtr ReadIntPtr(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            if (this.Is64Bit)
            {
                if (Environment.Is64BitProcess)
                    return new IntPtr(Marshal.ReadInt64(pBuffer));
                else
                    return new IntPtr((int)Marshal.ReadInt64(pBuffer));
            }
            else
            {
                return new IntPtr(Marshal.ReadInt32(pBuffer));
            }
        }


        public ushort ReadUInt16(IntPtr address)
        {
            return this.ReadUInt16(address, 0);
        }


        public ushort ReadUInt16(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return (ushort)Marshal.ReadInt16(pBuffer);
        }


        public uint ReadUInt32(IntPtr address)
        {
            return this.ReadUInt32(address, 0);
        }


        public uint ReadUInt32(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return (uint)Marshal.ReadInt32(pBuffer);
        }


        public ulong ReadUInt64(IntPtr address)
        {
            return this.ReadUInt64(address, 0);
        }


        public ulong ReadUInt64(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return (ulong)Marshal.ReadInt64(pBuffer);
        }


        public string ReadUnicodeString(IntPtr address)
        {
            return this.ReadUnicodeString(address, 0);
        }


        public string ReadUnicodeString(IntPtr address, int offset)
        {
            IntPtr pBuffer;

            if (Environment.Is64BitProcess)
                pBuffer = new IntPtr(this.Buffer.ToInt64() + address.ToInt64() + offset);
            else
                pBuffer = new IntPtr(this.Buffer.ToInt32() + address.ToInt32() + offset);

            return Marshal.PtrToStringUni(pBuffer);
        }


        public IntPtr[] SearchBytes(IntPtr basePointer, uint range, byte[] searchBytes)
        {
            return this.SearchBytes(basePointer, 0, range, searchBytes);
        }


        public IntPtr[] SearchBytes(
            IntPtr basePointer,
            int offset,
            uint range,
            byte[] searchBytes)
        {
            var results = new List<IntPtr>();
            IntPtr pointer;
            bool found;

            if (range > (uint)Int32.MaxValue)
                return results.ToArray();

            for (var count = 0; count < (int)(range - searchBytes.Length); count++)
            {
                found = false;

                if (Environment.Is64BitProcess)
                    pointer = new IntPtr(basePointer.ToInt64() + offset + count);
                else
                    pointer = new IntPtr(basePointer.ToInt32() + offset + count);

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


        public IntPtr SearchBytesFirst(IntPtr basePointer, uint range, byte[] searchBytes)
        {
            return this.SearchBytesFirst(basePointer, 0, range, searchBytes);
        }


        public IntPtr SearchBytesFirst(
            IntPtr basePointer,
            int offset,
            uint range,
            byte[] searchBytes)
        {
            IntPtr pointer;
            bool found;

            if (range > (uint)Int32.MaxValue)
                return IntPtr.Zero;

            for (var count = 0; count < (range - searchBytes.Length); count++)
            {
                found = false;

                if (Environment.Is64BitProcess)
                    pointer = new IntPtr(basePointer.ToInt64() + offset + count);
                else
                    pointer = new IntPtr(basePointer.ToInt32() + offset + count);

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
