using System;
using System.Runtime.InteropServices;

namespace PeRipper.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_BASE_RELOCATION
    {
        public int VirtualAddress;
        public int SizeOfBlock;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_DELAYLOAD_DESCRIPTOR
    {
        public int Attributes;
        public int DllNameRVA;                  // RVA to the name of the target library (NULL-terminate ASCII string)
        public int ModuleHandleRVA;             // RVA to the HMODULE caching location (PHMODULE)
        public int ImportAddressTableRVA;       // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
        public int ImportNameTableRVA;          // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
        public int BoundImportAddressTableRVA;  // RVA to an optional bound IAT
        public int UnloadInformationTableRVA;   // RVA to an optional unload info table
        public int TimeDateStamp;               // 0 if not bound, Otherwise, date/time of the target DLL
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_EXPORT_DIRECTORY
    {
        public int Characteristics;
        public int TimeDateStamp;
        public short MajorVersion;
        public short MinorVersion;
        public int Name;
        public int Base;
        public int NumberOfFunctions;
        public int NumberOfNames;
        public int AddressOfFunctions;     // RVA from base of image
        public int AddressOfNames;         // RVA from base of image
        public int AddressOfNameOrdinals;  // RVA from base of image
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_IMPORT_BY_NAME
    {
        public short Hint;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] Name;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_IMPORT_DESCRIPTOR
    {
        [FieldOffset(0)]
        public uint Characteristics;

        [FieldOffset(0)]
        public uint OriginalFirstThunk;

        [FieldOffset(4)]
        public uint TimeDateStamp;

        [FieldOffset(8)]
        public uint ForwarderChain;

        [FieldOffset(12)]
        public uint Name;

        [FieldOffset(16)]
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_SECTION_HEADER
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

    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_THUNK_DATA
    {
        [FieldOffset(0)]
        public IntPtr ForwarderString;

        [FieldOffset(0)]
        public IntPtr Function;

        [FieldOffset(0)]
        public IntPtr Ordinal;

        [FieldOffset(0)]
        public IntPtr AddressOfData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_TLS_DIRECTORY
    {
        public IntPtr StartAddressOfRawData;
        public IntPtr EndAddressOfRawData;
        public IntPtr AddressOfIndex;         // PDWORD
        public IntPtr AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
        public int SizeOfZeroFill;
        public int Characteristics;
    }
}
