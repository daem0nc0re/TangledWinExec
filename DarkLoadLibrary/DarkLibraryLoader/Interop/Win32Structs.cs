using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DarkLibraryLoader.Interop
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

    [StructLayout(LayoutKind.Explicit)]
    internal struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public int Low;
        [FieldOffset(4)]
        public int High;
        [FieldOffset(0)]
        public long QuadPart;

        public long ToInt64()
        {
            return ((long)this.High << 32) | (uint)this.Low;
        }

        public static LARGE_INTEGER FromInt64(long value)
        {
            return new LARGE_INTEGER
            {
                Low = (int)(value),
                High = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_DATA_TABLE_ENTRY
    {
        public LIST_ENTRY InLoadOrderLinks;
        public LIST_ENTRY InMemoryOrderLinks;
        public LIST_ENTRY InInitializationOrderLinks;
        public IntPtr DllBase;
        public IntPtr EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING FullDllName;
        public UNICODE_STRING BaseDllName;
        public LDR_DATA_TABLE_ENTRY_FLAGS Flags;
        public ushort ObsoleteLoadCount;
        public ushort TlsIndex;
        public LIST_ENTRY HashLinks;
        public uint TimeDateStamp;
        public IntPtr  /* _ACTIVATION_CONTEXT* */ EntryPointActivationContext;
        public IntPtr Lock;
        public IntPtr /* _LDR_DDAG_NODE* */ DdagNode;
        public LIST_ENTRY NodeModuleLink;
        public IntPtr  /* _LDRP_LOAD_CONTEXT* */ LoadContext;
        public IntPtr ParentDllBase;
        public IntPtr SwitchBackContext;
        public RTL_BALANCED_NODE BaseAddressIndexNode;
        public RTL_BALANCED_NODE MappingInfoIndexNode;
        public IntPtr OriginalBase;
        public LARGE_INTEGER LoadTime;
        public uint BaseNameHashValue;
        public LDR_DLL_LOAD_REASON LoadReason;
        public uint ImplicitPathOptions;
        public uint ReferenceCount;
        public uint DependentLoadFlags;
        public byte SigningLevel;
        /* Following members only in 64bit mode (Size = 0x10)*/
        // public uint CheckSum;
        // public IntPtr ActivePatchImageBase;
        // public LDR_HOT_PATCH_STATE HotPatchState;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_DDAG_NODE
    {
        public LIST_ENTRY Modules;
        public IntPtr /* LDR_SERVICE_TAG_RECORD* */ ServiceTagList;
        public uint LoadCount;
        public uint LoadWhileUnloadingCount;
        public uint LowestLink;
        public LDRP_CSLIST Dependencies;
        public LDRP_CSLIST IncomingDependencies;
        public LDR_DDAG_STATE State;
        public SINGLE_LIST_ENTRY CondenseLink;
        public uint PreorderNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_SERVICE_TAG_RECORD
    {
        public IntPtr /* LDR_SERVICE_TAG_RECORD* */ Next;
        public uint ServiceTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDRP_CSLIST
    {
        public IntPtr /* SINGLE_LIST_ENTRY* */ Tail;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LIST_ENTRY
    {
        public IntPtr /* LIST_ENTRY* */ Flink;
        public IntPtr /* LIST_ENTRY* */ Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB_LDR_DATA
    {
        public uint Length;
        public byte Initialized;
        public IntPtr SsHandle;
        public LIST_ENTRY InLoadOrderModuleList;
        public LIST_ENTRY InMemoryOrderModuleList;
        public LIST_ENTRY InInitializationOrderModuleList;
        public IntPtr EntryInProgress;
        public byte ShutdownInProgress;
        public IntPtr ShutdownThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB_PARTIAL
    {
        public BOOLEAN InheritedAddressSpace;
        public BOOLEAN ReadImageFileExecOptions;
        public BOOLEAN BeingDebugged;
        public byte BitField;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public IntPtr Mutant;
        public IntPtr ImageBaseAddress;
        public IntPtr /* PEB_LDR_DATA */ Ldr;
        public IntPtr /* RTL_USER_PROCESS_PARAMETERS* */ ProcessParameters;
        public IntPtr SubSystemData;
        public IntPtr ProcessHeap;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public int ExitStatus;
        public IntPtr PebBaseAddress;
        public UIntPtr AffinityMask;
        public int BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_BALANCED_NODE
    {
        public IntPtr /* RTL_BALANCED_NODE* */ Left;
        public IntPtr /* RTL_BALANCED_NODE* */ Right;
        public IntPtr ParentValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_RB_TREE
    {
        public IntPtr /* RTL_BALANCED_NODE* */ Root;
        public IntPtr /* RTL_BALANCED_NODE* */ Min;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SINGLE_LIST_ENTRY
    {
        public IntPtr /* SINGLE_LIST_ENTRY* */ Next;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            byte[] bytes;

            if (string.IsNullOrEmpty(s))
            {
                Length = 0;
                bytes = new byte[2];
            }
            else
            {
                Length = (ushort)(s.Length * 2);
                bytes = Encoding.Unicode.GetBytes(s);
            }

            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.AllocHGlobal(MaximumLength);

            Marshal.Copy(new byte[MaximumLength], 0, buffer, MaximumLength);
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer, Length / 2);
        }

        public IntPtr GetBuffer()
        {
            return buffer;
        }

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }
    }
}
