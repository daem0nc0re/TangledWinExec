using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcMemScan.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    [StructLayout(LayoutKind.Sequential)]
    internal struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CURDIR
    {
        public UNICODE_STRING DosPath;
        public IntPtr Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CURDIR32
    {
        public UNICODE_STRING32 DosPath;
        public int /* IntPtr */ Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_DOS_HEADER
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
    internal struct IMAGE_FILE_HEADER
    {
        public IMAGE_FILE_MACHINE Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_STATUS_BLOCK
    {
        public NTSTATUS status;
        public IntPtr information;
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
        public uint Flags;
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
        public ulong OriginalBase;
        public LARGE_INTEGER LoadTime;
        public uint BaseNameHashValue;
        public LDR_DLL_LOAD_REASON LoadReason;
        public uint ImplicitPathOptions;
        public uint ReferenceCount;
        public uint DependentLoadFlags;
        public byte SigningLevel;
        public uint CheckSum;
        public IntPtr ActivePatchImageBase;
        public LDR_HOT_PATCH_STATE HotPatchState;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_DATA_TABLE_ENTRY32
    {
        public LIST_ENTRY32 InLoadOrderLinks;
        public LIST_ENTRY32 InMemoryOrderLinks;
        public LIST_ENTRY32 InInitializationOrderLinks;
        public int /* IntPtr */ DllBase;
        public int /* IntPtr */ EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING32 FullDllName;
        public UNICODE_STRING32 BaseDllName;
        public uint Flags;
        public ushort ObsoleteLoadCount;
        public ushort TlsIndex;
        public LIST_ENTRY32 HashLinks;
        public uint TimeDateStamp;
        public int /* _ACTIVATION_CONTEXT* */ EntryPointActivationContext;
        public int /* IntPtr */ Lock;
        public int /* _LDR_DDAG_NODE* */ DdagNode;
        public LIST_ENTRY32 NodeModuleLink;
        public int /* _LDRP_LOAD_CONTEXT* */ LoadContext;
        public int /* IntPtr */ ParentDllBase;
        public int /* IntPtr */ SwitchBackContext;
        public RTL_BALANCED_NODE32 BaseAddressIndexNode;
        public RTL_BALANCED_NODE32 MappingInfoIndexNode;
        public uint OriginalBase;
        public LARGE_INTEGER LoadTime;
        public uint BaseNameHashValue;
        public LDR_DLL_LOAD_REASON LoadReason;
        public uint ImplicitPathOptions;
        public uint ReferenceCount;
        public uint DependentLoadFlags;
        public byte SigningLevel;
        public uint CheckSum;
        public int /* IntPtr */ ActivePatchImageBase;
        public LDR_HOT_PATCH_STATE HotPatchState;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LIST_ENTRY
    {
        public IntPtr Flink;
        public IntPtr Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LIST_ENTRY32
    {
        public int Flink;
        public int Blink;
    }

    [StructLayout(LayoutKind.Explicit, Size = 8, Pack = 4)]
    internal struct LUID
    {
        [FieldOffset(0)]
        public int LowPart;
        [FieldOffset(4)]
        public int HighPart;
        [FieldOffset(0)]
        public long QuadPart;

        public LUID(int _low, int _high)
        {
            QuadPart = 0L;
            LowPart = _low;
            HighPart = _high;
        }

        public LUID(long _quad)
        {
            LowPart = 0;
            HighPart = 0;
            QuadPart = _quad;
        }

        public long ToInt64()
        {
            return ((long)this.HighPart << 32) | (uint)this.LowPart;
        }

        public static LUID FromInt64(long value)
        {
            return new LUID
            {
                LowPart = (int)(value),
                HighPart = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MEMORY_PROTECTION AllocationProtect;
        public SIZE_T RegionSize;
        public MEMORY_ALLOCATION_TYPE State;
        public MEMORY_PROTECTION Protect;
        public MEMORY_ALLOCATION_TYPE Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_IMAGE_INFORMATION
    {
        public IntPtr ImageBase;
        public SIZE_T SizeOfImage;
        public uint ImageFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public OBJECT_ATTRIBUTES_FLAGS Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

        public OBJECT_ATTRIBUTES(
            string name,
            OBJECT_ATTRIBUTES_FLAGS attrs)
        {
            Length = 0;
            RootDirectory = IntPtr.Zero;
            objectName = IntPtr.Zero;
            Attributes = attrs;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;

            Length = Marshal.SizeOf(this);
            ObjectName = new UNICODE_STRING(name);
        }

        public UNICODE_STRING ObjectName
        {
            get
            {
                return (UNICODE_STRING)Marshal.PtrToStructure(
                 objectName, typeof(UNICODE_STRING));
            }

            set
            {
                bool fDeleteOld = objectName != IntPtr.Zero;
                if (!fDeleteOld)
                    objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                Marshal.StructureToPtr(value, objectName, fDeleteOld);
            }
        }

        public void Dispose()
        {
            if (objectName != IntPtr.Zero)
            {
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_BASIC_INFORMATION
    {
        public uint Attributes;
        public ACCESS_MASK GrantedAccess;
        public uint HandleCount;
        public uint PointerCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public uint[] Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB_LDR_DATA
    {
        public uint Length;
        public BOOLEAN Initialized;
        public IntPtr SsHandle;
        public LIST_ENTRY InLoadOrderModuleList;
        public LIST_ENTRY InMemoryOrderModuleList;
        public LIST_ENTRY InInitializationOrderModuleList;
        public IntPtr EntryInProgress;
        public BOOLEAN ShutdownInProgress;
        public IntPtr ShutdownThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB_LDR_DATA32
    {
        public uint Length;
        public BOOLEAN Initialized;
        public int SsHandle;
        public LIST_ENTRY32 InLoadOrderModuleList;
        public LIST_ENTRY32 InMemoryOrderModuleList;
        public LIST_ENTRY32 InInitializationOrderModuleList;
        public int EntryInProgress;
        public BOOLEAN ShutdownInProgress;
        public int ShutdownThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB32_PARTIAL
    {
        public BOOLEAN InheritedAddressSpace;
        public BOOLEAN ReadImageFileExecOptions;
        public BOOLEAN BeingDebugged;
        public byte BitField;
        public uint Mutant;
        public uint ImageBaseAddress;
        public uint Ldr;
        public uint ProcessParameters;
        public uint SubSystemData;
        public uint ProcessHeap;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB64_PARTIAL
    {
        public BOOLEAN InheritedAddressSpace;
        public BOOLEAN ReadImageFileExecOptions;
        public BOOLEAN BeingDebugged;
        public byte BitField;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public ulong Mutant;
        public ulong ImageBaseAddress;
        public ulong Ldr; // _PEB_LDR_DATA*
        public ulong ProcessParameters; // _RTL_USER_PROCESS_PARAMETERS*
        public ulong SubSystemData;
        public ulong ProcessHeap;
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
        public NTSTATUS ExitStatus;
        public IntPtr PebBaseAddress;
        public UIntPtr AffinityMask;
        public int BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_DEVICEMAP_INFORMATION
    {
        public uint DriveMap;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] DriveType;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_BALANCED_NODE
    {
        public IntPtr /* RTL_BALANCED_NODE* */ Left;
        public IntPtr /* RTL_BALANCED_NODE* */ Right;
        public ulong ParentValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_BALANCED_NODE32
    {
        public int /* RTL_BALANCED_NODE32* */ Left;
        public int /* RTL_BALANCED_NODE32* */ Right;
        public uint ParentValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_DRIVE_LETTER_CURDIR
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_DRIVE_LETTER_CURDIR32
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING32 DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_USER_PROCESS_PARAMETERS
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public IntPtr ConsoleHandle;
        public uint ConsoleFlags;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
        public CURDIR CurrentDirectory;
        public UNICODE_STRING DllPath;
        public UNICODE_STRING ImagePathName;
        public UNICODE_STRING CommandLine;
        public IntPtr Environment;
        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        public UNICODE_STRING WindowTitle;
        public UNICODE_STRING DesktopInfo;
        public UNICODE_STRING ShellInfo;
        public UNICODE_STRING RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public RTL_DRIVE_LETTER_CURDIR[] CurrentDirectores;
        public ulong EnvironmentSize;
        public ulong EnvironmentVersion;
        public IntPtr PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING RedirectionDllName;
        public UNICODE_STRING HeapPartitionName;
        public IntPtr DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_USER_PROCESS_PARAMETERS32
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public int /* IntPtr */ ConsoleHandle;
        public uint ConsoleFlags;
        public int /* IntPtr */ StandardInput;
        public int /* IntPtr */ StandardOutput;
        public int /* IntPtr */ StandardError;
        public CURDIR32 CurrentDirectory;
        public UNICODE_STRING32 DllPath;
        public UNICODE_STRING32 ImagePathName;
        public UNICODE_STRING32 CommandLine;
        public int /* IntPtr */ Environment;
        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        public UNICODE_STRING32 WindowTitle;
        public UNICODE_STRING32 DesktopInfo;
        public UNICODE_STRING32 ShellInfo;
        public UNICODE_STRING32 RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public RTL_DRIVE_LETTER_CURDIR32[] CurrentDirectores;
        public uint EnvironmentSize;
        public uint EnvironmentVersion;
        public int /* IntPtr */ PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING32 RedirectionDllName;
        public UNICODE_STRING32 HeapPartitionName;
        public uint /* ULONGLONG* */ DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_QUALITY_OF_SERVICE
    {
        public int Length;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
        public BOOLEAN EffectiveOnly;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public STRING(string s)
        {
            byte[] bytes;

            if (string.IsNullOrEmpty(s))
            {
                Length = 0;
                bytes = new byte[1];
            }
            else
            {
                Length = (ushort)s.Length;
                bytes = Encoding.ASCII.GetBytes(s);
            }

            MaximumLength = (ushort)(Length + 1);
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
            return Marshal.PtrToStringAnsi(buffer);
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct STRING32
    {
        public ushort Length;
        public ushort MaximumLength;
        public int /* IntPtr */ Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYMBOL_INFO
    {
        public uint SizeOfStruct;
        public uint TypeIndex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public ulong[] Reserved;
        public uint Index;
        public uint Size;
        public ulong ModBase;
        public uint Flags;
        public ulong Value;
        public ulong Address;
        public uint Register;
        public uint Scope;
        public uint Tag;
        public uint NameLen;
        public uint MaxNameLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2000 /* MAX_SYM_NAME */)]
        public byte[] Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_THREAD_INFORMATION
    {
        public LARGE_INTEGER KernelTime;
        public LARGE_INTEGER UserTime;
        public LARGE_INTEGER CreateTime;
        public uint WaitTime;
        public IntPtr StartAddress;
        public CLIENT_ID ClientId;
        public int Priority;
        public int BasePriority;
        public uint ContextSwitches;
        public KTHREAD_STATE ThreadState;
        public KWAIT_REASON WaitReason;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEMTIME
    {
        public short wYear;
        public short wMonth;
        public DAY_OF_WEEK wDayOfWeek;
        public short wDay;
        public short wHour;
        public short wMinute;
        public short wSecond;
        public short wMilliseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING32
    {
        public ushort Length;
        public ushort MaximumLength;
        public int Buffer;
    }
}
