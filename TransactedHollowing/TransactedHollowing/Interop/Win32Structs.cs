using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TransactedHollowing.Interop
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
    internal struct FILE_DISPOSITION_INFORMATION
    {
        public BOOLEAN DeleteFile;

        public FILE_DISPOSITION_INFORMATION(bool flag)
        {
            if (flag)
                this.DeleteFile = BOOLEAN.TRUE;
            else
                this.DeleteFile = BOOLEAN.FALSE;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_DISPOSITION_INFORMATION_EX
    {
        public FILE_DISPOSITION_FLAGS Flags;
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
    internal struct PEB32_PARTIAL
    {
        public byte InheritedAddressSpace;
        public byte ReadImageFileExecOptions;
        public byte BeingDebugged;
        public byte BitField;
        public uint Mutant;
        public uint ImageBaseAddress;
        public uint Ldr;
        public uint ProcessParameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB64_PARTIAL
    {
        public byte InheritedAddressSpace;
        public byte ReadImageFileExecOptions;
        public byte BeingDebugged;
        public byte BitField;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public ulong Mutant;
        public ulong ImageBaseAddress;
        public ulong Ldr; // _PEB_LDR_DATA*
        public ulong ProcessParameters; // _RTL_USER_PROCESS_PARAMETERS*
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
    internal struct PS_ATTRIBUTE
    {
        public UIntPtr Attribute; // PS_ATTRIBUTES
        public SIZE_T Size;
        public IntPtr Value;
        public IntPtr /* PSIZE_T */ ReturnLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_ATTRIBUTE_LIST
    {
        public SIZE_T TotalLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public PS_ATTRIBUTE[] Attributes;

        public PS_ATTRIBUTE_LIST(int nAttributes)
        {
            int length;

            if (nAttributes < 8)
                length = 8;
            else
                length = nAttributes;

            Attributes = new PS_ATTRIBUTE[length];
            TotalLength = new SIZE_T((uint)(
                Marshal.SizeOf(typeof(SIZE_T)) +
                (Marshal.SizeOf(typeof(PS_ATTRIBUTE)) * nAttributes)));
        }

        public PS_ATTRIBUTE_LIST(PS_ATTRIBUTE[] attributes)
        {
            int length;

            if (attributes.Length < 8)
                length = 8;
            else
                length = attributes.Length;

            Attributes = new PS_ATTRIBUTE[length];

            for (var idx = 0; idx < attributes.Length; idx++)
            {
                Attributes[idx].Attribute = attributes[idx].Attribute;
                Attributes[idx].Size = attributes[idx].Size;
                Attributes[idx].Value = attributes[idx].Value;
            }

            TotalLength = new SIZE_T((uint)(
                Marshal.SizeOf(typeof(SIZE_T)) +
                (Marshal.SizeOf(typeof(PS_ATTRIBUTE)) * length)));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_INFO
    {
        public SIZE_T Size;
        public PS_CREATE_STATE State;
        public PS_CREATE_INFO_UNION Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_EXE_FORMAT
    {
        public ushort DllCharacteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_EXE_NAME
    {
        public IntPtr IFEOKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_FAIL_SECTION
    {
        public IntPtr FileHandle;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct PS_CREATE_INFO_UNION
    {
        [FieldOffset(0)]
        public PS_CREATE_INITIAL_STATE InitState; // PsCreateInitialState

        [FieldOffset(0)]
        public PS_CREATE_FAIL_SECTION FailSection; // PsCreateFailOnSectionCreate

        [FieldOffset(0)]
        public PS_CREATE_EXE_FORMAT ExeFormat; // PsCreateFailExeFormat

        [FieldOffset(0)]
        public PS_CREATE_EXE_NAME ExeName; // PsCreateFailExeName

        [FieldOffset(0)]
        public PS_CREATE_SUCCESS_STATE SuccessState; // PsCreateSuccess
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_INITIAL_STATE
    {
        public PS_CREATE_INIT_FLAGS InitFlags;
        public ACCESS_MASK AdditionalFileAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_SUCCESS_STATE
    {
        public PS_CREATE_OUTPUT_FLAGS OutputFlags;
        public IntPtr FileHandle;
        public IntPtr SectionHandle;
        public ulong UserProcessParametersNative;
        public uint UserProcessParametersWow64;
        public uint CurrentParameterFlags;
        public ulong PebAddressNative;
        public uint PebAddressWow64;
        public ulong ManifestAddress;
        public uint ManifestSize;
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
    internal struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
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
