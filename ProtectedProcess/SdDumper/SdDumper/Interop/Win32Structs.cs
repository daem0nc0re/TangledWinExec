using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SdDumper.Interop
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACE_HEADER
    {
        public ACE_TYPE AceType;
        public ACE_FLAGS AceFlags;
        public short AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACL
    {
        public ACL_REVISION AclRevision;
        public byte Sbz1;
        public short AclSize;
        public short AceCount;
        public short Sbz2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BY_HANDLE_FILE_INFORMATION
    {
        public FILE_ATTRIBUTE dwFileAttributes;
        public LARGE_INTEGER /* FILETIME */ ftCreationTime;
        public LARGE_INTEGER /* FILETIME */ ftLastAccessTime;
        public LARGE_INTEGER /* FILETIME */ ftLastWriteTime;
        public int dwVolumeSerialNumber;
        public int nFileSizeHigh;
        public int nFileSizeLow;
        public int nNumberOfLinks;
        public int nFileIndexHigh;
        public int nFileIndexLow;
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
    internal struct LUID
    {
        public uint LowPart;
        public uint HighPart;

        public LUID(uint _lowPart, uint _highPart)
        {
            LowPart = _lowPart;
            HighPart = _highPart;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
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
    internal struct PUBLIC_OBJECT_BASIC_INFORMATION
    {
        public int Attributes;
        public ACCESS_MASK GrantedAccess;
        public int HandleCount;
        public int PointerCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public int[] Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PUBLIC_OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
        public int[] Reserved;
    }

    /*
     * PACL and PSID are relative in this tool, so type as int (not IntPtr)
     */
    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_DESCRIPTOR
    {
        public byte Revision;
        public byte Sbz1;
        public SECURITY_DESCRIPTOR_CONTROL Control;
        public int /* PSID */ Owner;
        public int /* PSID */ Group;
        public int /* PACL */ Sacl;
        public int /* PACL */ Dacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID
    {
        public byte Revision;
        public byte SubAuthorityCount;
        public SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public uint[] SubAuthority;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr /* PSID */ Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Value;

        public SID_IDENTIFIER_AUTHORITY(byte[] value)
        {
            Value = value;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ACCESS_FILTER_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_MANDATORY_LABEL_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_PROCESS_TRUST_LABEL_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_RESOURCE_ATTRIBUTE_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_SCOPED_POLICY_ID_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_DEFAULT_DACL
    {
        public IntPtr /* PACL */ DefaultDacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_OWNER
    {
        public IntPtr /* PSID */ Owner;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIMARY_GROUP
    {
        public IntPtr /* PSID */ PrimaryGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
        public LUID_AND_ATTRIBUTES[] Privileges;

        public TOKEN_PRIVILEGES(int privilegeCount)
        {
            PrivilegeCount = privilegeCount;
            Privileges = new LUID_AND_ATTRIBUTES[36];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PROCESS_TRUST_LEVEL
    {
        public IntPtr /* PSID */ TrustLevelSid;
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
