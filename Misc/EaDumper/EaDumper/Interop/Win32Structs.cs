using System;
using System.Runtime.InteropServices;
using System.Text;

namespace EaDumper.Interop
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential)]
    internal struct CI_ESB_EA_V3
    {
        public int Size;
        public ushort MajorVersion;
        public byte MinorVersion;
        public SE_SIGNING_LEVEL SignerLevel;
        public LARGE_INTEGER UsnJournalId;
        public LARGE_INTEGER LastBlackListTime;
        public uint Flags;
        public short ExtraDataSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] ExtraData;  // CI_DATA_BLOB
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CI_DATA_BLOB
    {
        public byte Size;
        public CI_DATA_BLOB_TYPE Type;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] BlobData; // CI_HASH_DATA_BLOB or others
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CI_HASH_DATA_BLOB
    {
        public HASH_ALGORITHM HashAlgorithm;
        public byte HashLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] HashData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_FULL_EA_INFORMATION
    {
        public uint NextEntryOffset;
        public EA_INFORMATION_FLAGS Flags;
        public byte EaNameLength;
        public ushort EaValueLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] EaName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_GET_EA_INFORMATION
    {
        public uint NextEntryOffset;
        public byte EaNameLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] EaName;
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
    internal struct TIME_ZONE_INFORMATION
    {
        public int Bias;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public short[] StandardName;
        public SYSTEMTIME StandardDate;
        public int StandardBias;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public short[] DaylightName;
        public SYSTEMTIME DaylightDate;
        public int DaylightBias;
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
