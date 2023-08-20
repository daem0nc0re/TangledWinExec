using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CommandLineSpoofing.Interop
{
    using NTSTATUS = Int32;

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
        public uint Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CURDIR64
    {
        public UNICODE_STRING64 DosPath;
        public ulong Handle;
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
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
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
    internal struct RTL_DRIVE_LETTER_CURDIR64
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING64 DosPath;
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
        public uint ConsoleHandle;
        public uint ConsoleFlags;
        public uint StandardInput;
        public uint StandardOutput;
        public uint StandardError;
        public CURDIR32 CurrentDirectory;
        public UNICODE_STRING32 DllPath;
        public UNICODE_STRING32 ImagePathName;
        public UNICODE_STRING32 CommandLine;
        public uint Environment;
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
        public ulong EnvironmentSize;
        public ulong EnvironmentVersion;
        public uint PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING32 RedirectionDllName;
        public UNICODE_STRING32 HeapPartitionName;
        public uint DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_USER_PROCESS_PARAMETERS64
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public ulong ConsoleHandle;
        public uint ConsoleFlags;
        public ulong StandardInput;
        public ulong StandardOutput;
        public ulong StandardError;
        public CURDIR64 CurrentDirectory;
        public UNICODE_STRING64 DllPath;
        public UNICODE_STRING64 ImagePathName;
        public UNICODE_STRING64 CommandLine;
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
        public UNICODE_STRING64 WindowTitle;
        public UNICODE_STRING64 DesktopInfo;
        public UNICODE_STRING64 ShellInfo;
        public UNICODE_STRING64 RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public RTL_DRIVE_LETTER_CURDIR64[] CurrentDirectores;
        public ulong EnvironmentSize;
        public ulong EnvironmentVersion;
        public ulong PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING64 RedirectionDllName;
        public UNICODE_STRING64 HeapPartitionName;
        public ulong DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public STARTF dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
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
        public uint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        public ulong Buffer;
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
        public uint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        public ulong Buffer;
    }
}
