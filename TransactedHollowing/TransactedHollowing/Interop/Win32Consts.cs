using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TransactedHollowing.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const NTSTATUS STATUS_IMAGE_NOT_AT_BASE = 0x40000003;
        public const int MAX_PATH = 260;
    }
}
