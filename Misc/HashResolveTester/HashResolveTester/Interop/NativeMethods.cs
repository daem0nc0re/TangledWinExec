using System;
using System.Runtime.InteropServices;

namespace HashResolveTester.Interop
{
    internal class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr LoadLibraryA(string lpLibFileName);
    }
}
