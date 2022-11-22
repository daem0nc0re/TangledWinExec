using System;
using System.Runtime.InteropServices;

namespace RemoteCodeInjector.Interop
{
    internal class DelegateTypes
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int THREAD_START_ROUTINE(IntPtr lpThreadParameter);
    }
}
