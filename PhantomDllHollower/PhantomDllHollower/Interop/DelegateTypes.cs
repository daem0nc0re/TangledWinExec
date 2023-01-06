using System;
using System.Runtime.InteropServices;

namespace PhantomDllHollower.Interop
{
    internal class DelegateTypes
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DllMain(
            IntPtr hinstDLL, // DLL base address
            DLLMAIN_CALL_REASON fdwReason,
            IntPtr lpvReserved);
    }
}
