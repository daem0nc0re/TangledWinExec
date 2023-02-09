using System;
using System.Runtime.InteropServices;

namespace DarkLibraryLoader.Interop
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate bool DllMain(
            IntPtr hinstDLL, // DLL base address
            DLLMAIN_CALL_REASON fdwReason,
            IntPtr lpvReserved);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void IMAGE_TLS_CALLBACK(
        IntPtr DllHandle,
        DLLMAIN_CALL_REASON Reason,
        IntPtr Reserved);
}
