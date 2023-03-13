using System;
using HashResolveTester.Interop;

namespace HashResolveTester.Library
{
    internal class Modules
    {
        public static bool ResolveFunctionAddress(string dllName, uint hash)
        {
            IntPtr pLibrary;
            var pProc = IntPtr.Zero;

            do
            {
                pLibrary = NativeMethods.LoadLibraryA(dllName);

                if (pLibrary == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to load {0}", dllName);
                    break;
                }
                else
                {
                    Console.WriteLine("[*] {0} @ 0x{1}", dllName, pLibrary.ToString(Environment.Is64BitProcess ? "X16" : "X8"));
                }

                pProc = Helpers.GetProcAddressByHash(pLibrary, hash, out string functionName);

                if (pProc == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get function address by hash.");
                }
                else
                {
                    Console.WriteLine(
                        "[*] 0x{0} => 0x{1} ({2}!{3})",
                        hash.ToString("X8"),
                        pProc.ToString(Environment.Is64BitProcess ? "X16" : "X8"),
                        dllName.ToLower(),
                        functionName);
                }
            } while (false);

            return (pProc != IntPtr.Zero);
        }
    }
}
