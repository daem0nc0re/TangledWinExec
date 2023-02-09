using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DarkLibraryLoader.Interop;

namespace DarkLibraryLoader.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static bool LoadLibrary(byte[] imageDataBytes, bool noLinks)
        {
            NTSTATUS ntstatus;
            int e_lfanew;
            ushort machine;
            int nTlsDirectoryOffset;
            IntPtr pImageBase;
            IntPtr pEntryPoint;
            IntPtr pImageDataDirectory;
            IntPtr pImageTlsDirectory;
            IntPtr pTlsCallback;
            IMAGE_DATA_DIRECTORY imageDataDirectory;
            IMAGE_TLS_DIRECTORY imageTlsDirectory;
            DllMain dllMain;
            IMAGE_TLS_CALLBACK tlsCallback;
            int nCallbackPointerOffset = 0;
            string addressFormat = Environment.Is64BitProcess ? "X16" : "X8";
            string baseDllName = "DarkLib.dll";
            string fullDllPath = string.Format(@"C:\Users\Public\{0}", baseDllName);
            IntPtr pModuleData = Marshal.AllocHGlobal(imageDataBytes.Length);
            var status = false;
            Marshal.Copy(imageDataBytes, 0, pModuleData, imageDataBytes.Length);

            do
            {
                Console.WriteLine("[>] Analyzing input image data.");

                if (!Helpers.IsValidModule(pModuleData))
                {
                    Console.WriteLine("[-] Invalid image data is specified.");
                    break;
                }
                else
                {
                    machine = Helpers.GetModuleArchitecture(pModuleData);
                    e_lfanew = Marshal.ReadInt32(pModuleData, 0x3C);

                    if (machine == 0x020B)
                    {
                        Console.WriteLine("[*] Architecture is AMD64");
                        nTlsDirectoryOffset = 0x88 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_TLS);

                        if (!Environment.Is64BitProcess)
                        {
                            Console.WriteLine("[!] To load 64bit module, should be built as 64bit binary.");
                            break;
                        }
                    }
                    else if (machine == 0x010B)
                    {
                        Console.WriteLine("[*] Architecture is I386");
                        nTlsDirectoryOffset = 0x68 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_TLS);

                        if (Environment.Is64BitProcess)
                        {
                            Console.WriteLine("[!] To load 32bit module, should be built as 32bit binary.");
                            break;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] Unsupported architecture.");
                        break;
                    }
                }

                Console.WriteLine("[>] Trying to map image data to new buffer.");

                pImageBase = Utilities.MapImageData(pModuleData);

                if (pImageBase == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to map image data.");
                    break;
                }
                else
                {
                    pEntryPoint = Helpers.GetEntryPointPointer(pImageBase);

                    if (pEntryPoint == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to read AddressOfEntryPoint.");
                        break;
                    }

                    Console.WriteLine("[+] Image data is mapped successfully.");
                    Console.WriteLine("    [*] Module Base @ 0x{0}", pImageBase.ToString(addressFormat));
                    Console.WriteLine("    [*] Entry Point @ 0x{0}", pEntryPoint.ToString(addressFormat));
                }

                if (!noLinks)
                {
                    Console.WriteLine("[>] Trying to link DLL to PEB.");
                    Console.WriteLine("    [*] Full DLL Path : {0}", fullDllPath);
                    Console.WriteLine("    [*] Base DLL Name : {0}", baseDllName);

                    status = Utilities.LinkModuleToPEB(pImageBase, fullDllPath, baseDllName);

                    if (!status)
                    {
                        Console.WriteLine("[-] Failed to link DLL.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] DLL is linked successfully.");
                    }
                }

                Console.WriteLine("[>] Trying to flush instruction cache.");

                ntstatus = NativeMethods.NtFlushInstructionCache(
                    Process.GetCurrentProcess().Handle,
                    IntPtr.Zero,
                    0u);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    ntstatus = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Failed to flush instuction cahche (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] Instruction cache is flushed successfully.");
                }

                if (Environment.Is64BitProcess)
                    pImageDataDirectory = new IntPtr(pImageBase.ToInt64() + e_lfanew + nTlsDirectoryOffset);
                else
                    pImageDataDirectory = new IntPtr(pImageBase.ToInt32() + e_lfanew + nTlsDirectoryOffset);

                imageDataDirectory = (IMAGE_DATA_DIRECTORY)Marshal.PtrToStructure(
                    pImageDataDirectory,
                    typeof(IMAGE_DATA_DIRECTORY));

                if (imageDataDirectory.Size > 0)
                {
                    Console.WriteLine("[>] Trying to execute TLS callbacks.");

                    if (Environment.Is64BitProcess)
                        pImageTlsDirectory = new IntPtr(pImageBase.ToInt64() + imageDataDirectory.VirtualAddress);
                    else
                        pImageTlsDirectory = new IntPtr(pImageBase.ToInt32() + (int)imageDataDirectory.VirtualAddress);

                    imageTlsDirectory = (IMAGE_TLS_DIRECTORY)Marshal.PtrToStructure(
                        pImageTlsDirectory,
                        typeof(IMAGE_TLS_DIRECTORY));
                    pTlsCallback = Marshal.ReadIntPtr(imageTlsDirectory.AddressOfCallBacks);

                    while (pTlsCallback != IntPtr.Zero)
                    {
                        tlsCallback = (IMAGE_TLS_CALLBACK)Marshal.GetDelegateForFunctionPointer(
                            pTlsCallback,
                            typeof(IMAGE_TLS_CALLBACK));

                        Console.WriteLine("[*] Calling TLS callback @ 0x{0}", pTlsCallback.ToString(addressFormat));
                        tlsCallback(pImageBase, DLLMAIN_CALL_REASON.DLL_PROCESS_ATTACH, IntPtr.Zero);

                        nCallbackPointerOffset += IntPtr.Size;
                        pTlsCallback = Marshal.ReadIntPtr(imageTlsDirectory.AddressOfCallBacks, nCallbackPointerOffset);
                    }
                }

                if (pEntryPoint != IntPtr.Zero)
                {
                    Console.WriteLine("[>] Calling DllMain by DLL_PROCESS_ATTACH.");
                    dllMain = (DllMain)Marshal.GetDelegateForFunctionPointer(
                        pEntryPoint,
                        typeof(DllMain));
                    dllMain(pImageBase, DLLMAIN_CALL_REASON.DLL_PROCESS_ATTACH, IntPtr.Zero);
                }

                status = true;
            } while (false);

            Marshal.FreeHGlobal(pModuleData);

            Console.WriteLine("[*] Done.");

            return status;
        }
    }
}
