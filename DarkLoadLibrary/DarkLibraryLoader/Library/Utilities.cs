using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DarkLibraryLoader.Interop;

namespace DarkLibraryLoader.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;
    using IMAGE_RELOC = UInt16; // struct IMAGE_RELOC { WORD offset:12, WORD type:4 };

    internal class Utilities
    {
        public static bool BuildBaseRelocDirectory(IntPtr pRawModuleData, IntPtr pNewImageBase)
        {
            int e_lfanew;
            int nBaseRelocDirectoryOffset;
            int nRelocationCount;
            int relocOffset;
            int tmpInt32;
            short tmpInt16;
            uint nBaseRelocEntryOffset;
            uint nRelocationBlockOffset;
            ushort machine;
            IntPtr pImageBaseRelocDirectory;
            IntPtr pOriginalImageBase;
            IntPtr pDifference;
            IntPtr pImageBaseRelocation;
            IntPtr pRelocationBlock;
            IntPtr pImageReloc;
            IntPtr pNewPointer;
            IMAGE_DATA_DIRECTORY imageBaseRelocDirectory;
            IMAGE_BASE_RELOCATION imageBaseRelocation;
            IMAGE_RELOC imageReloc;
            IMAGE_REL_BASED_TYPE relocType;
            bool isRebaseRequired;
            var is64Bit = false;
            var status = false;

            do
            {
                if (!Helpers.IsValidModule(pRawModuleData))
                    break;

                e_lfanew = Marshal.ReadInt32(pRawModuleData, 0x3C);
                machine = Helpers.GetModuleArchitecture(pRawModuleData);

                if (machine == 0x020B)
                {
                    is64Bit = true;
                    nBaseRelocDirectoryOffset = 0x88 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_BASERELOC);
                    pOriginalImageBase = Marshal.ReadIntPtr(pRawModuleData, e_lfanew + 0x30);
                }
                else if (machine == 0x010B)
                {
                    nBaseRelocDirectoryOffset = 0x68 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_BASERELOC);
                    pOriginalImageBase = Marshal.ReadIntPtr(pRawModuleData, e_lfanew + 0x34);
                }
                else
                {
                    break;
                }

                if (is64Bit && !Environment.Is64BitProcess)
                    throw new InvalidOperationException("To load 64bit module, should be built as 64bit binary");
                else if (!is64Bit && Environment.Is64BitProcess)
                    throw new InvalidOperationException("To load 32bit module, should be built as 32bit binary");

                if (Environment.Is64BitProcess)
                    pImageBaseRelocDirectory = new IntPtr(pRawModuleData.ToInt64() + e_lfanew + nBaseRelocDirectoryOffset);
                else
                    pImageBaseRelocDirectory = new IntPtr(pRawModuleData.ToInt32() + e_lfanew + nBaseRelocDirectoryOffset);

                imageBaseRelocDirectory = (IMAGE_DATA_DIRECTORY)Marshal.PtrToStructure(
                    pImageBaseRelocDirectory,
                    typeof(IMAGE_DATA_DIRECTORY));
                nBaseRelocEntryOffset = Helpers.ConvertRvaToRawDataOffset(pRawModuleData, imageBaseRelocDirectory.VirtualAddress);

                if (Environment.Is64BitProcess)
                {
                    pImageBaseRelocation = new IntPtr(pRawModuleData.ToInt64() + nBaseRelocEntryOffset);
                    pDifference = new IntPtr(pNewImageBase.ToInt64() - pOriginalImageBase.ToInt64());
                    isRebaseRequired = (pDifference != IntPtr.Zero);
                }
                else
                {
                    pImageBaseRelocation = new IntPtr(pRawModuleData.ToInt32() + (int)nBaseRelocEntryOffset);
                    pDifference = new IntPtr(pNewImageBase.ToInt32() - pOriginalImageBase.ToInt32());
                    isRebaseRequired = (pDifference != IntPtr.Zero);
                }

                if (isRebaseRequired && (imageBaseRelocDirectory.VirtualAddress > 0))
                {
                    imageBaseRelocation = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(
                        pImageBaseRelocation,
                        typeof(IMAGE_BASE_RELOCATION));

                    while (imageBaseRelocation.SizeOfBlock != 0)
                    {
                        nRelocationBlockOffset = Helpers.ConvertRvaToRawDataOffset(pRawModuleData, (uint)imageBaseRelocation.VirtualAddress);
                        nRelocationCount = imageBaseRelocation.SizeOfBlock -
                            (Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)) / Marshal.SizeOf(typeof(IMAGE_RELOC)));

                        if (Environment.Is64BitProcess)
                        {
                            pRelocationBlock = new IntPtr(pRawModuleData.ToInt64() + nRelocationBlockOffset);
                            pImageReloc = new IntPtr(pImageBaseRelocation.ToInt64() + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)));
                        }
                        else
                        {
                            pRelocationBlock = new IntPtr(pRawModuleData.ToInt32() + (int)nRelocationBlockOffset);
                            pImageReloc = new IntPtr(pImageBaseRelocation.ToInt32() + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)));
                        }

                        for (var count = 0; count < nRelocationCount; count++)
                        {
                            imageReloc = (IMAGE_RELOC)Marshal.ReadInt16(pImageReloc, Marshal.SizeOf(typeof(IMAGE_RELOC)) * count);
                            relocOffset = imageReloc & 0xFFF;
                            relocType = (IMAGE_REL_BASED_TYPE)(imageReloc >> 12);

                            if (relocType == IMAGE_REL_BASED_TYPE.DIR64)
                            {
                                if (Environment.Is64BitProcess)
                                    pNewPointer = new IntPtr(Marshal.ReadIntPtr(pRelocationBlock, relocOffset).ToInt64() + pDifference.ToInt64());
                                else
                                    pNewPointer = new IntPtr(Marshal.ReadIntPtr(pRelocationBlock, relocOffset).ToInt32() + pDifference.ToInt32());

                                Marshal.WriteIntPtr(pRelocationBlock, relocOffset, pNewPointer);
                            }
                            else if (relocType == IMAGE_REL_BASED_TYPE.HIGHLOW)
                            {
                                tmpInt32 = Marshal.ReadInt32(pRelocationBlock, relocOffset);
                                tmpInt32 += (int)(pDifference.ToInt64() & 0xFFFFFFFF);
                                Marshal.WriteInt32(pRelocationBlock, relocOffset, tmpInt32);
                            }
                            else if (relocType == IMAGE_REL_BASED_TYPE.HIGH)
                            {
                                tmpInt16 = Marshal.ReadInt16(pRelocationBlock, relocOffset);
                                tmpInt16 += (short)((pDifference.ToInt64() >> 16) & 0xFFFF);
                                Marshal.WriteInt16(pRelocationBlock, relocOffset, tmpInt16);
                            }
                            else if (relocType == IMAGE_REL_BASED_TYPE.LOW)
                            {
                                tmpInt16 = Marshal.ReadInt16(pRelocationBlock, relocOffset);
                                tmpInt16 += (short)(pDifference.ToInt64() & 0xFFFF);
                                Marshal.WriteInt16(pRelocationBlock, relocOffset, tmpInt16);
                            }
                        }

                        if (Environment.Is64BitProcess)
                            pImageBaseRelocation = new IntPtr(pImageBaseRelocation.ToInt64() + imageBaseRelocation.SizeOfBlock);
                        else
                            pImageBaseRelocation = new IntPtr(pImageBaseRelocation.ToInt32() + imageBaseRelocation.SizeOfBlock);

                        imageBaseRelocation = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(
                            pImageBaseRelocation,
                            typeof(IMAGE_BASE_RELOCATION));
                    }
                }

                status = true;
            } while (false);

            return status;
        }


        public static bool BuildDelayImportDirectory(IntPtr pRawModuleData)
        {
            int e_lfanew;
            int nExportDirectoryOffset;
            int nDelayLoadDirectoryOffset;
            int nOrdinalBase;
            uint nDelayLoadDescriptorOffset;
            uint nIntOffset;
            uint nIatOffset;
            uint nNameOffset;
            ushort machine;
            IntPtr pImageDirectory;
            IntPtr pImageDelayLoadDescriptor;
            IntPtr pIntEntry;
            IntPtr pIatEntry;
            IntPtr pImageExportDirectory;
            IntPtr pAddressOfFunctions;
            IntPtr pNameBuffer;
            IntPtr pLibrary;
            IntPtr pProc;
            string procName;
            IMAGE_DATA_DIRECTORY imageDirectory;
            IMAGE_DELAYLOAD_DESCRIPTOR imageDelayLoadDescriptor;
            IMAGE_EXPORT_DIRECTORY imageExportDirectory;
            IMAGE_THUNK_DATA intData;
            bool isOrdinal;
            int nImageDelayLoadDescriptorSize = Marshal.SizeOf(typeof(IMAGE_DELAYLOAD_DESCRIPTOR));
            var status = false;
            var is64Bit = false;

            do
            {
                if (!Helpers.IsValidModule(pRawModuleData))
                    break;

                e_lfanew = Marshal.ReadInt32(pRawModuleData, 0x3C);
                machine = Helpers.GetModuleArchitecture(pRawModuleData);

                if (machine == 0x020B)
                {
                    is64Bit = true;
                    nExportDirectoryOffset = 0x88 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_EXPORT);
                    nDelayLoadDirectoryOffset = 0x88 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
                }
                else if (machine == 0x010B)
                {
                    nExportDirectoryOffset = 0x68 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_EXPORT);
                    nDelayLoadDirectoryOffset = 0x68 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
                }
                else
                {
                    break;
                }

                if (is64Bit && !Environment.Is64BitProcess)
                    throw new InvalidOperationException("To load 64bit module, should be built as 64bit binary");
                else if (!is64Bit && Environment.Is64BitProcess)
                    throw new InvalidOperationException("To load 32bit module, should be built as 32bit binary");

                if (Environment.Is64BitProcess)
                    pImageDirectory = new IntPtr(pRawModuleData.ToInt64() + e_lfanew + nDelayLoadDirectoryOffset);
                else
                    pImageDirectory = new IntPtr(pRawModuleData.ToInt32() + e_lfanew + nDelayLoadDirectoryOffset);

                imageDirectory = (IMAGE_DATA_DIRECTORY)Marshal.PtrToStructure(
                        pImageDirectory,
                        typeof(IMAGE_DATA_DIRECTORY));
                nDelayLoadDescriptorOffset = Helpers.ConvertRvaToRawDataOffset(
                    pRawModuleData,
                    imageDirectory.VirtualAddress);

                if (Environment.Is64BitProcess)
                    pImageDelayLoadDescriptor = new IntPtr(pRawModuleData.ToInt64() + nDelayLoadDescriptorOffset);
                else
                    pImageDelayLoadDescriptor = new IntPtr(pRawModuleData.ToInt32() + (int)nDelayLoadDescriptorOffset);

                imageDelayLoadDescriptor = (IMAGE_DELAYLOAD_DESCRIPTOR)Marshal.PtrToStructure(
                    pImageDelayLoadDescriptor,
                    typeof(IMAGE_DELAYLOAD_DESCRIPTOR));

                while (imageDelayLoadDescriptor.DllNameRVA != 0)
                {
                    nIntOffset = Helpers.ConvertRvaToRawDataOffset(pRawModuleData, (uint)imageDelayLoadDescriptor.ImportNameTableRVA);
                    nIatOffset = Helpers.ConvertRvaToRawDataOffset(pRawModuleData, (uint)imageDelayLoadDescriptor.ImportAddressTableRVA);
                    nNameOffset = Helpers.ConvertRvaToRawDataOffset(pRawModuleData, (uint)imageDelayLoadDescriptor.DllNameRVA);

                    if (Environment.Is64BitProcess)
                    {
                        pIntEntry = new IntPtr(pRawModuleData.ToInt64() + nIntOffset);
                        pIatEntry = new IntPtr(pRawModuleData.ToInt64() + nIatOffset);
                        pNameBuffer = new IntPtr(pRawModuleData.ToInt64() + nNameOffset);
                    }
                    else
                    {
                        pIntEntry = new IntPtr(pRawModuleData.ToInt32() + (int)nIntOffset);
                        pIatEntry = new IntPtr(pRawModuleData.ToInt32() + (int)nIatOffset);
                        pNameBuffer = new IntPtr(pRawModuleData.ToInt32() + (int)nNameOffset);
                    }

                    pLibrary = Helpers.GetModuleHandle(Marshal.PtrToStringAnsi(pNameBuffer));

                    if (pLibrary == IntPtr.Zero)
                    {
                        pLibrary = NativeMethods.LoadLibraryA(Marshal.PtrToStringAnsi(pNameBuffer));

                        if (pLibrary == IntPtr.Zero)
                            break;
                    }

                    while (Marshal.ReadIntPtr(pIatEntry) != IntPtr.Zero)
                    {
                        intData = (IMAGE_THUNK_DATA)Marshal.PtrToStructure(pIntEntry, typeof(IMAGE_THUNK_DATA));

                        if (is64Bit)
                            isOrdinal = (((ulong)intData.Ordinal.ToInt64() & Win32Consts.IMAGE_ORDINAL_FLAG64) != 0);
                        else
                            isOrdinal = (((uint)intData.Ordinal.ToInt32() & Win32Consts.IMAGE_ORDINAL_FLAG32) != 0);

                        if (isOrdinal)
                        {
                            e_lfanew = Marshal.ReadInt32(pLibrary, 0x3C);

                            if (Environment.Is64BitProcess)
                                pImageDirectory = new IntPtr(pLibrary.ToInt64() + e_lfanew + nExportDirectoryOffset);
                            else
                                pImageDirectory = new IntPtr(pLibrary.ToInt32() + e_lfanew + nExportDirectoryOffset);

                            imageDirectory = (IMAGE_DATA_DIRECTORY)Marshal.PtrToStructure(
                                pImageDirectory,
                                typeof(IMAGE_DATA_DIRECTORY));

                            if (Environment.Is64BitProcess)
                                pImageExportDirectory = new IntPtr(pLibrary.ToInt64() + imageDirectory.VirtualAddress);
                            else
                                pImageExportDirectory = new IntPtr(pLibrary.ToInt32() + (int)imageDirectory.VirtualAddress);

                            imageExportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                                pImageExportDirectory,
                                typeof(IMAGE_EXPORT_DIRECTORY));
                            nOrdinalBase = (int)((intData.Ordinal.ToInt64() & 0xFFFF) - imageExportDirectory.Base);

                            if (Environment.Is64BitProcess)
                            {
                                pAddressOfFunctions = new IntPtr(pLibrary.ToInt64() + imageExportDirectory.AddressOfFunctions);
                                pProc = new IntPtr(pLibrary.ToInt64() + Marshal.ReadInt32(pAddressOfFunctions, nOrdinalBase * 4));
                            }
                            else
                            {
                                pAddressOfFunctions = new IntPtr(pLibrary.ToInt32() + imageExportDirectory.AddressOfFunctions);
                                pProc = new IntPtr(pLibrary.ToInt32() + Marshal.ReadInt32(pAddressOfFunctions, nOrdinalBase * 4));
                            }

                            Marshal.WriteIntPtr(pIatEntry, pProc);
                        }
                        else
                        {
                            // PIMAGE_IMPORT_BY_NAME
                            pNameBuffer = Helpers.ConvertRvaToRawDataPointer(pRawModuleData, intData.AddressOfData);

                            // &PIMAGE_IMPORT_BY_NAME->Name
                            if (Environment.Is64BitProcess)
                                pNameBuffer = new IntPtr(pNameBuffer.ToInt64() + 2);
                            else
                                pNameBuffer = new IntPtr(pNameBuffer.ToInt32() + 2);

                            procName = Marshal.PtrToStringAnsi(pNameBuffer);
                            pProc = NativeMethods.GetProcAddress(pLibrary, procName);
                            Marshal.WriteIntPtr(pIatEntry, pProc);
                        }

                        if (Environment.Is64BitProcess)
                        {
                            pIatEntry = new IntPtr(pIatEntry.ToInt64() + IntPtr.Size);
                            pIntEntry = new IntPtr(pIntEntry.ToInt64() + IntPtr.Size);
                        }
                        else
                        {
                            pIatEntry = new IntPtr(pIatEntry.ToInt32() + IntPtr.Size);
                            pIntEntry = new IntPtr(pIntEntry.ToInt32() + IntPtr.Size);
                        }
                    }

                    if (Environment.Is64BitProcess)
                        pImageDelayLoadDescriptor = new IntPtr(pImageDelayLoadDescriptor.ToInt64() + nImageDelayLoadDescriptorSize);
                    else
                        pImageDelayLoadDescriptor = new IntPtr(pImageDelayLoadDescriptor.ToInt32() + nImageDelayLoadDescriptorSize);

                    imageDelayLoadDescriptor = (IMAGE_DELAYLOAD_DESCRIPTOR)Marshal.PtrToStructure(
                        pImageDelayLoadDescriptor,
                        typeof(IMAGE_DELAYLOAD_DESCRIPTOR));
                }

                status = true;
            } while (false);

            return status;
        }


        public static bool BuildImportDirectory(IntPtr pRawModuleData)
        {
            int e_lfanew;
            int nExportDirectoryOffset;
            int nImportDirectoryOffset;
            int nOrdinalBase;
            uint nImportDescriptorOffset;
            uint nIntOffset;
            uint nIatOffset;
            uint nNameOffset;
            ushort machine;
            IntPtr pImageDirectory;
            IntPtr pImageImportDescriptor;
            IntPtr pIntEntry;
            IntPtr pIatEntry;
            IntPtr pImageExportDirectory;
            IntPtr pAddressOfFunctions;
            IntPtr pNameBuffer;
            IntPtr pLibrary;
            IntPtr pProc;
            string procName;
            IMAGE_DATA_DIRECTORY imageDirectory;
            IMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
            IMAGE_EXPORT_DIRECTORY imageExportDirectory;
            IMAGE_THUNK_DATA intData;
            IMAGE_THUNK_DATA iatData;
            bool isOrdinal;
            int nImageImportDescriptorSize = Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
            var status = false;
            var is64Bit = false;

            do
            {
                if (!Helpers.IsValidModule(pRawModuleData))
                    break;

                e_lfanew = Marshal.ReadInt32(pRawModuleData, 0x3C);
                machine = Helpers.GetModuleArchitecture(pRawModuleData);

                if (machine == 0x020B)
                {
                    is64Bit = true;
                    nExportDirectoryOffset = 0x88 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_EXPORT);
                    nImportDirectoryOffset = 0x88 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_IMPORT);
                }
                else if (machine == 0x010B)
                {
                    nExportDirectoryOffset = 0x68 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_EXPORT);
                    nImportDirectoryOffset = 0x68 + (8 * Win32Consts.IMAGE_DIRECTORY_ENTRY_IMPORT);
                }
                else
                {
                    break;
                }

                if (is64Bit && !Environment.Is64BitProcess)
                    throw new InvalidOperationException("To load 64bit module, should be built as 64bit binary");
                else if (!is64Bit && Environment.Is64BitProcess)
                    throw new InvalidOperationException("To load 32bit module, should be built as 32bit binary");

                if (Environment.Is64BitProcess)
                    pImageDirectory = new IntPtr(pRawModuleData.ToInt64() + e_lfanew + nImportDirectoryOffset);
                else
                    pImageDirectory = new IntPtr(pRawModuleData.ToInt32() + e_lfanew + nImportDirectoryOffset);

                imageDirectory = (IMAGE_DATA_DIRECTORY)Marshal.PtrToStructure(
                        pImageDirectory,
                        typeof(IMAGE_DATA_DIRECTORY));
                nImportDescriptorOffset = Helpers.ConvertRvaToRawDataOffset(
                    pRawModuleData,
                    imageDirectory.VirtualAddress);

                if (Environment.Is64BitProcess)
                    pImageImportDescriptor = new IntPtr(pRawModuleData.ToInt64() + nImportDescriptorOffset);
                else
                    pImageImportDescriptor = new IntPtr(pRawModuleData.ToInt32() + (int)nImportDescriptorOffset);

                imageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                    pImageImportDescriptor,
                    typeof(IMAGE_IMPORT_DESCRIPTOR));

                while (imageImportDescriptor.Name != 0)
                {
                    nIntOffset = Helpers.ConvertRvaToRawDataOffset(pRawModuleData, imageImportDescriptor.OriginalFirstThunk);
                    nIatOffset = Helpers.ConvertRvaToRawDataOffset(pRawModuleData, imageImportDescriptor.FirstThunk);
                    nNameOffset = Helpers.ConvertRvaToRawDataOffset(pRawModuleData, imageImportDescriptor.Name);

                    if (Environment.Is64BitProcess)
                    {
                        pIntEntry = new IntPtr(pRawModuleData.ToInt64() + nIntOffset);
                        pIatEntry = new IntPtr(pRawModuleData.ToInt64() + nIatOffset);
                        pNameBuffer = new IntPtr(pRawModuleData.ToInt64() + nNameOffset);
                    }
                    else
                    {
                        pIntEntry = new IntPtr(pRawModuleData.ToInt32() + (int)nIntOffset);
                        pIatEntry = new IntPtr(pRawModuleData.ToInt32() + (int)nIatOffset);
                        pNameBuffer = new IntPtr(pRawModuleData.ToInt32() + (int)nNameOffset);
                    }

                    pLibrary = Helpers.GetModuleHandle(Marshal.PtrToStringAnsi(pNameBuffer));

                    if (pLibrary == IntPtr.Zero)
                    {
                        pLibrary = NativeMethods.LoadLibraryA(Marshal.PtrToStringAnsi(pNameBuffer));

                        if (pLibrary == IntPtr.Zero)
                            break;
                    }

                    while (Marshal.ReadIntPtr(pIatEntry) != IntPtr.Zero)
                    {
                        intData = (IMAGE_THUNK_DATA)Marshal.PtrToStructure(pIntEntry, typeof(IMAGE_THUNK_DATA));
                        iatData = (IMAGE_THUNK_DATA)Marshal.PtrToStructure(pIatEntry, typeof(IMAGE_THUNK_DATA));

                        if (Environment.Is64BitProcess)
                            isOrdinal = (((ulong)intData.Ordinal.ToInt64() & Win32Consts.IMAGE_ORDINAL_FLAG64) != 0);
                        else
                            isOrdinal = (((uint)intData.Ordinal.ToInt32() & Win32Consts.IMAGE_ORDINAL_FLAG32) != 0);

                        if (isOrdinal)
                        {
                            e_lfanew = Marshal.ReadInt32(pLibrary, 0x3C);

                            if (Environment.Is64BitProcess)
                                pImageDirectory = new IntPtr(pLibrary.ToInt64() + e_lfanew + nExportDirectoryOffset);
                            else
                                pImageDirectory = new IntPtr(pLibrary.ToInt32() + e_lfanew + nExportDirectoryOffset);

                            imageDirectory = (IMAGE_DATA_DIRECTORY)Marshal.PtrToStructure(
                                pImageDirectory,
                                typeof(IMAGE_DATA_DIRECTORY));

                            if (Environment.Is64BitProcess)
                                pImageExportDirectory = new IntPtr(pLibrary.ToInt64() + imageDirectory.VirtualAddress);
                            else
                                pImageExportDirectory = new IntPtr(pLibrary.ToInt32() + (int)imageDirectory.VirtualAddress);

                            imageExportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                                pImageExportDirectory,
                                typeof(IMAGE_EXPORT_DIRECTORY));
                            nOrdinalBase = (int)((intData.Ordinal.ToInt64() & 0xFFFF) - imageExportDirectory.Base);

                            if (Environment.Is64BitProcess)
                            {
                                pAddressOfFunctions = new IntPtr(pLibrary.ToInt64() + imageExportDirectory.AddressOfFunctions);
                                pProc = new IntPtr(pLibrary.ToInt64() + Marshal.ReadInt32(pAddressOfFunctions, nOrdinalBase * 4));
                            }
                            else
                            {
                                pAddressOfFunctions = new IntPtr(pLibrary.ToInt32() + imageExportDirectory.AddressOfFunctions);
                                pProc = new IntPtr(pLibrary.ToInt32() + Marshal.ReadInt32(pAddressOfFunctions, nOrdinalBase * 4));
                            }

                            Marshal.WriteIntPtr(pIatEntry, pProc);
                        }
                        else
                        {
                            // PIMAGE_IMPORT_BY_NAME
                            pNameBuffer = Helpers.ConvertRvaToRawDataPointer(pRawModuleData, iatData.AddressOfData);

                            // &PIMAGE_IMPORT_BY_NAME->Name
                            if (Environment.Is64BitProcess)
                                pNameBuffer = new IntPtr(pNameBuffer.ToInt64() + 2);
                            else
                                pNameBuffer = new IntPtr(pNameBuffer.ToInt32() + 2);

                            procName = Marshal.PtrToStringAnsi(pNameBuffer);
                            pProc = NativeMethods.GetProcAddress(pLibrary, procName);
                            Marshal.WriteIntPtr(pIatEntry, pProc);
                        }

                        if (Environment.Is64BitProcess)
                        {
                            pIatEntry = new IntPtr(pIatEntry.ToInt64() + IntPtr.Size);
                            pIntEntry = new IntPtr(pIntEntry.ToInt64() + IntPtr.Size);
                        }
                        else
                        {
                            pIatEntry = new IntPtr(pIatEntry.ToInt32() + IntPtr.Size);
                            pIntEntry = new IntPtr(pIntEntry.ToInt32() + IntPtr.Size);
                        }
                    }

                    if (Environment.Is64BitProcess)
                        pImageImportDescriptor = new IntPtr(pImageImportDescriptor.ToInt64() + nImageImportDescriptorSize);
                    else
                        pImageImportDescriptor = new IntPtr(pImageImportDescriptor.ToInt32() + nImageImportDescriptorSize);

                    imageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                        pImageImportDescriptor,
                        typeof(IMAGE_IMPORT_DESCRIPTOR));
                }

                status = true;
            } while (false);

            return status;
        }


        public static bool LinkModuleToPEB(IntPtr pDllBase, string fullDllPath, string dllFileName)
        {
            IntPtr pEntryPoint;
            IntPtr pPeb = Helpers.GetPebAddress(Process.GetCurrentProcess().Handle);
            int nNodeModuleLinkOffset = Marshal.OffsetOf(typeof(LDR_DATA_TABLE_ENTRY), "NodeModuleLink").ToInt32();
            int nLdrDataTableEntrySize = Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY));
            int e_lfanew = Marshal.ReadInt32(pDllBase, 0x3C);
            var nTimeDateStamp = (uint)Marshal.ReadInt32(pDllBase, e_lfanew + 0x8);
            var nEntryPointOffset = (uint)Marshal.ReadInt32(pDllBase, e_lfanew + 0x10);
            var pImageBase = Environment.Is64BitProcess ? Marshal.ReadIntPtr(pDllBase, e_lfanew + 0x30) : Marshal.ReadIntPtr(pDllBase, e_lfanew + 0x34);
            var nSizeOfImage = (uint)Marshal.ReadInt32(pDllBase, e_lfanew + 0x50);
            var ldrEntry = new LDR_DATA_TABLE_ENTRY
            {
                DllBase = pDllBase,
                SizeOfImage = nSizeOfImage,
                FullDllName = new UNICODE_STRING(fullDllPath),
                BaseDllName = new UNICODE_STRING(dllFileName),
                ObsoleteLoadCount = 1,
                TimeDateStamp = nTimeDateStamp,
                OriginalBase = pImageBase,
                LoadReason = LDR_DLL_LOAD_REASON.DynamicLoad,
                ReferenceCount = 1
            };
            var ddagNode = new LDR_DDAG_NODE
            {
                State = LDR_DDAG_STATE.LdrModulesReadyToRun,
                LoadCount = 1
            };
            var pLdrEntry = IntPtr.Zero;
            var status = false;

            if (Environment.Is64BitProcess)
                pEntryPoint = new IntPtr(pDllBase.ToInt64() + nEntryPointOffset);
            else
                pEntryPoint = new IntPtr(pDllBase.ToInt32() + (int)nEntryPointOffset);

            if (Environment.Is64BitProcess)
                nLdrDataTableEntrySize += 0x10; // Add size for extra members in 64bit struct

            NativeMethods.NtQuerySystemTime(out LARGE_INTEGER systemTime);
            ldrEntry.EntryPoint = pEntryPoint;
            ldrEntry.BaseNameHashValue = Helpers.LdrHashEntry(ldrEntry.BaseDllName, false);
            ldrEntry.LoadTime.QuadPart = systemTime.QuadPart;
            ldrEntry.Flags = LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_IMAGE_DLL;
            ldrEntry.Flags |= LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_ENTRY_PROCESSED;
            ldrEntry.Flags |= LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_PROTECT_DELAY_LOAD;
            ldrEntry.Flags |= LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_PROCESS_ATTACH_CALLED;

            try
            {
                pLdrEntry = Marshal.AllocHGlobal(nLdrDataTableEntrySize);
                Helpers.ZeroMemory(pLdrEntry, nLdrDataTableEntrySize);

                ldrEntry.DdagNode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LDR_DDAG_NODE)));
                ldrEntry.NodeModuleLink.Flink = ldrEntry.DdagNode; // &LDR_DDAG_NODE.Modules
                ldrEntry.NodeModuleLink.Blink = ldrEntry.DdagNode; // &LDR_DDAG_NODE.Modules

                if (Environment.Is64BitProcess)
                {
                    ddagNode.Modules.Flink = new IntPtr(pLdrEntry.ToInt64() + nNodeModuleLinkOffset);
                    ddagNode.Modules.Blink = new IntPtr(pLdrEntry.ToInt64() + nNodeModuleLinkOffset);
                }
                else
                {
                    ddagNode.Modules.Flink = new IntPtr(pLdrEntry.ToInt32() + nNodeModuleLinkOffset);
                    ddagNode.Modules.Blink = new IntPtr(pLdrEntry.ToInt32() + nNodeModuleLinkOffset);
                }

                Marshal.StructureToPtr(ddagNode, ldrEntry.DdagNode, true);
                Marshal.StructureToPtr(ldrEntry, pLdrEntry, true);
                Helpers.AddBaseAddressEntry(pPeb, pLdrEntry, pDllBase);
                Helpers.AddHashTableEntry(pLdrEntry);
                status = true;
            }
            catch
            {
                if (ldrEntry.DdagNode != IntPtr.Zero)
                    Marshal.FreeHGlobal(ldrEntry.DdagNode);

                if (pLdrEntry != IntPtr.Zero)
                    Marshal.FreeHGlobal(pLdrEntry);
            }

            return status;
        }


        public static IntPtr MapImageData(IntPtr pSourceData)
        {
            NTSTATUS ntstatus;
            int e_lfanew;
            int nSectionOffset;
            ushort machine;
            ushort nNumberOfSections;
            ushort nSizeOfOptionalHeader;
            uint nSizeOfImage;
            uint nSizeOfHeaders;
            uint nNumberOfBytesToProtect;
            IntPtr pOriginalImageBase;
            IntPtr pSectionHeader;
            IntPtr pSectionHeaderBase;
            IntPtr pSectionBaseOfRawData;
            IntPtr pSectionBaseOfParsedData;
            IMAGE_SECTION_HEADER sectionHeader;
            MEMORY_PROTECTION newProtection;
            int nSectionHeaderSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            var nRegionSize = SIZE_T.Zero;
            var pImageBase = IntPtr.Zero;
            var status = false;

            do
            {
                if (!Helpers.IsValidModule(pSourceData))
                    break;

                e_lfanew = Marshal.ReadInt32(pSourceData, 0x3C);
                machine = Helpers.GetModuleArchitecture(pSourceData);
                nNumberOfSections = (ushort)Marshal.ReadInt16(pSourceData, e_lfanew + 0x6);
                nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pSourceData, e_lfanew + 0x14);
                nSizeOfImage = (uint)Marshal.ReadInt32(pSourceData, e_lfanew + 0x50);
                nSizeOfHeaders = (uint)Marshal.ReadInt32(pSourceData, e_lfanew + 0x54);
                nSectionOffset = e_lfanew + 0x18 + nSizeOfOptionalHeader;
                nRegionSize = new SIZE_T(nSizeOfImage);

                if (machine == 0x020B)
                    pOriginalImageBase = Marshal.ReadIntPtr(pSourceData, e_lfanew + 0x30);
                else if (machine == 0x010B)
                    pOriginalImageBase = Marshal.ReadIntPtr(pSourceData, e_lfanew + 0x34);
                else
                    break;

                if (Environment.Is64BitProcess)
                    pSectionHeaderBase = new IntPtr(pSourceData.ToInt64() + nSectionOffset);
                else
                    pSectionHeaderBase = new IntPtr(pSourceData.ToInt32() + nSectionOffset);

                pImageBase = pOriginalImageBase;
                ntstatus = NativeMethods.NtAllocateVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref pImageBase,
                    UIntPtr.Zero,
                    ref nRegionSize,
                    ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                    MEMORY_PROTECTION.EXECUTE_READWRITE);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                {
                    pImageBase = IntPtr.Zero;
                    ntstatus = NativeMethods.NtAllocateVirtualMemory(
                        Process.GetCurrentProcess().Handle,
                        ref pImageBase,
                        UIntPtr.Zero,
                        ref nRegionSize,
                        ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                        MEMORY_PROTECTION.EXECUTE_READWRITE);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        pImageBase = IntPtr.Zero;
                        break;
                    }
                }

                // Update image directories
                if (!BuildImportDirectory(pSourceData))
                    break;

                if (!BuildDelayImportDirectory(pSourceData))
                    break;

                if (!BuildBaseRelocDirectory(pSourceData, pImageBase))
                    break;

                // Copy file header data
                Helpers.CopyMemory(pImageBase, pSourceData, nSizeOfHeaders);

                // Copy section Data
                for (var index = 0; index < nNumberOfSections; index++)
                {
                    if (Environment.Is64BitProcess)
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt64() + (index * nSectionHeaderSize));
                    else
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt32() + (index * nSectionHeaderSize));

                    sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pSectionHeader,
                        typeof(IMAGE_SECTION_HEADER));
                    nNumberOfBytesToProtect = sectionHeader.SizeOfRawData;

                    if (Environment.Is64BitProcess)
                    {
                        pSectionBaseOfRawData = new IntPtr(pSourceData.ToInt64() + sectionHeader.PointerToRawData);
                        pSectionBaseOfParsedData = new IntPtr(pImageBase.ToInt64() + sectionHeader.VirtualAddress);
                    }
                    else
                    {
                        pSectionBaseOfRawData = new IntPtr(pSourceData.ToInt32() + (int)sectionHeader.PointerToRawData);
                        pSectionBaseOfParsedData = new IntPtr(pImageBase.ToInt32() + (int)sectionHeader.VirtualAddress);
                    }

                    Helpers.CopyMemory(pSectionBaseOfParsedData, pSectionBaseOfRawData, nNumberOfBytesToProtect);

                    if (((sectionHeader.Characteristics & SectionFlags.MEM_EXECUTE) != 0u) &&
                        ((sectionHeader.Characteristics & SectionFlags.MEM_READ) != 0u) &&
                        ((sectionHeader.Characteristics & SectionFlags.MEM_WRITE) != 0u))
                    {
                        newProtection = MEMORY_PROTECTION.EXECUTE_READWRITE;
                    }
                    else if (((sectionHeader.Characteristics & SectionFlags.MEM_EXECUTE) != 0u) &&
                        ((sectionHeader.Characteristics & SectionFlags.MEM_READ) != 0u))
                    {
                        newProtection = MEMORY_PROTECTION.EXECUTE_READ;
                    }
                    else if (((sectionHeader.Characteristics & SectionFlags.MEM_READ) != 0u) &&
                        ((sectionHeader.Characteristics & SectionFlags.MEM_WRITE) != 0u))
                    {
                        newProtection = MEMORY_PROTECTION.READWRITE;
                    }
                    else if (((sectionHeader.Characteristics & SectionFlags.MEM_EXECUTE) != 0u) &&
                        ((sectionHeader.Characteristics & SectionFlags.MEM_WRITE) != 0u))
                    {
                        newProtection = MEMORY_PROTECTION.EXECUTE_WRITECOPY;
                    }
                    else if ((sectionHeader.Characteristics & SectionFlags.MEM_EXECUTE) != 0u)
                    {
                        newProtection = MEMORY_PROTECTION.EXECUTE;
                    }
                    else if ((sectionHeader.Characteristics & SectionFlags.MEM_READ) != 0u)
                    {
                        newProtection = MEMORY_PROTECTION.READONLY;
                    }
                    else if ((sectionHeader.Characteristics & SectionFlags.MEM_WRITE) != 0u)
                    {
                        newProtection = MEMORY_PROTECTION.WRITECOPY;
                    }
                    else
                    {
                        newProtection = MEMORY_PROTECTION.NOACCESS;
                    }

                    if ((sectionHeader.Characteristics & SectionFlags.MEM_NOT_CACHED) != 0)
                        newProtection |= MEMORY_PROTECTION.NOCACHE;

                    ntstatus = NativeMethods.NtProtectVirtualMemory(
                        Process.GetCurrentProcess().Handle,
                        ref pSectionBaseOfParsedData,
                        ref nNumberOfBytesToProtect,
                        newProtection,
                        out MEMORY_PROTECTION _);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                        break;
                }

                status = (ntstatus == Win32Consts.STATUS_SUCCESS);
            } while (false);

            if (!status && (pImageBase != IntPtr.Zero))
            {
                NativeMethods.NtFreeVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref pImageBase,
                    ref nRegionSize,
                    ALLOCATION_TYPE.RELEASE);
                pImageBase = IntPtr.Zero;
            }

            return pImageBase;
        }
    }
}
