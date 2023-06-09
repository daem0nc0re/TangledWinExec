using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DarkLibraryLoader.Interop;

namespace DarkLibraryLoader.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static bool AddBaseAddressEntry(
            IntPtr pPeb,
            IntPtr pLdrDataTableEntry,
            IntPtr pBaseAddress)
        {
            long nDifference;
            IntPtr pLdrDataTableNode;
            IntPtr pParent;
            IntPtr pNode;
            LDR_DATA_TABLE_ENTRY ldrDataTableNode;
            int nBaseAddressIndexNodeOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "BaseAddressIndexNode").ToInt32();
            var right = BOOLEAN.FALSE;
            var status = false;
            IntPtr pRbTree = FindModuleBaseAddressIndex(pPeb);

            if (pRbTree == IntPtr.Zero)
                return status;

            if (Environment.Is64BitProcess)
                pLdrDataTableNode = new IntPtr(pRbTree.ToInt64() - nBaseAddressIndexNodeOffset);
            else
                pLdrDataTableNode = new IntPtr(pRbTree.ToInt32() - nBaseAddressIndexNodeOffset);

            do
            {
                ldrDataTableNode = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(
                    pLdrDataTableNode,
                    typeof(LDR_DATA_TABLE_ENTRY));
                nDifference = pBaseAddress.ToInt64() - ldrDataTableNode.DllBase.ToInt64();

                if (nDifference < 0)
                {
                    if (ldrDataTableNode.BaseAddressIndexNode.Left == IntPtr.Zero)
                        break;

                    if (Environment.Is64BitProcess)
                        pLdrDataTableNode = new IntPtr(ldrDataTableNode.BaseAddressIndexNode.Left.ToInt64() - nBaseAddressIndexNodeOffset);
                    else
                        pLdrDataTableNode = new IntPtr(ldrDataTableNode.BaseAddressIndexNode.Left.ToInt32() - nBaseAddressIndexNodeOffset);
                }
                else if (nDifference > 0)
                {
                    if (ldrDataTableNode.BaseAddressIndexNode.Right == IntPtr.Zero)
                    {
                        right = BOOLEAN.TRUE;
                        break;
                    }

                    if (Environment.Is64BitProcess)
                        pLdrDataTableNode = new IntPtr(ldrDataTableNode.BaseAddressIndexNode.Right.ToInt64() - nBaseAddressIndexNodeOffset);
                    else
                        pLdrDataTableNode = new IntPtr(ldrDataTableNode.BaseAddressIndexNode.Right.ToInt32() - nBaseAddressIndexNodeOffset);
                }
                else
                {
                    break;
                }
            } while (true);

            if (Environment.Is64BitProcess)
            {
                pParent = new IntPtr(pLdrDataTableNode.ToInt64() + nBaseAddressIndexNodeOffset);
                pNode = new IntPtr(pLdrDataTableEntry.ToInt64() + nBaseAddressIndexNodeOffset);
            }
            else
            {

                pParent = new IntPtr(pLdrDataTableNode.ToInt32() + nBaseAddressIndexNodeOffset);
                pNode = new IntPtr(pLdrDataTableEntry.ToInt32() + nBaseAddressIndexNodeOffset);
            }

            NativeMethods.RtlRbInsertNodeEx(pRbTree, pParent, right, pNode);

            return status;
        }


        public static bool AddHashTableEntry(IntPtr pNewLdrEntry)
        {
            PEB_PARTIAL peb;
            LDR_DATA_TABLE_ENTRY ldrDataTable;
            IntPtr pHashTable; // PLIST_ENTRY
            IntPtr pHashTableTail; // PLIST_ENTRY
            IntPtr pLdrLoadOrderList;
            IntPtr pLdrMemoryOrderList;
            IntPtr pLdrInitOrderList;
            IntPtr pLdrDataLoadOrderList;
            IntPtr pLdrDataMemoryOrderList;
            IntPtr pLdrDataInitOrderList;
            IntPtr pNewHashLinks;
            uint hash;
            int nLdrLoadOrderListOffset = Marshal.OffsetOf(
                typeof(PEB_LDR_DATA),
                "InLoadOrderModuleList").ToInt32();
            int nLdrMemoryOrderListOffset = Marshal.OffsetOf(
                typeof(PEB_LDR_DATA),
                "InMemoryOrderModuleList").ToInt32();
            int nLdrInitOrderListOffset = Marshal.OffsetOf(
                typeof(PEB_LDR_DATA),
                "InInitializationOrderModuleList").ToInt32();
            int nLdrDataLoadOrderListOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "InLoadOrderLinks").ToInt32();
            int nLdrDataMemoryOrderListOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "InMemoryOrderLinks").ToInt32();
            int nLdrDataInitOrderListOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "InInitializationOrderLinks").ToInt32();
            int nHashLinksOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "HashLinks").ToInt32();
            bool status = false;
            IntPtr pPeb = GetPebAddress(Process.GetCurrentProcess().Handle);

            do
            {
                if (pPeb == IntPtr.Zero)
                    break;

                peb = (PEB_PARTIAL)Marshal.PtrToStructure(pPeb, typeof(PEB_PARTIAL));

                pHashTable = FindHashTable(pPeb);

                if (pHashTable == IntPtr.Zero)
                    break;

                ldrDataTable = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(
                    pNewLdrEntry,
                    typeof(LDR_DATA_TABLE_ENTRY));
                hash = LdrHashEntry(ldrDataTable.BaseDllName, true);

                if (Environment.Is64BitProcess)
                {
                    pHashTableTail = new IntPtr(pHashTable.ToInt64() + (hash * Marshal.SizeOf(typeof(LIST_ENTRY))));
                    pLdrLoadOrderList = new IntPtr(peb.Ldr.ToInt64() + nLdrLoadOrderListOffset);
                    pLdrMemoryOrderList = new IntPtr(peb.Ldr.ToInt64() + nLdrMemoryOrderListOffset);
                    pLdrInitOrderList = new IntPtr(peb.Ldr.ToInt64() + nLdrInitOrderListOffset);
                    pLdrDataLoadOrderList = new IntPtr(pNewLdrEntry.ToInt64() + nLdrDataLoadOrderListOffset);
                    pLdrDataMemoryOrderList = new IntPtr(pNewLdrEntry.ToInt64() + nLdrDataMemoryOrderListOffset);
                    pLdrDataInitOrderList = new IntPtr(pNewLdrEntry.ToInt64() + nLdrDataInitOrderListOffset);
                    pNewHashLinks = new IntPtr(pNewLdrEntry.ToInt64() + nHashLinksOffset);
                }
                else
                {
                    pHashTableTail = new IntPtr(pHashTable.ToInt32() + (hash * Marshal.SizeOf(typeof(LIST_ENTRY))));
                    pLdrLoadOrderList = new IntPtr(peb.Ldr.ToInt32() + nLdrLoadOrderListOffset);
                    pLdrMemoryOrderList = new IntPtr(peb.Ldr.ToInt32() + nLdrMemoryOrderListOffset);
                    pLdrInitOrderList = new IntPtr(peb.Ldr.ToInt32() + nLdrInitOrderListOffset);
                    pLdrDataLoadOrderList = new IntPtr(pNewLdrEntry.ToInt32() + nLdrDataLoadOrderListOffset);
                    pLdrDataMemoryOrderList = new IntPtr(pNewLdrEntry.ToInt32() + nLdrDataMemoryOrderListOffset);
                    pLdrDataInitOrderList = new IntPtr(pNewLdrEntry.ToInt32() + nLdrDataInitOrderListOffset);
                    pNewHashLinks = new IntPtr(pNewLdrEntry.ToInt32() + nHashLinksOffset);
                }

                InsertTailList(pHashTableTail, pNewHashLinks);
                InsertTailList(pLdrLoadOrderList, pLdrDataLoadOrderList);
                InsertTailList(pLdrMemoryOrderList, pLdrDataMemoryOrderList);
                InsertTailList(pLdrInitOrderList, pLdrDataInitOrderList);
                status = true;
            } while (false);

            return status;
        }


        public static bool CompareIgnoreCase(string strA, string strB)
        {
            return (string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase) == 0);
        }


        public static bool CompareMemory(IntPtr pData1, IntPtr pData2, int nCompareSize)
        {
            var status = true;

            for (var offset = 0; offset < nCompareSize; offset++)
            {
                if (Marshal.ReadByte(pData1, offset) != Marshal.ReadByte(pData2, offset))
                {
                    status = false;
                    break;
                }
            }

            return status;
        }


        public static uint ConvertRvaToRawDataOffset(IntPtr pModuleBase, uint nVirtualAddress)
        {
            int e_lfanew;
            int nSectionOffset;
            uint nDifference;
            ushort nNumberOfSections;
            ushort nSizeOfOptionalHeader;
            IntPtr pSectionHeader;
            IntPtr pSectionHeaderBase;
            IMAGE_SECTION_HEADER sectionHeader;
            uint nPointerToRawData = 0;
            int nSectionHeaderSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

            do
            {
                if (!IsValidModule(pModuleBase))
                    break;

                e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);
                nNumberOfSections = (ushort)Marshal.ReadInt16(pModuleBase, e_lfanew + 0x6);
                nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pModuleBase, e_lfanew + 0x14);
                nSectionOffset = e_lfanew + 0x18 + nSizeOfOptionalHeader;

                if (Environment.Is64BitProcess)
                    pSectionHeaderBase = new IntPtr(pModuleBase.ToInt64() + nSectionOffset);
                else
                    pSectionHeaderBase = new IntPtr(pModuleBase.ToInt32() + nSectionOffset);

                for (var index = 0; index < nNumberOfSections; index++)
                {
                    if (Environment.Is64BitProcess)
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt64() + (index * nSectionHeaderSize));
                    else
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt32() + (index * nSectionHeaderSize));

                    sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pSectionHeader,
                        typeof(IMAGE_SECTION_HEADER));

                    if ((nVirtualAddress >= sectionHeader.VirtualAddress) &&
                        (nVirtualAddress <= (sectionHeader.VirtualAddress + sectionHeader.VirtualSize)))
                    {
                        nDifference = sectionHeader.VirtualAddress - sectionHeader.PointerToRawData;
                        nPointerToRawData = nVirtualAddress - nDifference;
                        break;
                    }
                }
            } while (false);

            return nPointerToRawData;
        }


        public static IntPtr ConvertRvaToRawDataPointer(IntPtr pModuleBase, IntPtr pVirtualAddress)
        {
            int e_lfanew;
            int nSectionOffset;
            uint nDifference;
            ushort nNumberOfSections;
            ushort nSizeOfOptionalHeader;
            IntPtr pSectionHeader;
            IntPtr pSectionHeaderBase;
            IMAGE_SECTION_HEADER sectionHeader;
            int nSectionHeaderSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            var pRawDataPointer = IntPtr.Zero;

            do
            {
                if (!IsValidModule(pModuleBase))
                    break;

                e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);
                nNumberOfSections = (ushort)Marshal.ReadInt16(pModuleBase, e_lfanew + 0x6);
                nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pModuleBase, e_lfanew + 0x14);
                nSectionOffset = e_lfanew + 0x18 + nSizeOfOptionalHeader;

                if (Environment.Is64BitProcess)
                    pSectionHeaderBase = new IntPtr(pModuleBase.ToInt64() + nSectionOffset);
                else
                    pSectionHeaderBase = new IntPtr(pModuleBase.ToInt32() + nSectionOffset);

                for (var index = 0; index < nNumberOfSections; index++)
                {
                    if (Environment.Is64BitProcess)
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt64() + (index * nSectionHeaderSize));
                    else
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt32() + (index * nSectionHeaderSize));

                    sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pSectionHeader,
                        typeof(IMAGE_SECTION_HEADER));

                    if ((pVirtualAddress.ToInt64() >= (long)sectionHeader.VirtualAddress) &&
                        (pVirtualAddress.ToInt64() <= (long)(sectionHeader.VirtualAddress + sectionHeader.VirtualSize)))
                    {
                        nDifference = sectionHeader.VirtualAddress - sectionHeader.PointerToRawData;

                        if (Environment.Is64BitProcess)
                            pRawDataPointer = new IntPtr(pModuleBase.ToInt64() + pVirtualAddress.ToInt64() - nDifference);
                        else
                            pRawDataPointer = new IntPtr(pModuleBase.ToInt32() + pVirtualAddress.ToInt32() - (int)nDifference);

                        break;
                    }
                }
            } while (false);

            return pRawDataPointer;
        }


        public static void CopyMemory(IntPtr pDestination, IntPtr pSource, uint nSize)
        {
            for (var offset = 0; offset < nSize; offset++)
                Marshal.WriteByte(pDestination, offset, Marshal.ReadByte(pSource, offset));
        }


        public static IntPtr FindHashTable(IntPtr pPeb)
        {
            PEB_PARTIAL peb;
            PEB_LDR_DATA ldrData;
            LDR_DATA_TABLE_ENTRY ldrDataTable;
            IntPtr pHeadList; // PLIST_ENTRY
            IntPtr pEntry; // PLIST_ENTRY
            IntPtr pCurrentEntry;
            IntPtr pHashLink;
            uint hash;
            int nHashLinkOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "HashLinks").ToInt32();
            int nInitOrderListOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "InInitializationOrderLinks").ToInt32();
            IntPtr pListEntry = IntPtr.Zero; // PLIST_ENTRY

            if (pPeb == IntPtr.Zero)
                return IntPtr.Zero;

            peb = (PEB_PARTIAL)Marshal.PtrToStructure(pPeb, typeof(PEB_PARTIAL));
            ldrData = (PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(PEB_LDR_DATA));
            pHeadList = ldrData.InInitializationOrderModuleList.Flink;
            pEntry = Marshal.ReadIntPtr(pHeadList); // pHeadList->Flink

            do
            {
                if (Environment.Is64BitProcess)
                {
                    pCurrentEntry = new IntPtr(pEntry.ToInt64() - nInitOrderListOffset);
                    pHashLink = new IntPtr(pCurrentEntry.ToInt64() + nHashLinkOffset);
                }
                else
                {
                    pCurrentEntry = new IntPtr(pEntry.ToInt32() - nInitOrderListOffset);
                    pHashLink = new IntPtr(pCurrentEntry.ToInt32() + nHashLinkOffset);
                }

                ldrDataTable = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(
                    pCurrentEntry,
                    typeof(LDR_DATA_TABLE_ENTRY));
                pEntry = Marshal.ReadIntPtr(pEntry); // pEntry->Flink

                if (ldrDataTable.HashLinks.Flink == pHashLink)
                    continue;

                pListEntry = ldrDataTable.HashLinks.Flink;

                if (Marshal.ReadIntPtr(pListEntry) == pHashLink)
                {
                    hash = LdrHashEntry(ldrDataTable.BaseDllName, true);

                    if (Environment.Is64BitProcess)
                        pListEntry = new IntPtr(ldrDataTable.HashLinks.Flink.ToInt64() - (hash * Marshal.SizeOf(typeof(LIST_ENTRY))));
                    else
                        pListEntry = new IntPtr(ldrDataTable.HashLinks.Flink.ToInt32() - (hash * Marshal.SizeOf(typeof(LIST_ENTRY))));

                    break;
                }

                pListEntry = IntPtr.Zero;
            } while (pEntry != pHeadList);

            return pListEntry;
        }


        public static IntPtr FindLdrDataTableEntry(IntPtr pPeb, string moduleName)
        {
            PEB_PARTIAL peb;
            PEB_LDR_DATA ldrData;
            LDR_DATA_TABLE_ENTRY ldrDataTable;
            IntPtr pFirstEntry;
            IntPtr pCurrentEntry;
            int nMemoryOrderLinksOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "InMemoryOrderLinks").ToInt32();
            var pLdrDataTableEntry = IntPtr.Zero;

            do
            {
                if (pPeb == IntPtr.Zero)
                    break;

                peb = (PEB_PARTIAL)Marshal.PtrToStructure(pPeb, typeof(PEB_PARTIAL));
                ldrData = (PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(PEB_LDR_DATA));

                if (Environment.Is64BitProcess)
                    pFirstEntry = new IntPtr(ldrData.InMemoryOrderModuleList.Flink.ToInt64() - nMemoryOrderLinksOffset);
                else
                    pFirstEntry = new IntPtr(ldrData.InMemoryOrderModuleList.Flink.ToInt32() - nMemoryOrderLinksOffset);

                pCurrentEntry = pFirstEntry;

                do
                {
                    ldrDataTable = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(pCurrentEntry, typeof(LDR_DATA_TABLE_ENTRY));

                    if (CompareIgnoreCase(ldrDataTable.BaseDllName.ToString(), moduleName))
                    {
                        pLdrDataTableEntry = pCurrentEntry;
                        break;
                    }

                    if (Environment.Is64BitProcess)
                        pCurrentEntry = new IntPtr(ldrDataTable.InMemoryOrderLinks.Flink.ToInt64() - nMemoryOrderLinksOffset);
                    else
                        pCurrentEntry = new IntPtr(ldrDataTable.InMemoryOrderLinks.Flink.ToInt64() - nMemoryOrderLinksOffset);
                } while (pCurrentEntry != pFirstEntry);
            } while (false);

            return pLdrDataTableEntry;
        }


        public static IntPtr FindModuleBaseAddressIndex(IntPtr pPeb)
        {
            int e_lfanew;
            int nSectionCount;
            int nSizeOfOptionalHeader;
            IntPtr pLdrDataTableEntry; // PLDR_DATA_TABLE_ENTRY
            IntPtr pNode; // RTL_BALANCED_NODE
            IntPtr pParent; // RTL_BALANCED_NODE.Parent
            IntPtr pDllBase;
            IntPtr pSectionHeaderBase;
            IntPtr pSectionHeader;
            LDR_DATA_TABLE_ENTRY ldrDataTableEntry;
            IMAGE_SECTION_HEADER sectionHeader;
            bool status;
            bool isRed;
            int nDataSectionSize = 0;
            var pDataSection = IntPtr.Zero; // PIMAGE_SECTION_HEADER
            var pRbTree = IntPtr.Zero; // PRTL_RB_TREE
            int nSectionHeaderSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            var nBaseAddressIndexNodeOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY),
                "BaseAddressIndexNode").ToInt32();

            pLdrDataTableEntry = FindLdrDataTableEntry(pPeb, "ntdll.dll");
            ldrDataTableEntry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(
                pLdrDataTableEntry,
                typeof(LDR_DATA_TABLE_ENTRY));

            if (pLdrDataTableEntry == IntPtr.Zero)
                return IntPtr.Zero;

            if (Environment.Is64BitProcess)
                pNode = new IntPtr(pLdrDataTableEntry.ToInt64() + nBaseAddressIndexNodeOffset);
            else
                pNode = new IntPtr(pLdrDataTableEntry.ToInt32() + nBaseAddressIndexNodeOffset);

            pParent = Marshal.ReadIntPtr(pNode, IntPtr.Size * 2);

            do
            {
                if (Environment.Is64BitProcess)
                {
                    pNode = new IntPtr(pParent.ToInt64() & (~7L));
                    pParent = Marshal.ReadIntPtr(pNode, IntPtr.Size * 2);
                    status = (new IntPtr(pParent.ToInt64() & (~7L)) != IntPtr.Zero);
                }
                else
                {
                    pNode = new IntPtr(pParent.ToInt32() & (~7));
                    pParent = Marshal.ReadIntPtr(pNode, IntPtr.Size * 2);
                    status = (new IntPtr(pParent.ToInt32() & (~7)) != IntPtr.Zero);
                }
            } while (status);

            isRed = ((Marshal.ReadIntPtr(pNode, IntPtr.Size * 2).ToInt64() & 0x1L) != 0);

            if (!isRed)
            {
                pDllBase = ldrDataTableEntry.DllBase;
                e_lfanew = Marshal.ReadInt32(pDllBase, 0x3C);
                nSectionCount = (ushort)Marshal.ReadInt16(pDllBase, e_lfanew + 0x6);
                nSizeOfOptionalHeader = (ushort)Marshal.ReadInt16(pDllBase, e_lfanew + 0x14);

                if (Environment.Is64BitProcess)
                    pSectionHeaderBase = new IntPtr(pDllBase.ToInt64() + e_lfanew + 0x18 + nSizeOfOptionalHeader);
                else
                    pSectionHeaderBase = new IntPtr(pDllBase.ToInt64() + e_lfanew + 0x18 + nSizeOfOptionalHeader);

                for (var index = 0; index < nSectionCount; index++)
                {
                    if (Environment.Is64BitProcess)
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt64() + (index * nSectionHeaderSize));
                    else
                        pSectionHeader = new IntPtr(pSectionHeaderBase.ToInt32() + (index * nSectionHeaderSize));

                    sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                        pSectionHeader,
                        typeof(IMAGE_SECTION_HEADER));

                    if (CompareIgnoreCase(sectionHeader.Name, ".data"))
                    {
                        if (Environment.Is64BitProcess)
                            pDataSection = new IntPtr(pDllBase.ToInt64() + sectionHeader.VirtualAddress);
                        else
                            pDataSection = new IntPtr(pDllBase.ToInt32() + (int)sectionHeader.VirtualAddress);

                        nDataSectionSize = (int)sectionHeader.VirtualSize;
                        break;
                    }
                }

                for (var offset = 0; offset < (nDataSectionSize - IntPtr.Size); offset++)
                {
                    if (Marshal.ReadIntPtr(pDataSection, offset) == pNode)
                    {
                        if (Environment.Is64BitProcess)
                            pRbTree = new IntPtr(pDataSection.ToInt64() + offset);
                        else
                            pRbTree = new IntPtr(pDataSection.ToInt32() + offset);
                        break;
                    }
                }

                if (pRbTree != IntPtr.Zero)
                {
                    if ((Marshal.ReadIntPtr(pRbTree) == IntPtr.Zero) ||
                        (Marshal.ReadIntPtr(pRbTree, 8) == IntPtr.Zero)) // pRbTree->Root && pRbTree->Min
                    {
                        pRbTree = IntPtr.Zero;
                    }
                }
            }

            return pRbTree;
        }


        public static IntPtr GetEntryPointPointer(IntPtr pModule)
        {
            int e_lfanew;
            uint addressOfEntryPoint;
            var pEntryPoint = IntPtr.Zero;

            do
            {
                if (Marshal.ReadInt16(pModule) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pModule, 0x3C);

                // Avoid memory access violation
                if (e_lfanew > 0x200)
                    break;

                if (Marshal.ReadInt32(pModule, e_lfanew) != 0x00004550)
                    break;

                addressOfEntryPoint = (uint)Marshal.ReadInt32(pModule, e_lfanew + 0x28);

                if (addressOfEntryPoint == 0)
                    break;

                if (Environment.Is64BitProcess)
                    pEntryPoint = new IntPtr(pModule.ToInt64() + addressOfEntryPoint);
                else
                    pEntryPoint = new IntPtr(pModule.ToInt32() + (int)addressOfEntryPoint);
            } while (false);

            return pEntryPoint;
        }


        public static ushort GetModuleArchitecture(IntPtr pModuleBase)
        {
            int e_lfanew;
            ushort machine = 0;

            do
            {
                if (Marshal.ReadInt16(pModuleBase) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);

                // Avoid memory access violation
                if (e_lfanew > 0x200)
                    break;

                if (Marshal.ReadInt32(pModuleBase, e_lfanew) != 0x00004550)
                    break;

                machine = (ushort)Marshal.ReadInt16(pModuleBase, e_lfanew + 0x18);
            } while (false);

            return machine;
        }


        public static IntPtr GetModuleHandle(string moduleName)
        {
            var pModule = IntPtr.Zero;
            var modules = Process.GetCurrentProcess().Modules;

            foreach (ProcessModule module in modules)
            {
                if (CompareIgnoreCase(module.ModuleName, moduleName))
                {
                    pModule = module.BaseAddress;
                    break;
                }
            }

            return pModule;
        }


        public static IntPtr GetPebAddress(IntPtr hProcess)
        {
            NTSTATUS ntstatus;
            IntPtr pBuffer;
            IntPtr pPeb;
            bool isWow64;

            if (Environment.Is64BitProcess)
                NativeMethods.IsWow64Process(hProcess, out isWow64);
            else
                isWow64 = false;

            if (isWow64)
            {
                pBuffer = Marshal.AllocHGlobal(IntPtr.Size);

                ntstatus = NativeMethods.NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessWow64Information,
                    pBuffer,
                    (uint)IntPtr.Size,
                    out uint _);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    pPeb = Marshal.ReadIntPtr(pBuffer);
                else
                    pPeb = IntPtr.Zero;

                Marshal.FreeHGlobal(pBuffer);
            }
            else
            {
                if (GetProcessBasicInformation(hProcess, out PROCESS_BASIC_INFORMATION pbi))
                    pPeb = pbi.PebBaseAddress;
                else
                    pPeb = IntPtr.Zero;
            }

            return pPeb;
        }


        public static bool GetProcessBasicInformation(
            IntPtr hProcess,
            out PROCESS_BASIC_INFORMATION pbi)
        {
            NTSTATUS ntstatus;
            bool status;
            var nSizeBuffer = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal((int)nSizeBuffer);

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                nSizeBuffer,
                out uint _);
            status = (ntstatus == Win32Consts.STATUS_SUCCESS);

            if (status)
            {
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
            }
            else
            {
                pbi = new PROCESS_BASIC_INFORMATION();
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return status;
        }


        public static void InsertTailList(
            IntPtr /* PLIST_ENTRY */ pHeadList,
            IntPtr /* PLIST_ENTRY */ pTailList)
        {
            var headList = (LIST_ENTRY)Marshal.PtrToStructure(pHeadList, typeof(LIST_ENTRY));
            var tailList = (LIST_ENTRY)Marshal.PtrToStructure(pTailList, typeof(LIST_ENTRY));
            var midList = (LIST_ENTRY)Marshal.PtrToStructure(headList.Blink, typeof(LIST_ENTRY));
            IntPtr pMidList = headList.Blink;

            tailList.Flink = pHeadList;
            tailList.Blink = pMidList;
            midList.Flink = pTailList;
            headList.Blink = pTailList;

            Marshal.StructureToPtr(midList, pMidList, true);
            Marshal.StructureToPtr(tailList, pTailList, true);
            Marshal.StructureToPtr(headList, pHeadList, true);
        }


        public static bool IsValidModule(IntPtr pModule)
        {
            int e_lfanew;
            bool status = false;

            do
            {
                if (Marshal.ReadInt16(pModule) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pModule, 0x3C);

                // Avoid memory access violation
                if (e_lfanew > 0x200)
                    break;

                if (Marshal.ReadInt32(pModule, e_lfanew) != 0x00004550)
                    break;

                status = true;
            } while (false);

            return status;
        }


        public static uint LdrHashEntry(UNICODE_STRING unicodeString, bool getEntry)
        {
            NTSTATUS ntstatus = NativeMethods.RtlHashUnicodeString(
                in unicodeString,
                BOOLEAN.TRUE,
                0u,
                out uint hashValue);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                hashValue = 0;
            }
            else
            {
                // LDR_GET_HASH_ENTRY(x)
                if (getEntry)
                    hashValue &= (Win32Consts.LDR_HASH_TABLE_ENTRIES - 1);
            }

            return hashValue;
        }


        public static void ZeroMemory(IntPtr pBuffer, int nSize)
        {
            for (var offset = 0; offset < nSize; offset++)
                Marshal.WriteByte(pBuffer, offset, 0);
        }
    }
}
