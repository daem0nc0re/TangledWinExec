using System;

namespace DarkLibraryLoader.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
        public const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
        public const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
        public const int IMAGE_DIRECTORY_ENTRY_TLS = 9;
        public const int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
        public const ulong IMAGE_ORDINAL_FLAG64 = 0x8000000000000000;
        public const uint IMAGE_ORDINAL_FLAG32 = 0x80000000;
        public const uint LDR_HASH_TABLE_ENTRIES = 32u;
    }
}
