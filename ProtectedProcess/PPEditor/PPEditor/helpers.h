#pragma once

BOOL IsKernelAddress(ULONG64);
std::string PointerToString(ULONG64);
std::string ProtectionToString(PS_PROTECTION);
std::string ReadAnsiString(ULONG64, LONG);
std::string ReadUnicodeString(ULONG64, LONG);