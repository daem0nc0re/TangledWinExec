#include "pch.h"
#include "PPEditor.h"
#include "helpers.h"

BOOL IsKernelAddress(ULONG64 Address)
{
    if (IsPtr64())
        return (Address >= 0xFFFF080000000000ULL);
    else
        return ((ULONG)Address >= 0x80000000UL);
}


std::string PointerToString(ULONG64 pointer)
{
    CHAR buffer[32] = { 0 };
    ULONG higher = (ULONG)((pointer >> 32) & 0xFFFFFFFFUL);
    ULONG lower = (ULONG)(pointer & 0xFFFFFFFFUL);

    if (IsPtr64())
        ::sprintf_s(buffer, 32, "0x%08x`%08x", higher, lower);
    else
        ::sprintf_s(buffer, 32, "0x%08x", lower);

    return std::string(buffer);
}


std::string ProtectionToString(PS_PROTECTION protection)
{
    CHAR result[32] = { 0 };
    std::string type;
    std::string signer;

    if (protection.Type == PsProtectedTypeProtectedLight)
        type = std::string("ProtectedLight");
    else if (protection.Type == PsProtectedTypeProtected)
        type = std::string("Protected");

    if (protection.Signer == PsProtectedSignerAuthenticode)
        signer = std::string("Authenticode");
    else if (protection.Signer == PsProtectedSignerCodeGen)
        signer = std::string("CodeGen");
    else if (protection.Signer == PsProtectedSignerAntimalware)
        signer = std::string("AntiMalware");
    else if (protection.Signer == PsProtectedSignerLsa)
        signer = std::string("Lsa");
    else if (protection.Signer == PsProtectedSignerWindows)
        signer = std::string("Windows");
    else if (protection.Signer == PsProtectedSignerWinTcb)
        signer = std::string("WinTcb");
    else if (protection.Signer == PsProtectedSignerWinSystem)
        signer = std::string("WinSystem");
    else if (protection.Signer == PsProtectedSignerApp)
        signer = std::string("App");

    if (!type.empty() && !signer.empty())
        ::sprintf_s(result, 32, "%s-%s", type.c_str(), signer.c_str());
    else
        ::sprintf_s(result, 32, "None");

    return result;
}


std::string ReadAnsiString(ULONG64 Address, LONG Size)
{
    std::string result;
    char charByte = 0;
    ULONG cb = 0;

    for (LONG idx = 0; idx < Size; idx++)
    {
        if (ReadMemory(Address + idx, &charByte, sizeof(char), &cb))
        {
            if (charByte == 0)
                break;
            else
                result.push_back(charByte);
        }
    }

    return result;
}


std::string ReadUnicodeString(ULONG64 Address, LONG Size)
{
    std::string result;
    std::wstring readString;
    ULONG nBufferSize;
    CHAR* charBuffer;
    ULONG cb = 0UL;
    SHORT unicode = 0;
    size_t retVal = 0;

    for (LONG idx = 0; idx < Size; idx += 2)
    {
        if (ReadMemory(Address + idx, &unicode, sizeof(short), &cb))
        {
            if (unicode == 0)
                break;
            else
                readString.push_back(unicode);
        }
        else
        {
            break;
        }
    }

    if (readString.length() > 0)
    {
        nBufferSize = (ULONG)readString.length() * 2;
        charBuffer = new CHAR[nBufferSize + 2];
        ::wcstombs_s(&retVal, charBuffer, nBufferSize, readString.c_str(), nBufferSize);
        result = std::string(charBuffer);
        delete[] charBuffer;
    }

    return result;
}