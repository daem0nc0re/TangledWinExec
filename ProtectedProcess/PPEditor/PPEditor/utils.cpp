#include "pch.h"
#include "PPEditor.h"
#include "helpers.h"
#include "utils.h"

std::string GetFileName(ULONG64 pEprocess)
{
    std::string fileName;
    ULONG64 pImageFilePointer = 0ULL;
    UNICODE_STRING unicodeString = { 0 };
    ULONG nFileNameOffset = IsPtr64() ? 0x58UL : 0x30UL; // ntdll!_FILE_OBJECT.FileName
    ULONG cb = 0UL;

    if (ReadPtr(pEprocess + g_KernelOffsets.ImageFilePointer, &pImageFilePointer))
        return std::string("");

    if (ReadMemory(pImageFilePointer + nFileNameOffset,
        &unicodeString,
        sizeof(UNICODE_STRING),
        &cb))
    {
        fileName = ReadUnicodeString((ULONG64)unicodeString.Buffer, unicodeString.Length);
    }

    return fileName;
}


std::string GetImageFileName(ULONG64 pEprocess)
{
    return ReadAnsiString(pEprocess + g_KernelOffsets.ImageFileName, 16);
}


std::string GetProcessName(ULONG64 pEprocess)
{
    std::regex re_expected(R"([\S ]+\\([^\\]+))");
    std::smatch matches;
    std::string fileName = GetFileName(pEprocess);
    std::string imageFileName = GetImageFileName(pEprocess);

    if (fileName.empty())
        return imageFileName;

    if (std::regex_match(fileName, matches, re_expected))
        return matches[1].str();

    return std::string("");
}


std::map<ULONG_PTR, PROCESS_CONTEXT> ListProcessInformation()
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> results;
    ULONG64 value;
    ULONG64 pCurrent = g_SystemProcess;
    std::string processName;
    PROCESS_CONTEXT context = { 0 };
    ULONG_PTR uniqueProcessId = 0;
    ULONG cb = 0UL;
    size_t len = 0;

    do
    {
        context = { 0 };

        if (!ReadPtr(pCurrent + g_KernelOffsets.UniqueProcessId, &value))
        {
            uniqueProcessId = (ULONG_PTR)value;
            context.Eprocess = pCurrent;
            processName = GetProcessName(pCurrent);
            len = (processName.length() > 255) ? 255 : processName.length();

            if (len == 0)
            {
                uniqueProcessId = 0;
                processName = std::string("Idle");
                len = processName.length();
            }

            ::strcpy_s(context.ProcessName, (rsize_t)&len, processName.c_str());

            ReadMemory(pCurrent + g_KernelOffsets.SignatureLevel, &context.SignatureLevel, sizeof(UCHAR), &cb);
            ReadMemory(pCurrent + g_KernelOffsets.SectionSignatureLevel, &context.SectionSignatureLevel, sizeof(UCHAR), &cb);
            ReadMemory(pCurrent + g_KernelOffsets.Protection, &context.Protection, sizeof(PS_PROTECTION), &cb);

            if (results.find(uniqueProcessId) == results.end())
                results[uniqueProcessId] = context;
            else
                break;

            if (!ReadPtr(pCurrent + g_KernelOffsets.ActiveProcessLinks, &value))
                pCurrent = value - g_KernelOffsets.ActiveProcessLinks;
            else
                break;
        }
        else
        {
            break;
        }
    } while (pCurrent != g_SystemProcess);

    return results;
}