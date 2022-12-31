// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "PPEditor.h"
#include "helpers.h"
#include "utils.h"

EXT_API_VERSION ApiVersion = {
    0,                        // MajorVersion
    0,                        // MinorVersion
    EXT_API_VERSION_NUMBER64, // Revision
    0                         // Reserved
};

WINDBG_EXTENSION_APIS ExtensionApis;

LPEXT_API_VERSION ExtensionApiVersion(void)
{
    return &ApiVersion;
}

BOOL g_IsInitialized = FALSE;
ULONG64 g_SystemProcess = 0ULL;
KERNEL_OFFSETS g_KernelOffsets = { 0 };

VOID WinDbgExtensionDllInit(
    PWINDBG_EXTENSION_APIS lpExtensionApis,
    USHORT /* MajorVersion */,
    USHORT /* MinorVersion */
)
{
    ULONG64 pKthread = 0ULL;
    ULONG64 pApcState = 0ULL;
    ULONG nApcStateOffset = 0UL;
    ULONG nProcessOffset = 0UL;
    PCSTR reminder = new CHAR[MAX_PATH];
    ExtensionApis = *lpExtensionApis;

    do
    {
        if (!GetExpressionEx("nt!KiInitialThread", &pKthread, &reminder))
            break;

        if (GetFieldOffset("nt!_KTHREAD", "ApcState", &nApcStateOffset) != 0UL)
            break;

        if (GetFieldOffset("nt!_KAPC_STATE", "Process", &nProcessOffset) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "UniqueProcessId", &g_KernelOffsets.UniqueProcessId) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "ActiveProcessLinks", &g_KernelOffsets.ActiveProcessLinks) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "ImageFilePointer", &g_KernelOffsets.ImageFilePointer) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "ImageFileName", &g_KernelOffsets.ImageFileName) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "SignatureLevel", &g_KernelOffsets.SignatureLevel) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "SectionSignatureLevel", &g_KernelOffsets.SectionSignatureLevel) != 0UL)
            break;

        if (GetFieldOffset("nt!_EPROCESS", "Protection", &g_KernelOffsets.Protection) != 0UL)
            break;

        if (ReadPtr(pKthread + nApcStateOffset, &pApcState))
            break;

        ReadPtr(pApcState + nProcessOffset, &g_SystemProcess);
    } while (FALSE);

    g_IsInitialized = IsKernelAddress(g_SystemProcess) ? TRUE : FALSE;

    dprintf("\n");

    if (g_IsInitialized)
    {
        dprintf("PPEditor - Kernel Mode WinDbg extension for Protected Process investigation.\n");
        dprintf("\n");
        dprintf("Commands :\n");
        dprintf("    + !getpps : List Protected Processes in the target system.\n");
        dprintf("    + !setpps : Set Protection Level for target processes.\n");
        dprintf("\n");
        dprintf("[*] To see command help, execute \"!<Command> help\" or \"!<Command> /?\".\n");
    }
    else
    {
        dprintf("[!] This plugin should be used by Kernel-mode debugger.\n");
    }

    dprintf("\n");
}


DECLARE_API(getpps)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> ppslist;
    std::map<ULONG_PTR, PROCESS_CONTEXT> filteredlist;
    std::smatch matches;
    std::string protection;
    std::string searchFilter;
    std::string cmdline(args);
    std::regex re_help(R"(^\s*(help|/\?)\s*$)");
    std::regex re_expected1(R"(^\s*/p\s*$)");
    std::regex re_expected2(R"(^\s*(\d+)\s*$)");
    std::regex re_expected3(R"(^\s*(\S+)\s*$)");
    std::regex re_expected4(R"(^\s*/p\s+(\S+)\s*$)");
    ULONG_PTR pid = -1;
    BOOL pponly = FALSE;

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[!] Parameters are not initialized. This extension should be run in Kernel-mode WinDbg.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!getpps - List Protected Process.\n");
            dprintf("\n");
            dprintf("Usage :\n");
            dprintf("    (1) !getpps             : List all processes.\n");
            dprintf("    (2) !getpps /p          : List Protected Processes.\n");
            dprintf("    (3) !getpps <PID>       : List a process has a specific PID.\n");
            dprintf("    (4) !getpps <Filter>    : List processes with search filter.\n");
            dprintf("    (5) !getpps /p <Filter> : List Protected Processes with search filter.\n");
            dprintf("\n");
            dprintf("[*] Search filter is used for forward matching and case insensitive.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected1))
        {
            pponly = TRUE;
        }
        else if (std::regex_match(cmdline, matches, re_expected2))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
        }
        else if (std::regex_match(cmdline, matches, re_expected3))
        {
            searchFilter = matches[1].str();
        }
        else if (std::regex_match(cmdline, matches, re_expected4))
        {
            pponly = TRUE;
            searchFilter = matches[1].str();
        }
        else if (!cmdline.empty())
        {
            dprintf("[!] Invalid arguments. See \"!getpps help\" or \"!getpps /?\".\n");
            break;
        }

        ppslist = ListProcessInformation();

        if (ppslist.size() == 0)
        {
            dprintf("[-] Failed to get process list.\n");
            break;
        }

        if (pponly)
        {
            for (std::pair<ULONG_PTR, PROCESS_CONTEXT> pps : ppslist)
            {
                protection = ProtectionToString(pps.second.Protection);

                if (searchFilter.empty())
                {
                    if (_stricmp(protection.c_str(), "None") != 0)
                        filteredlist[pps.first] = pps.second;
                }
                else
                {
                    if ((_stricmp(protection.c_str(), "None") != 0) &&
                        (_strnicmp(searchFilter.c_str(), pps.second.ProcessName, searchFilter.size()) == 0))
                    {
                        filteredlist[pps.first] = pps.second;
                    }
                }
            }
        }
        else if (pid != -1)
        {
            if (ppslist.find(pid) != ppslist.end())
                filteredlist[pid] = ppslist[pid];
        }
        else if (!searchFilter.empty())
        {
            for (std::pair<ULONG_PTR, PROCESS_CONTEXT> pps : ppslist)
            {
                if (_strnicmp(searchFilter.c_str(), pps.second.ProcessName, searchFilter.size()) == 0)
                    filteredlist[pps.first] = pps.second;
            }
        }
        else
        {
            filteredlist = ppslist;
        }

        if (filteredlist.size() == 0)
        {
            dprintf("[-] No entries.\n");
            break;
        }

        if (IsPtr64())
        {
            dprintf("     PID        nt!_EPROCESS                  Protection Process Name\n");
            dprintf("======== =================== =========================== ============\n");
        }
        else
        {
            dprintf("     PID nt!_EPROCESS                  Protection Process Name\n");
            dprintf("======== ============ =========================== ============\n");
        }

        for (std::pair<ULONG_PTR, PROCESS_CONTEXT> pps : filteredlist)
        {
            if (IsPtr64())
            {
                dprintf("%8d %19s %27s %s\n",
                    pps.first,
                    PointerToString(pps.second.Eprocess).c_str(),
                    ProtectionToString(pps.second.Protection).c_str(),
                    pps.second.ProcessName);
            }
            else
            {
                dprintf("%8d %12s %27s %s\n",
                    pps.first,
                    PointerToString(pps.second.Eprocess).c_str(),
                    ProtectionToString(pps.second.Protection).c_str(),
                    pps.second.ProcessName);
            }
        }
        
        dprintf("\n");

        if (pid != -1)
        {
            dprintf("[*] SignatureLevel        : 0x%02x\n", filteredlist[pid].SignatureLevel);
            dprintf("[*] SectionSignatureLevel : 0x%02x\n", filteredlist[pid].SectionSignatureLevel);
            dprintf("\n");
        }

        dprintf("[*] Done.\n");
    } while (FALSE);

    dprintf("\n");
}


DECLARE_API(setpps)
{
    std::map<ULONG_PTR, PROCESS_CONTEXT> ppslist;
    PROCESS_CONTEXT pps;
    std::smatch matches;
    ULONG_PTR pid;
    std::string prot;
    std::string type;
    std::string signer;
    std::string cmdline(args);
    PS_PROTECTION protValue = { 0 };
    std::regex re_help(R"(^\s*(help|/\?)\s*$)");
    std::regex re_expected(R"(^\s*(\d+)\s+([A-Za-z\-]+)\s*$)");
    std::regex re_prot(R"(^([A-Za-z]+)-([A-Za-z]+)$)");
    ULONG64 eprocess = 0ULL;
    ULONG cb = 0UL;
    BOOL filter = FALSE;
    BOOL isParsed = FALSE;

    dprintf("\n");

    do
    {
        if (!g_IsInitialized)
        {
            dprintf("[!] Parameters are not initialized. This extension should be run in Kernel-mode WinDbg.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_help))
        {
            dprintf("!setpps - List Protected Process.\n");
            dprintf("\n");
            dprintf("Usage : !setpps <PID> <Protection>\n");
            dprintf("\n");
            dprintf("    + PID        : Specifies target PID by decimal format.\n");
            dprintf("    + Protection : Specifies the Protection Level in the format \"None\" or \"<Type>-<Signer>\".\n");
            dprintf("                   Type should be \"ProtectedLight\" or \"Protected\".\n");
            dprintf("                   Signer should be \"Authenticode\", \"CodeGen\", \"AntiMalware\", \"Lsa\",\n");
            dprintf("                   \"Windows\", \"WinTcb\", \"WinSystem\" or \"App\".\n");
            dprintf("\n");
            dprintf("[*] Protection Level is used for case insensitive.\n");
            break;
        }

        if (std::regex_match(cmdline, matches, re_expected))
        {
            pid = (ULONG_PTR)std::stoull(matches[1].str());
            prot = matches[2].str();
        }
        else
        {
            dprintf("[!] Invalid arguments. See \"!setpps help\" or \"!setpps /?\".\n");
            break;
        }

        ppslist = ListProcessInformation();

        if (ppslist.size() == 0)
        {
            dprintf("[-] Failed to get process list.\n");
            break;
        }
        else if (ppslist.find(pid) == ppslist.end())
        {
            dprintf("[-] Failed to find the specified PID.\n");
            break;
        }
        else
        {
            pps = ppslist[pid];
            eprocess = ppslist[pid].Eprocess;
            dprintf("[*] %s (PID : %d) @ %s\n", pps.ProcessName, pid, PointerToString(eprocess).c_str());
        }

        if (_stricmp(prot.c_str(), "None") == 0)
        {
            protValue.Level = 0;
            isParsed = TRUE;
        }
        else
        {
            if (std::regex_match(prot, matches, re_prot))
            {
                type = matches[1].str();
                signer = matches[2].str();

                if (_stricmp(type.c_str(), "ProtectedLight") == 0)
                {
                    protValue.Type = PsProtectedTypeProtectedLight;
                }
                else if (_stricmp(type.c_str(), "Protected") == 0)
                {
                    protValue.Type = PsProtectedTypeProtected;
                }
                else
                {
                    dprintf("[!] Invalid Type is specified.\n");
                    break;
                }

                if (_stricmp(signer.c_str(), "Authenticode") == 0)
                {
                    protValue.Signer = PsProtectedSignerAuthenticode;
                }
                else if (_stricmp(signer.c_str(), "CodeGen") == 0)
                {
                    protValue.Signer = PsProtectedSignerCodeGen;
                }
                else if (_stricmp(signer.c_str(), "AntiMalware") == 0)
                {
                    protValue.Signer = PsProtectedSignerAntimalware;
                }
                else if (_stricmp(signer.c_str(), "Lsa") == 0)
                {
                    protValue.Signer = PsProtectedSignerLsa;
                }
                else if (_stricmp(signer.c_str(), "Windows") == 0)
                {
                    protValue.Signer = PsProtectedSignerWindows;
                }
                else if (_stricmp(signer.c_str(), "WinTcb") == 0)
                {
                    protValue.Signer = PsProtectedSignerWinTcb;
                }
                else if (_stricmp(signer.c_str(), "WinSystem") == 0)
                {
                    protValue.Signer = PsProtectedSignerWinSystem;
                }
                else if (_stricmp(signer.c_str(), "App") == 0)
                {
                    protValue.Signer = PsProtectedSignerApp;
                }
                else
                {
                    dprintf("[!] Invalid Signer is specified.\n");
                    break;
                }

                isParsed = TRUE;
            }
            else
            {
                dprintf("[!] Invalid arguments. See \"!setpps help\" or \"!setpps /?\".\n\n");
                break;
            }
        }

        if (isParsed)
        {
            dprintf("[>] Setting %s protection level.\n", ProtectionToString(protValue).c_str());

            WriteMemory(eprocess + g_KernelOffsets.Protection, &protValue, sizeof(PS_PROTECTION), &cb);

            dprintf("[*] SignatureLevel : 0x%02x, SectionSignatureLevel : 0x%02x\n", pps.SignatureLevel, pps.SectionSignatureLevel);
            dprintf("[*] If you want to change SignatureLevel or SectionSignatureLevel, set them manually with following commands.\n");
            dprintf("    [*] For SignatureLevel        : eb %s+0x%x 0x??\n", PointerToString(eprocess).c_str(), g_KernelOffsets.SignatureLevel);
            dprintf("    [*] For SectionSignatureLevel : eb %s+0x%x 0x??\n", PointerToString(eprocess).c_str(), g_KernelOffsets.SectionSignatureLevel);
            dprintf("[*] Done.\n");
        }
    } while (FALSE);

    dprintf("\n");
}