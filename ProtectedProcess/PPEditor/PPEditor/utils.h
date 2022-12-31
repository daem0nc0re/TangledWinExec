#pragma once

std::string GetFileName(ULONG64);
std::string GetImageFileName(ULONG64);
std::string GetProcessName(ULONG64);
std::map<ULONG_PTR, PROCESS_CONTEXT> ListProcessInformation();