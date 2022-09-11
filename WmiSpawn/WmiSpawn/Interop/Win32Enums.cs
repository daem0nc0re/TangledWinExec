using System;

namespace WmiSpawn.Interop
{
    [Flags]
    internal enum SHOW_WINDOW_FLAGS : uint
    {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_NORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_MAXIMIZE = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_FORCEMINIMIZE = 11,
        SW_MAX = 11
    }

    /*
     * Reference :
     * + https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-process
     */
    internal enum WMI_PROCESS_STATUS : uint
    {
        SUCCESS = 0,
        ACCESS_DENIED = 2,
        INSUFFICIENT_PRIVILEGE = 3,
        UNKNOWN_FAILURE = 8,
        PATH_NOT_FOUND = 9,
        INVALID_PARAMETERS = 21,
        OTHER_REASON = 22
    }
}
