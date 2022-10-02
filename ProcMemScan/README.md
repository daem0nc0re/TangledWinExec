# ProcMemScan

This tool is written for inspecting undebuggable process.
Following functionalities are implemented.

* [Get ntdll!_PEB information for a remote process as !peb command of WinDbg.](#dump-ntdllpeb-information)
* [Enumerate memory layout for a remote process.](#enumerate-memory)
* [Get basic information and hexdump of a specific memory region for a remote process.](#dump-memory)
* [Extract data in a specific memory region for a remote process.](#extract-memory-to-file)
* [Extract PE image file in a specific memory region for a remote process.](#extract-pe-image-from-memory)
* [Scan suspicious things in a remote process.](#scan-suspicious-things)

## Dump ntdll!_PEB information

[Back to Top](#procmemscan)

To dump ntdll!_PEB information for a remote process, simply specify PID with `-p` option in decimal as follows:

```
PS C:\Tools> Get-Process notepad

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    553      33    31208      19104       0.70   7204   1 Notepad


PS C:\Tools> .\ProcMemScan.exe -p 7204

[>] Trying to get target process information.
[*] Target process is 'Notepad' (PID : 7204).
[+] Got target process information.

ntdll!_PEB @ 0x0000006EF33CE000
    InheritedAddressSpace    : FALSE
    ReadImageFileExecOptions : FALSE
    BeingDebugged            : FALSE
    ImageBaseAddress         : 0x00007FF7FCE70000 (C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe)
    Ldr                      : 0x00007FFEFCE99120
    Ldr.Initialized          : TRUE
    Ldr.InInitializationOrderModuleList : { 0x0000018C3FA04220 - 0x0000018C47EB0060 }
    Ldr.InLoadOrderModuleList           : { 0x0000018C3FA043B0 - 0x0000018C47EB0040 }
    Ldr.InMemoryOrderModuleList         : { 0x0000018C3FA043C0 - 0x0000018C47EB0050 }
                      Base Reason                     Loaded              Module
        0x00007FF7FCE70000 DynamicLoad                2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
        0x00007FFEFCD20000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\ntdll.dll
        0x00007FFEFC010000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\KERNEL32.DLL
        0x00007FFEFA830000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\KERNELBASE.dll
        0x00007FFEFAD40000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\SHLWAPI.dll
        0x00007FFEFC800000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\msvcrt.dll
        0x00007FFEFCA40000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\USER32.dll
        0x00007FFEFA800000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\win32u.dll
        0x00007FFEFAEC0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\GDI32.dll
        0x00007FFEFA430000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\gdi32full.dll
        0x00007FFEFA760000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\msvcp_win.dll
        0x00007FFEFA5C0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\ucrtbase.dll
        0x00007FFEFB7A0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\ole32.dll
        0x00007FFEFC0D0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\combase.dll
        0x00007FFEFABD0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\RPCRT4.dll
        0x00007FFEFAF90000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\SHELL32.dll
        0x00007FFEFCBF0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\COMDLG32.dll
        0x00007FFEF41B0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\urlmon.dll
        0x00007FFEFC8C0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\shcore.dll
        0x00007FFEFC450000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\ADVAPI32.dll
        0x00007FFEFC6D0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\sechost.dll
        0x00007FFEFAD00000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\IMM32.dll
        0x00007FFEFBF30000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\OLEAUT32.dll
        0x00007FFEF6860000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\PROPSYS.dll
        0x00007FFEF3E60000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\iertutil.dll
        0x00007FFEF4120000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\srvcli.dll
        0x00007FFEF8E50000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\netutils.dll
        0x00007FFEE4D10000 StaticDependency           2022/09/28 03:15:18 C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.22000.120_none_9d947278b86cc467\COMCTL32.dll
        0x00007FFEE18D0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\WINSPOOL.DRV
        0x00007FFEF7F30000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\dwmapi.dll
        0x00007FFEF79A0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\UxTheme.dll
        0x00007FFEBE700000 StaticDependency           2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe\MSVCP140.dll
        0x00007FFEBE6D0000 StaticDependency           2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe\VCRUNTIME140_1.dll
        0x00007FFEBE6E0000 StaticDependency           2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe\VCRUNTIME140.dll
        0x00007FFEFA6E0000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\System32\bcryptPrimitives.dll
        0x00007FFEF9320000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\SYSTEM32\kernel.appcore.dll
        0x00007FFEBD180000 DynamicLoad                2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\msptls.dll
        0x00007FFEBCE60000 DynamicLoad                2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\riched20.dll
        0x00007FFEFB9A0000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\System32\clbcatq.dll
        0x00007FFEED410000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\MrmCoreR.dll
        0x00007FFEECC40000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\SYSTEM32\windows.staterepositoryclient.dll
        0x00007FFEEE640000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\SYSTEM32\windows.staterepositorycore.dll
        0x00007FFEFA130000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\System32\profapi.dll
        0x00007FFEE6680000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\Windows.UI.dll
        0x00007FFEE6610000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\System32\bcp47mrm.dll
        0x00007FFEF3A20000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\twinapi.appcore.dll
        0x00007FFEF8230000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\WinTypes.dll
        0x00007FFEF83A0000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\SYSTEM32\windows.storage.dll
        0x00007FFEFADA0000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\System32\MSCTF.dll
        0x00007FFEBD500000 DynamicLoad                2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\NotepadXamlUI.dll
        0x00007FFEE4940000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\DWrite.dll
        0x00007FFEDF020000 StaticDependency           2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\MSVCP140_APP.dll
        0x00007FFEDF0B0000 StaticDependency           2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\VCRUNTIME140_1_APP.dll
        0x00007FFEDF0C0000 StaticDependency           2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\VCRUNTIME140_APP.dll
        0x00007FFEBE3B0000 DynamicLoad                2022/09/28 03:15:18 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Microsoft.Toolkit.Win32.UI.XamlHost.dll
        0x00007FFEE65F0000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\SYSTEM32\threadpoolwinrt.dll
        0x00007FFEE53E0000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\Windows.UI.Xaml.dll
        0x00007FFEFA0D0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\SYSTEM32\powrprof.dll
        0x00007FFEF62A0000 StaticDependency           2022/09/28 03:15:18 C:\Windows\System32\d2d1.dll
        0x00007FFEFA0B0000 DelayloadDependency        2022/09/28 03:15:18 C:\Windows\SYSTEM32\UMPDC.dll
        0x00007FFEF3020000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\OneCoreUAPCommonProxyStub.dll
        0x00007FFEF7390000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\CoreMessaging.dll
        0x00007FFEE94A0000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\InputHost.dll
        0x00007FFEF9990000 DynamicForwarderDependency 2022/09/28 03:15:18 C:\Windows\SYSTEM32\CRYPTBASE.DLL
        0x00007FFEE86C0000 DynamicLoad                2022/09/28 03:15:18 C:\Windows\System32\UiaManager.dll
        0x00007FFEF5200000 DelayloadDependency        2022/09/28 03:15:19 C:\Windows\System32\WindowManagementAPI.dll
        0x00007FFEF7AC0000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\SYSTEM32\dxgi.dll
        0x00007FFEF7A80000 DynamicForwarderDependency 2022/09/28 03:15:19 C:\Windows\SYSTEM32\dxcore.dll
        0x00007FFEF5890000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\System32\dcomp.dll
        0x00007FFEF5F20000 DelayloadDependency        2022/09/28 03:15:19 C:\Windows\SYSTEM32\directxdatabasehelper.dll
        0x00007FFEF7BD0000 StaticDependency           2022/09/28 03:15:19 C:\Windows\SYSTEM32\ntmarta.dll
        0x00007FFEE5140000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\System32\Windows.UI.Immersive.dll
        0x00007FFEF4F40000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\SYSTEM32\d3d11.dll
        0x00007FFEF2230000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\SYSTEM32\vm3dum64_loader.dll
        0x00007FFEF2060000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\system32\vm3dum64_10.dll
        0x00007FFEF2010000 StaticDependency           2022/09/28 03:15:19 C:\Windows\SYSTEM32\WINMM.dll
        0x00007FFEF2050000 StaticDependency           2022/09/28 03:15:19 C:\Windows\SYSTEM32\VERSION.dll
        0x00007FFEE29D0000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\system32\DataExchange.dll
        0x00007FFEE3DB0000 DelayloadDependency        2022/09/28 03:15:19 C:\Windows\SYSTEM32\TextShaping.dll
        0x00007FFEBDD50000 DynamicLoad                2022/09/28 03:15:19 C:\Program Files\WindowsApps\Microsoft.UI.Xaml.2.7_7.2203.17001.0_x64__8wekyb3d8bbwe\Microsoft.UI.Xaml.dll
        0x00007FFEE3E60000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\SYSTEM32\Windows.UI.Xaml.Controls.dll
        0x00007FFEE9670000 StaticDependency           2022/09/28 03:15:19 C:\Windows\SYSTEM32\Bcp47Langs.dll
        0x00007FFEDB860000 DelayloadDependency        2022/09/28 03:15:19 C:\Windows\SYSTEM32\uiautomationcore.dll
        0x00007FFEF9820000 StaticDependency           2022/09/28 03:15:19 C:\Windows\System32\USERENV.dll
        0x00007FFEF9F80000 DelayloadDependency        2022/09/28 03:15:19 C:\Windows\SYSTEM32\sxs.dll
        0x00007FFEE4770000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\System32\Windows.Globalization.dll
        0x00007FFEDAD50000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\SYSTEM32\msftedit.dll
        0x00007FFEDAD20000 DelayloadDependency        2022/09/28 03:15:19 C:\Windows\SYSTEM32\globinputhost.dll
        0x00007FFEDF900000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\System32\Windows.UI.Core.TextInput.dll
        0x00007FFEECA60000 DelayloadDependency        2022/09/28 03:15:19 C:\Windows\System32\TextInputFramework.dll
        0x00007FFEF5520000 DelayloadDependency        2022/09/28 03:15:19 C:\Windows\System32\CoreUIComponents.dll
        0x00007FFEBCCB0000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\System32\efswrt.dll
        0x00007FFEE2BE0000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\System32\oleacc.dll
        0x00007FFEE9F60000 DynamicLoad                2022/09/28 03:15:19 C:\Windows\System32\Windows.ApplicationModel.dll
        0x00007FFEE36E0000 DynamicLoad                2022/09/28 03:15:20 C:\Windows\system32\directmanipulation.dll
        0x00007FFEF9AF0000 DelayloadDependency        2022/09/28 03:15:20 C:\Windows\SYSTEM32\bcrypt.dll
        0x00007FFEF44E0000 DynamicLoad                2022/09/28 03:15:20 C:\Windows\system32\windowscodecs.dll
        0x00007FFEF4150000 DelayloadDependency        2022/09/28 03:15:20 C:\Windows\System32\wuceffects.dll
        0x00007FFEE52D0000 DynamicLoad                2022/09/28 03:15:20 C:\Windows\System32\twinapi.dll
    SubSystemData     : 0x00007FFEF3C5A6E0
    ProcessHeap       : 0x0000018C3F980000
    ProcessParameters : 0x0000018C3FA035F0
    CurrentDirectory  : 'C:\Users\admin\'
    WindowTitle       : 'C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe'
    ImagePathName     : 'C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe'
    CommandLine       : '"C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe" '
    DLLPath           : 'C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe;C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe;C:\Program Files\WindowsApps\Microsoft.UI.Xaml.2.7_7.2203.17001.0_x64__8wekyb3d8bbwe;C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe;'
    Environment       : 0x0000018C3FA02900
        ALLUSERSPROFILE=C:\ProgramData
        APPDATA=C:\Users\admin\AppData\Roaming
        CommonProgramFiles=C:\Program Files\Common Files
        CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
        CommonProgramW6432=C:\Program Files\Common Files
        COMPUTERNAME=DESKTOP-53V8DCQ
        ComSpec=C:\Windows\system32\cmd.exe
        DriverData=C:\Windows\System32\Drivers\DriverData
        HOMEDRIVE=C:
        HOMEPATH=\Users\admin
        LOCALAPPDATA=C:\Users\admin\AppData\Local
        LOGONSERVER=\\DESKTOP-53V8DCQ
        NUMBER_OF_PROCESSORS=2
        OneDrive=C:\Users\admin\OneDrive
        OS=Windows_NT
        Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files (x86)\Sysinternals;C:\Program Files (x86)\sandbox-attacksurface-analysis-tools;C:\Users\admin\AppData\Local\Microsoft\WindowsApps
        PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
        PROCESSOR_ARCHITECTURE=AMD64
        PROCESSOR_IDENTIFIER=AMD64 Family 25 Model 80 Stepping 0, AuthenticAMD
        PROCESSOR_LEVEL=25
        PROCESSOR_REVISION=5000
        ProgramData=C:\ProgramData
        ProgramFiles=C:\Program Files
        ProgramFiles(x86)=C:\Program Files (x86)
        ProgramW6432=C:\Program Files
        PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        PUBLIC=C:\Users\Public
        SystemDrive=C:
        SystemRoot=C:\Windows
        TEMP=C:\Users\admin\AppData\Local\Temp
        TMP=C:\Users\admin\AppData\Local\Temp
        USERDOMAIN=DESKTOP-53V8DCQ
        USERDOMAIN_ROAMINGPROFILE=DESKTOP-53V8DCQ
        USERNAME=admin
        USERPROFILE=C:\Users\admin
        windir=C:\Windows

[*] Completed.
```

## Enumerate Memory

[Back to Top](#procmemscan)

To enumerate memory layout for a remote process, set `-l` flag as follows:

```
PS C:\Tools> .\ProcMemScan.exe -p 6888 -l

[>] Trying to get target process memory information.
[*] Target process is 'Notepad' (PID : 6888).
[+] Got target process memory information.

              Base           Size State       Protect                           Type        Mapped
0x0000000000000000     0x18470000 MEM_FREE    PAGE_NOACCESS                     NONE        N/A
0x0000000018470000         0x1000 MEM_COMMIT  PAGE_READWRITE                    MEM_PRIVATE N/A
0x0000000018471000     0x67B6F000 MEM_FREE    PAGE_NOACCESS                     NONE        N/A
0x000000007FFE0000         0x1000 MEM_COMMIT  PAGE_READONLY                     MEM_PRIVATE N/A

--snip--

0x00007FF5F52E0000         0x1000 MEM_COMMIT  PAGE_READWRITE                    MEM_PRIVATE N/A
0x00007FF5F52E1000         0xF000 MEM_FREE    PAGE_NOACCESS                     NONE        N/A
0x00007FF5F52F0000         0x1000 MEM_COMMIT  PAGE_READONLY                     MEM_MAPPED  N/A
0x00007FF5F52F1000    0x11928F000 MEM_FREE    PAGE_NOACCESS                     NONE        N/A
0x00007FF70E580000         0x1000 MEM_COMMIT  PAGE_READONLY                     MEM_IMAGE   C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
0x00007FF70E581000        0x43000 MEM_COMMIT  PAGE_EXECUTE_READ                 MEM_IMAGE   C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
0x00007FF70E5C4000        0x17000 MEM_COMMIT  PAGE_READONLY                     MEM_IMAGE   C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.

--snip--

0x00007FFC3C06C000        0x54000 MEM_FREE    PAGE_NOACCESS                     NONE        N/A
0x00007FFC3C0C0000         0x1000 MEM_COMMIT  PAGE_READONLY                     MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFC3C0C1000       0x12A000 MEM_COMMIT  PAGE_EXECUTE_READ                 MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFC3C1EB000        0x48000 MEM_COMMIT  PAGE_READONLY                     MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFC3C233000         0x1000 MEM_COMMIT  PAGE_READWRITE                    MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFC3C234000         0x2000 MEM_COMMIT  PAGE_WRITECOPY                    MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFC3C236000         0x8000 MEM_COMMIT  PAGE_READWRITE                    MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFC3C23E000        0x89000 MEM_COMMIT  PAGE_READONLY                     MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFC3C2C7000    0x3C3D29000 MEM_FREE    PAGE_NOACCESS                     NONE        N/A

[*] Completed.
```


## Dump Memory

[Back to Top](#procmemscan)

To get basic information of a specific memory region for a remote process, set `-d` flag and base address with `-b` option in hex as follows (default base address is `0x000000000`):

```
PS C:\Tools> .\ProcMemScan.exe -p 6888 -d

[>] Trying to get target process information.
[*] Target process is 'Notepad' (PID : 6888).
[+] Got target process memory.
    [*] BaseAddress       : 0x0000000000000000
    [*] AllocationBase    : 0x0000000000000000
    [*] RegionSize        : 0x18470000
    [*] AllocationProtect : NONE
    [*] State             : MEM_FREE
    [*] Protect           : PAGE_NOACCESS
    [*] Type              : NONE
    [*] Mapped File Path  : N/A
[*] Completed.

PS C:\Tools> .\ProcMemScan.exe -p 6888 -d -b 0x00007FFC3B591ABC

[>] Trying to get target process information.
[*] Target process is 'Notepad' (PID : 6888).
[+] Got target process memory.
    [*] BaseAddress       : 0x00007FFC3B591000
    [*] AllocationBase    : 0x00007FFC3B590000
    [*] RegionSize        : 0x7D000
    [*] AllocationProtect : PAGE_EXECUTE_WRITECOPY
    [*] State             : MEM_COMMIT
    [*] Protect           : PAGE_EXECUTE_READ
    [*] Type              : MEM_IMAGE
    [*] Mapped File Path  : C:\Windows\System32\kernel32.dll
[*] Completed.
```

You can get hexdump by setting memory region size with `-r` option in hex:

```
PS C:\Tools> .\ProcMemScan.exe -p 6888 -d -b 0x00007FFC3B590000 -r 0x100

[>] Trying to get target process information.
[*] Target process is 'Notepad' (PID : 6888).
[+] Got target process memory.
    [*] BaseAddress       : 0x00007FFC3B590000
    [*] AllocationBase    : 0x00007FFC3B590000
    [*] RegionSize        : 0x1000
    [*] AllocationProtect : PAGE_EXECUTE_WRITECOPY
    [*] State             : MEM_COMMIT
    [*] Protect           : PAGE_READONLY
    [*] Type              : MEM_IMAGE
    [*] Mapped File Path  : C:\Windows\System32\kernel32.dll
    [*] Hexdump (0x100 Bytes):

                           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

        00007FFC3B590000 | 4D 5A 90 00 03 00 00 00-04 00 00 00 FF FF 00 00 | MZ...... ....ÿÿ..
        00007FFC3B590010 | B8 00 00 00 00 00 00 00-40 00 00 00 00 00 00 00 | ,....... @.......
        00007FFC3B590020 | 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 | ........ ........
        00007FFC3B590030 | 00 00 00 00 00 00 00 00-00 00 00 00 F8 00 00 00 | ........ ....o...
        00007FFC3B590040 | 0E 1F BA 0E 00 B4 09 CD-21 B8 01 4C CD 21 54 68 | ..º..'.I !,.LI!Th
        00007FFC3B590050 | 69 73 20 70 72 6F 67 72-61 6D 20 63 61 6E 6E 6F | is.progr am.canno
        00007FFC3B590060 | 74 20 62 65 20 72 75 6E-20 69 6E 20 44 4F 53 20 | t.be.run .in.DOS.
        00007FFC3B590070 | 6D 6F 64 65 2E 0D 0D 0A-24 00 00 00 00 00 00 00 | mode.... $.......
        00007FFC3B590080 | 6A 2A 90 63 2E 4B FE 30-2E 4B FE 30 2E 4B FE 30 | j*.c.K_0 .K_0.K_0
        00007FFC3B590090 | FD 39 FF 31 2A 4B FE 30-27 33 6D 30 E7 4B FE 30 | y9ÿ1*K_0 '3m0çK_0
        00007FFC3B5900A0 | 2E 4B FF 30 01 4E FE 30-FD 39 FA 31 24 4B FE 30 | .Kÿ0.N_0 y9ú1$K_0
        00007FFC3B5900B0 | FD 39 FE 31 2F 4B FE 30-FD 39 FD 31 2B 4B FE 30 | y9_1/K_0 y9y1+K_0
        00007FFC3B5900C0 | FD 39 F3 31 E1 4B FE 30-FD 39 01 30 2F 4B FE 30 | y9ó1áK_0 y9.0/K_0
        00007FFC3B5900D0 | FD 39 FC 31 2F 4B FE 30-52 69 63 68 2E 4B FE 30 | y9ü1/K_0 Rich.K_0
        00007FFC3B5900E0 | 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 | ........ ........
        00007FFC3B5900F0 | 00 00 00 00 00 00 00 00-50 45 00 00 64 86 07 00 | ........ PE..d...

[*] Completed.
```


## Extract Memory to File

[Back to Top](#procmemscan)

To extract memory as a file, set `-x` flag with base address and memory region size:

```
PS C:\Tools> .\ProcMemScan.exe -p 6888 -x -b 0x00007FFC3B590000 -r 0x100

[>] Trying to get target process information.
[*] Target process is 'Notepad' (PID : 6888).
[+] Got target process memory.
    [*] BaseAddress       : 0x00007FFC3B590000
    [*] AllocationBase    : 0x00007FFC3B590000
    [*] RegionSize        : 0x1000
    [*] AllocationProtect : PAGE_EXECUTE_WRITECOPY
    [*] State             : MEM_COMMIT
    [*] Protect           : PAGE_READONLY
    [*] Type              : MEM_IMAGE
    [*] Mapped File Path  : C:\Windows\System32\kernel32.dll
[>] Trying to export the specified memory.
    [*] File Path : C:\Tools\memory-0x00007FFC3B590000-0x100bytes.bin
[+] Memory is extracted successfully.

PS C:\Tools> dir .\memory-0x00007FFC3B590000-0x100bytes.bin


    Directory: C:\Tools


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/25/2022   9:17 PM            256 memory-0x00007FFC3B590000-0x100bytes.bin


PS C:\Tools> Format-Hex .\memory-0x00007FFC3B590000-0x100bytes.bin


           Path: C:\Tools\memory-0x00007FFC3B590000-0x100bytes.bin

           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00000000   4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  MZ..
```

If you don't specify memory region size, whole page from specified address will be extracted:

```
PS C:\Tools> .\ProcMemScan.exe -p 6888 -x -b 0x00007FFC3B590000

[>] Trying to get target process information.
[*] Target process is 'Notepad' (PID : 6888).
[+] Got target process memory.
    [*] BaseAddress       : 0x00007FFC3B590000
    [*] AllocationBase    : 0x00007FFC3B590000
    [*] RegionSize        : 0x1000
    [*] AllocationProtect : PAGE_EXECUTE_WRITECOPY
    [*] State             : MEM_COMMIT
    [*] Protect           : PAGE_READONLY
    [*] Type              : MEM_IMAGE
    [*] Mapped File Path  : C:\Windows\System32\kernel32.dll
[>] Trying to export the specified memory.
    [*] File Path : C:\Tools\memory-0x00007FFC3B590000-0x1000bytes.bin
[+] Memory is extracted successfully.

PS C:\Tools> dir .\memory-0x00007FFC3B590000-0x1000bytes.bin


    Directory: C:\Tools


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/25/2022   9:20 PM           4096 memory-0x00007FFC3B590000-0x1000bytes.bin
```


## Extract PE Image from Memory

[Back to Top](#procmemscan)

To extract PE image file from a remote process, set `-i` flag with `-x` flag and specify base address of PE header (MZ magic).
Extracted PE image files are incomplete, so we cannot execute it as executable files.
But it is sufficient for reverse engineering with disassembler such as Ghidra.

```
PS C:\Tools> .\ProcMemScan.exe -p 6888 -b 0x00007FF70E580000 -r 0x80 -d

[>] Trying to get target process information.
[*] Target process is 'Notepad' (PID : 6888).
[+] Got target process memory.
    [*] BaseAddress       : 0x00007FF70E580000
    [*] AllocationBase    : 0x00007FF70E580000
    [*] RegionSize        : 0x1000
    [*] AllocationProtect : PAGE_EXECUTE_WRITECOPY
    [*] State             : MEM_COMMIT
    [*] Protect           : PAGE_READONLY
    [*] Type              : MEM_IMAGE
    [*] Mapped File Path  : C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2203.10.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
    [*] Hexdump (0x80 Bytes):

                           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

        00007FF70E580000 | 4D 5A 90 00 03 00 00 00-04 00 00 00 FF FF 00 00 | MZ...... ....ÿÿ..
        00007FF70E580010 | B8 00 00 00 00 00 00 00-40 00 00 00 00 00 00 00 | ,....... @.......
        00007FF70E580020 | 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 | ........ ........
        00007FF70E580030 | 00 00 00 00 00 00 00 00-00 00 00 00 08 01 00 00 | ........ ........
        00007FF70E580040 | 0E 1F BA 0E 00 B4 09 CD-21 B8 01 4C CD 21 54 68 | ..º..'.I !,.LI!Th
        00007FF70E580050 | 69 73 20 70 72 6F 67 72-61 6D 20 63 61 6E 6E 6F | is.progr am.canno
        00007FF70E580060 | 74 20 62 65 20 72 75 6E-20 69 6E 20 44 4F 53 20 | t.be.run .in.DOS.
        00007FF70E580070 | 6D 6F 64 65 2E 0D 0D 0A-24 00 00 00 00 00 00 00 | mode.... $.......

[*] Completed.

PS C:\Tools> .\ProcMemScan.exe -p 6888 -b 0x00007FF70E580000 -x -i

[>] Trying to get target process information.
[*] Target process is 'Notepad' (PID : 6888).
[>] Trying to export the specified memory.
    [*] File Path          : C:\Tools\image-0x00007FF70E580000-Notepad_exe-AMD64.bin
    [*] Image Architecture : AMD64
[+] Image file is extracted successfully.

PS C:\Tools> dir .\image-0x00007FF70E580000-Notepad_exe.bin


    Directory: C:\Tools


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/25/2022   9:24 PM         470528 image-0x00007FF70E580000-Notepad_exe.bin
```


## Scan Suspicious Things

[Back to Top](#procmemscan)

To perform simple scan suspicious things in remote process, set `-s` flag.
The scan would contain false positive / negative.
Signature may be updated later.

For example, if we execute [Process Herpaderping PoC](../ProcessHerpaderping) as follows:

```
PS C:\Tools> .\ProcessHerpaderping.exe -f explorer -r cmd

[*] Got target information.
    [*] Image Path Name : C:\Windows\explorer.exe
    [*] Architecture    : x64
    [*] Command Line    : explorer
[>] Analyzing PE image data.
[>] Trying to create payload file.
    [*] File Path : C:\Users\admin\AppData\Local\Temp\tmp386.tmp
[+] Payload is written successfully.
[>] Trying to create herpaderping process.
[+] Herpaderping process is created successfully.
[+] Got herpaderping process basic information.
    [*] ntdll!_PEB : 0x0000008FC4F73000
    [*] Process ID : 7432
[*] Image base address for the herpaderping process is 0x00007FF643B30000.
[+] Trying to update image file to fake image.
[+] Fake image data is written successfully.
[>] Trying to start herpaderping process thread.
[+] Thread is resumed successfully.
[*] This technique remains payload file. Remove it mannually.
    [*] Payload File Path : C:\Users\admin\AppData\Local\Temp\tmp386.tmp
```

the scan outputs following result:

```
PS C:\Tools> .\ProcMemScan.exe -p 7432 -s

[>] Trying to scan target process.
[*] Target process is 'tmp386.tmp' (PID : 7432).
[!] Found suspicious things:
    [!] The mapped file for ntdll!_PEB.ImageBaseAddress does not match ProcessParameters.ImagePathName.
        [*] Mapped File for ImageBaseAddress : C:\Users\admin\AppData\Local\Temp\tmp386.tmp
        [*] ProcessParameters.ImagePathName  : C:\Windows\explorer.exe
[*] Completed.
```
