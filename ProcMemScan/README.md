# ProcMemScan

This tool is written for inspecting undebuggable process.
Following functionalities are implemented.

* [Get ntdll!_PEB information for a remote process as !peb command of WinDbg.](#dump-ntdllpeb-information)
* [Enumerate memory layout for a remote process.](#enumerate-memory)
* [Get export items from in-memory module.](#dump-export-items)
* [Get basic information and hexdump of a specific memory region for a remote process.](#dump-memory)
* [Extract data in a specific memory region for a remote process.](#extract-memory-to-file)
* [Extract PE image file in a specific memory region for a remote process.](#extract-pe-image-from-memory)
* [Find PE injected process.](#find-pe-injected-process)

## Dump ntdll!_PEB information

[Back to Top](#procmemscan)

To dump ntdll!_PEB information for a remote process, simply specify PID with `-p` option in decimal as follows:

```
PS C:\Tools> Get-Process notepad

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    580      34    32664      84604       0.67   2580   1 Notepad


PS C:\Tools> .\ProcMemScan.exe -p 7204

[*] Target process is 'Notepad' (PID : 2580).
[>] Trying to get target process information.

ntdll!_PEB @ 0x0000000D07740000
    InheritedAddressSpace    : FALSE
    ReadImageFileExecOptions : FALSE
    BeingDebugged            : FALSE
    ImageBaseAddress         : 0x00007FF72EE10000 (C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe)
    Ldr                      : 0x00007FFDBCD94380
    Ldr.Initialized          : TRUE
    Ldr.InInitializationOrderModuleList : { 0x000001FB2B204400 - 0x000001FB336336E0 }
    Ldr.InLoadOrderModuleList           : { 0x000001FB2B204590 - 0x000001FB336336C0 }
    Ldr.InMemoryOrderModuleList         : { 0x000001FB2B2045A0 - 0x000001FB336336D0 }
                      Base Reason                     Loaded              Module
        0x00007FF72EE10000 DynamicLoad                2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
        0x00007FFDBCC10000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\ntdll.dll
        0x00007FFDBABD0000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\KERNEL32.DLL
        0x00007FFDBA1C0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\KERNELBASE.dll
        0x00007FFDBCA70000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\SHLWAPI.dll
        0x00007FFDBB590000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\msvcrt.dll
        0x00007FFDBC130000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\USER32.dll
        0x00007FFDBA050000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\win32u.dll
        0x00007FFDBC0F0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\GDI32.dll
        0x00007FFDBA900000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\gdi32full.dll
        0x00007FFDBA740000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\msvcp_win.dll
        0x00007FFDBA7E0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\ucrtbase.dll
        0x00007FFDBBEF0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\ole32.dll
        0x00007FFDBC390000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\combase.dll
        0x00007FFDBBDD0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\RPCRT4.dll
        0x00007FFDBADB0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\SHELL32.dll
        0x00007FFDBCAD0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\COMDLG32.dll
        0x00007FFDBB640000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\shcore.dll
        0x00007FFDBACA0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\ADVAPI32.dll
        0x00007FFDBBC00000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\sechost.dll
        0x00007FFDBAA20000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\OLEAUT32.dll
        0x00007FFDBA560000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\CRYPT32.dll
        0x00007FFDA8F10000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\urlmon.dll
        0x00007FFDB5770000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\PROPSYS.dll
        0x00007FFDA40F0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.22621.317_none_a9434687c10c9fa2\COMCTL32.dll
        0x00007FFDB7A10000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\dwmapi.dll
        0x00007FFD9EAF0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\WINSPOOL.DRV
        0x00007FFDB76F0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\UxTheme.dll
        0x00007FFD92DF0000 StaticDependency           2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe\MSVCP140.dll
        0x00007FFD92DE0000 StaticDependency           2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe\VCRUNTIME140_1.dll
        0x00007FFD92930000 StaticDependency           2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe\VCRUNTIME140.dll
        0x00007FFDAE110000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\iertutil.dll
        0x00007FFDA89B0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\srvcli.dll
        0x00007FFDB8A90000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\netutils.dll
        0x00007FFDBB740000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\IMM32.DLL
        0x00007FFDB9080000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\kernel.appcore.dll
        0x00007FFDBA140000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\System32\bcryptPrimitives.dll
        0x00007FFDBC2E0000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\System32\clbcatq.dll
        0x00007FFDA5F80000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\MrmCoreR.dll
        0x00007FFDB1710000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\windows.staterepositoryclient.dll
        0x00007FFDB1750000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\windows.staterepositorycore.dll
        0x00007FFDB9F80000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\System32\profapi.dll
        0x00007FFDA5E00000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\Windows.UI.dll
        0x00007FFDA5D50000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\System32\bcp47mrm.dll
        0x00007FFDB3410000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\twinapi.appcore.dll
        0x00007FFDB7F70000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\WinTypes.dll
        0x00007FFDB80B0000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\windows.storage.dll
        0x00007FFD7E740000 DynamicLoad                2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe\Notepad\NotepadXamlUI.dll
        0x00007FFD9A450000 StaticDependency           2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\MSVCP140_APP.dll
        0x00007FFDB6060000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\DWrite.dll
        0x00007FFD9CBD0000 StaticDependency           2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\VCRUNTIME140_1_APP.dll
        0x00007FFD9A8C0000 StaticDependency           2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\VCRUNTIME140_APP.dll
        0x00007FFDA4A40000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\Windows.UI.Xaml.dll
        0x00007FFDB9F30000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\powrprof.dll
        0x00007FFDB9F00000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\UMPDC.dll
        0x00007FFDB2C50000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\OneCoreUAPCommonProxyStub.dll
        0x00007FFD7E590000 DynamicLoad                2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe\msptls.dll
        0x00007FFD7E040000 DynamicLoad                2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe\riched20.dll
        0x00007FFD9B190000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\Windows.Storage.ApplicationData.dll
        0x00007FFDAE890000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\InputHost.dll
        0x00007FFDB7240000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\CoreMessaging.dll
        0x00007FFDB9790000 DynamicForwarderDependency 2024/10/28 21:03:47 C:\Windows\SYSTEM32\CRYPTBASE.DLL
        0x00007FFDBBCB0000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\System32\MSCTF.dll
        0x00007FFDAB430000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\UiaManager.dll
        0x00007FFDB4250000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\System32\WindowManagementAPI.dll
        0x00007FFDB7810000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\SYSTEM32\dxgi.dll
        0x00007FFDB6BB0000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\dcomp.dll
        0x00007FFDB77D0000 DynamicForwarderDependency 2024/10/28 21:03:47 C:\Windows\SYSTEM32\dxcore.dll
        0x00007FFDA4680000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\Windows.UI.Immersive.dll
        0x00007FFDB51E0000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\directxdatabasehelper.dll
        0x00007FFDB0320000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\system32\DataExchange.dll
        0x00007FFDB6380000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\SYSTEM32\d3d11.dll
        0x00007FFDB2380000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\SYSTEM32\vm3dum64_loader.dll
        0x00007FFDB2070000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\system32\vm3dum64_10.dll
        0x00007FFDB2030000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\WINMM.dll
        0x00007FFDB2650000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\VERSION.dll
        0x00007FFD7D8D0000 DynamicLoad                2024/10/28 21:03:47 C:\Program Files\WindowsApps\Microsoft.UI.Xaml.2.8_8.2212.15002.0_x64__8wekyb3d8bbwe\Microsoft.UI.Xaml.dll
        0x00007FFDB65E0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\d2d1.dll
        0x00007FFDA3320000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\TextShaping.dll
        0x00007FFDA3630000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\SYSTEM32\Windows.UI.Xaml.Controls.dll
        0x00007FFDAEAF0000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\Bcp47Langs.dll
        0x00007FFDAD4C0000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\Windows.ApplicationModel.dll
        0x00007FFD9F520000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\uiautomationcore.dll
        0x00007FFDB9DD0000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\sxs.dll
        0x00007FFDA3E90000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\Windows.Globalization.dll
        0x00007FFD979C0000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\Windows.Energy.dll
        0x00007FFDB24E0000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\Windows.Graphics.dll
        0x00007FFDB9C50000 StaticDependency           2024/10/28 21:03:47 C:\Windows\SYSTEM32\cfgmgr32.dll
        0x00007FFDB9930000 StaticDependency           2024/10/28 21:03:47 C:\Windows\System32\bcrypt.dll
        0x00007FFDAC3A0000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\efswrt.dll
        0x00007FFDA0D70000 DynamicLoad                2024/10/28 21:03:47 C:\Windows\System32\oleacc.dll
        0x00007FFDAFC00000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\textinputframework.dll
        0x00007FFD9F460000 DelayloadDependency        2024/10/28 21:03:47 C:\Windows\SYSTEM32\globinputhost.dll
        0x00007FFDA3590000 DynamicLoad                2024/10/28 21:03:48 C:\Windows\system32\directmanipulation.dll
        0x00007FFDB5730000 DelayloadDependency        2024/10/28 21:03:48 C:\Windows\System32\XmlLite.dll
        0x00007FFDB5A20000 DynamicLoad                2024/10/28 21:03:48 C:\Windows\system32\windowscodecs.dll
        0x00007FFDB38F0000 DelayloadDependency        2024/10/28 21:03:48 C:\Windows\System32\wuceffects.dll
        0x00007FFDB4810000 DelayloadDependency        2024/10/28 21:03:48 C:\Windows\SYSTEM32\CoreUIComponents.dll
        0x00007FFDA2E40000 DynamicLoad                2024/10/28 21:03:48 C:\Windows\System32\threadpoolwinrt.dll
        0x00007FFD9F180000 DynamicLoad                2024/10/28 21:03:48 C:\Windows\System32\Windows.UI.Core.TextInput.dll
        0x00007FFDA4800000 DynamicLoad                2024/10/28 21:03:48 C:\Windows\System32\twinapi.dll
    SubSystemData     : 0x00007FFDB364E6A0
    ProcessHeap       : 0x000001FB2B040000
    ProcessParameters : 0x000001FB2B2037C0
    CurrentDirectory  : 'C:\Users\user\'
    WindowTitle       : 'C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe'
    ImagePathName     : 'C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe'
    CommandLine       : '"C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe" '
    DLLPath           : 'C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2302.26.0_x64__8wekyb3d8bbwe;C:\Program Files\WindowsApps\Microsoft.UI.Xaml.2.8_8.2212.15002.0_x64__8wekyb3d8bbwe;C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe;C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe;'
    Environment       : 0x000001FB2B202B10 (0xB88 Bytes)
        ALLUSERSPROFILE=C:\ProgramData
        APPDATA=C:\Users\user\AppData\Roaming
        CommonProgramFiles=C:\Program Files\Common Files
        CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
        CommonProgramW6432=C:\Program Files\Common Files
        COMPUTERNAME=DEV22H2
        ComSpec=C:\Windows\system32\cmd.exe
        DriverData=C:\Windows\System32\Drivers\DriverData
        HOMEDRIVE=C:
        HOMEPATH=\Users\user
        LOCALAPPDATA=C:\Users\user\AppData\Local
        LOGONSERVER=\\DEV22H2
        NUMBER_OF_PROCESSORS=2
        OneDrive=C:\Users\user\OneDrive
        OS=Windows_NT
        Path=C:\Program Files\Common Files\Oracle\Java\javapath;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Dev\Tools\SysinternalsSuite;C:\Dev\Tools\neo4j\bin;C:\Users\user\AppData\Local\Microsoft\WindowsApps
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
        TEMP=C:\Users\user\AppData\Local\Temp
        TMP=C:\Users\user\AppData\Local\Temp
        USERDOMAIN=dev22h2
        USERDOMAIN_ROAMINGPROFILE=dev22h2
        USERNAME=user
        USERPROFILE=C:\Users\user
        windir=C:\Windows


ACTIVE THREAD INFORMATION
-------------------------

  TID          CreateTime Priority BasePriority   State    WaitReason StartAddress
===== =================== ======== ============ ======= ============= ============
 9656 2024/10/28 21:03:47       10            8 Waiting WrUserRequest Notepad.exe+0x7B1AC
10012 2024/10/28 21:03:47        8            8 Waiting       WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 9960 2024/10/28 21:03:47        8            8 Waiting       WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 5280 2024/10/28 21:03:47        8            8 Waiting       WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 3512 2024/10/28 21:03:47        8            8 Waiting   UserRequest MrmCoreR.dll!GetStringValueForManifestField+0x3910
 1184 2024/10/28 21:03:47        8            8 Waiting   UserRequest ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 4236 2024/10/28 21:03:47        8            8 Waiting   UserRequest combase.dll!CoIncrementMTAUsage+0x3E60
 7856 2024/10/28 21:03:47        8            8 Waiting       WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 7800 2024/10/28 21:03:47        9            8 Waiting WrUserRequest ucrtbase.dll!recalloc+0x10
 4556 2024/10/28 21:03:47        8            8 Waiting   UserRequest SHCore.dll!SHCreateThreadRef+0x1430
 7764 2024/10/28 21:03:47       15           15 Waiting   UserRequest Windows.UI.Xaml.dll!DllCanUnloadNow+0x13C0
 7664 2024/10/28 21:03:47        8            8 Waiting   UserRequest combase.dll!CoIncrementMTAUsage+0x3E60
 6964 2024/10/28 21:03:47        9            8 Waiting   UserRequest SHCore.dll!SHCreateThreadRef+0x1430
 5604 2024/10/28 21:03:47        9            8 Waiting       WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 8944 2024/10/28 21:03:47       10            8 Waiting WrUserRequest ucrtbase.dll!recalloc+0x10
 9076 2024/10/28 21:03:48        8            8 Waiting   UserRequest directmanipulation.dll!DllGetClassObject+0x2840
 7192 2024/10/28 21:03:48        9            8 Waiting   UserRequest SHCore.dll!SHCreateThreadRef+0x1430
 6700 2024/10/28 21:03:48        8            8 Waiting       WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 6864 2024/10/28 21:03:49        8            8 Waiting   UserRequest SHCore.dll!SHCreateThreadRef+0x1430
 6252 2024/10/28 21:03:49        9            8 Waiting   UserRequest SHCore.dll!SHCreateThreadRef+0x1430

TERMINATED THREAD INFORMATION
-----------------------------

Nothing.

[*] Done.
```

To act as SYSTEM, set `-S` flag as follows:

```
PS C:\Tools> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1256      24     6720      19480       1.59    776   0 lsass


PS C:\Tools> .\ProcMemScan.exe -p 776

[*] Target process is 'lsass' (PID : 776).
[>] Trying to get target process information.

ntdll!_PEB @ 0x000000CB65866000
    InheritedAddressSpace    : FALSE
    ReadImageFileExecOptions : FALSE
    BeingDebugged            : FALSE
    ImageBaseAddress         : 0x00007FF62F620000 (C:\Windows\System32\lsass.exe)
    Ldr                      : 0x00007FFDBCD94380
    Ldr.Initialized          : TRUE
    Ldr.InInitializationOrderModuleList : { 0x00000250FDC03DE0 - 0x00000250FE643D20 }
    Ldr.InLoadOrderModuleList           : { 0x00000250FDC03F70 - 0x00000250FE643580 }
    Ldr.InMemoryOrderModuleList         : { 0x00000250FDC03F80 - 0x00000250FE643590 }
                      Base Reason                     Loaded              Module
        0x00007FF62F620000 DynamicLoad                2024/10/28 20:56:47 C:\Windows\system32\lsass.exe
        0x00007FFDBCC10000 StaticDependency           2024/10/28 20:56:47 C:\Windows\SYSTEM32\ntdll.dll
        0x00007FFDBABD0000 DynamicLoad                2024/10/28 20:56:47 C:\Windows\System32\KERNEL32.DLL

--snip--

        USERNAME=SYSTEM
        USERPROFILE=C:\Windows\system32\config\systemprofile
        windir=C:\Windows


ACTIVE THREAD INFORMATION
-------------------------

 TID          CreateTime Priority BasePriority   State   WaitReason StartAddress
==== =================== ======== ============ ======= ============ ============
 792 2024/10/28 20:56:47       10            9 Waiting WrLpcReceive N/A (Access is denied)
 808 2024/10/28 20:56:47        9            9 Waiting  UserRequest N/A (Access is denied)
 812 2024/10/28 20:56:47        9            9 Waiting      WrQueue N/A (Access is denied)
 820 2024/10/28 20:56:47       10            9 Waiting  UserRequest N/A (Access is denied)
5480 2024/10/28 20:56:57        9            9 Waiting  UserRequest N/A (Access is denied)
7560 2024/10/28 20:57:04        9            9 Waiting      WrQueue N/A (Access is denied)
6468 2024/10/28 21:02:51        9            9 Waiting      WrQueue N/A (Access is denied)
5128 2024/10/28 21:04:51        9            9 Waiting      WrQueue N/A (Access is denied)
3844 2024/10/28 21:06:32        9            9 Waiting      WrQueue N/A (Access is denied)

TERMINATED THREAD INFORMATION
-----------------------------

 TID          CreateTime Priority BasePriority      State   WaitReason StartAddress
==== =================== ======== ============ ========== ============ ============
 780 2024/10/28 20:56:47       10            9 Terminated WrTerminated N/A (Access is denied)
 828 2024/10/28 20:56:47       10            9 Terminated WrTerminated N/A (Access is denied)
 832 2024/10/28 20:56:47        9            9 Terminated WrTerminated N/A (Access is denied)
1188 2024/10/28 20:57:02        9            9 Terminated WrTerminated N/A (Access is denied)

[*] Done.

PS C:\Tools> .\ProcMemScan.exe -p 776 -S

[+] Got SYSTEM privileges.
[*] Target process is 'lsass' (PID : 776).
[>] Trying to get target process information.

ntdll!_PEB @ 0x000000CB65866000
    InheritedAddressSpace    : FALSE
    ReadImageFileExecOptions : FALSE
    BeingDebugged            : FALSE
    ImageBaseAddress         : 0x00007FF62F620000 (C:\Windows\System32\lsass.exe)
    Ldr                      : 0x00007FFDBCD94380
    Ldr.Initialized          : TRUE
    Ldr.InInitializationOrderModuleList : { 0x00000250FDC03DE0 - 0x00000250FE643D20 }
    Ldr.InLoadOrderModuleList           : { 0x00000250FDC03F70 - 0x00000250FE643580 }
    Ldr.InMemoryOrderModuleList         : { 0x00000250FDC03F80 - 0x00000250FE643590 }
                      Base Reason                     Loaded              Module
        0x00007FF62F620000 DynamicLoad                2024/10/28 20:56:47 C:\Windows\system32\lsass.exe
        0x00007FFDBCC10000 StaticDependency           2024/10/28 20:56:47 C:\Windows\SYSTEM32\ntdll.dll
        0x00007FFDBABD0000 DynamicLoad                2024/10/28 20:56:47 C:\Windows\System32\KERNEL32.DLL

--snip--

        USERNAME=SYSTEM
        USERPROFILE=C:\Windows\system32\config\systemprofile
        windir=C:\Windows


ACTIVE THREAD INFORMATION
-------------------------

 TID          CreateTime Priority BasePriority   State   WaitReason StartAddress
==== =================== ======== ============ ======= ============ ============
 792 2024/10/28 20:56:47       10            9 Waiting WrLpcReceive lsass.exe!LsaGetInterface+0x1700
 808 2024/10/28 20:56:47        9            9 Waiting  UserRequest lsasrv.dll!LsapGetCapeNamesForCap+0x950
 812 2024/10/28 20:56:47        9            9 Waiting      WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 820 2024/10/28 20:56:47       10            9 Waiting  UserRequest ucrtbase.dll!recalloc+0x10
5480 2024/10/28 20:56:57        9            9 Waiting  UserRequest ucrtbase.dll!crt_at_quick_exit+0x20
7560 2024/10/28 20:57:04        9            9 Waiting      WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
6468 2024/10/28 21:02:51        9            9 Waiting      WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
5128 2024/10/28 21:04:51        9            9 Waiting      WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
3844 2024/10/28 21:06:32        9            9 Waiting      WrQueue ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
1836 2024/10/28 21:07:30        9            9 Waiting  UserRequest crypt32.dll!I_CryptInstallAsn1Module+0x1F0

TERMINATED THREAD INFORMATION
-----------------------------

 TID          CreateTime Priority BasePriority      State   WaitReason StartAddress
==== =================== ======== ============ ========== ============ ============
 780 2024/10/28 20:56:47       10            9 Terminated WrTerminated lsass.exe!LsaRegisterExtension+0x120
 828 2024/10/28 20:56:47       10            9 Terminated WrTerminated ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
 832 2024/10/28 20:56:47        9            9 Terminated WrTerminated ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70
1188 2024/10/28 20:57:02        9            9 Terminated WrTerminated ntdll.dll!RtlClearThreadWorkOnBehalfTicket+0x70

[*] Done.
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

## Dump Export Items

[Back to Top](#procmemscan)

To dump export items from in-memory module, set `-e` flag and base address with `-b` option in hex format.
Base address must be base address of the target image file (`MZ` magic address):

```
PS C:\Dev> .\ProcMemScan.exe -p 3876 -e -b 0x00007FFBDB110000

[>] Trying to dump module exports from process memory.
[*] Target process is 'notepad' (PID : 3876).
[+] Got 1005 export(s).
    [*] Architecture : AMD64
    [*] Export Name  : USER32.dll
    [*] Export Items :
        [*] .text Section (999 Item(s)):
            [*] 0x00007FFBDB13C660 : ActivateKeyboardLayout
            [*] 0x00007FFBDB13CE40 : AddClipboardFormatListener
            [*] 0x00007FFBDB143990 : AddVisualIdentifier

--snip--

            [*] 0x00007FFBDB1373F0 : wvsprintfA
            [*] 0x00007FFBDB1399D0 : wvsprintfW

        [*] .rdata Section (5 Item(s)):
            [*] 0x00007FFBDB1B5360 : DefDlgProcA
            [*] 0x00007FFBDB1B5387 : DefDlgProcW
            [*] 0x00007FFBDB1B53FF : DefWindowProcA
            [*] 0x00007FFBDB1B5429 : DefWindowProcW
            [*] 0x00007FFBDB1A1990 : gapfnScSendMessage

        [*] .data Section (1 Item(s)):
            [*] 0x00007FFBDB1C3030 : gSharedInfo

[*] Done.

PS C:\Dev>
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


## Find PE Injected Process

[Back to Top](#procmemscan)

To find PE injected processes, set `-s` flag without `-p` option.
The scan would contain false positive / negative.
Implemented IoCs are following:

* __Memory allocation type for ImageBaseAddress is not MEM_IMAGE__

    If the injected PE image file was mapped manually, the memory type tends to be non MEM_IMAGE type.

* __Mapped file name for ImageBaseAddress cannot be specified__

    PE injected processes with some techniques such as Process Ghosting or Process Doppelgänging, mapped image file cannot be retrieved with `NtQueryVirtualMemory` API.

* __Process image name cannot be specified__

    PE injected processes with some techniques such as Process Ghosting, process image file cannot be retrieved with `NtQueryInformationProcess` API.

* __Mapped file name for ImageBaseAddress does not match with process image name__

    In PE injected processes, process image name retrieved by `NtQueryInformationProcess` API tends to not match with mapped image file for ImageBaseAddress retrived with `NtQueryVirtualMemory` API.

* __Mapped image file for ImageBaseAddress is not found__

    Mapped image file for some PE injected processes, would not be found on disk.

* __Mapped image file for ImageBaseAddress is different from image file on disk__

    PE injected processes with some techniques such as Process Herpaderping, mapped image file for ImageBaseAddress match with process image name retrieved by `NtQueryInformationProcess` API.
    However, mapped image file data does not match with image file on disk.
    To check this characteristic effectively, this tool calculates and compare SHA256 hash for static `_IMAGE_NT_HEADERS` data.

For example, if we execute [Transacted Hollowing PoC](../TransactedHollowing) as follows:

```
PS C:\Tools> .\TransactedHollowing.exe -f explorer -r cmd

[>] Loading image data.
[+] Image data is loaded successfully.
    [*] Architecture : AMD64
    [*] 64Bit Binary : True
[>] Trying to load target image file.
[+] Taget image is loaded successfully.
    [*] Image Path Name : C:\Windows\explorer.exe
    [*] Architecture    : AMD64
    [*] 64Bit Binary    : True
[>] Trying to create transacted file.
    [*] File Path : C:\Users\user\AppData\Local\Temp\tmpC5AA.tmp
[>] Trying to map transacted section to the hollowing process.
[+] Transacted section is mapped to the hollowing process successfully.
    [*] Section Base : 0x00007FF6C14B0000
[>] Trying to get ntdll!_PEB address for the hollowing process.
[+] Got hollowing process basic information.
    [*] ntdll!_PEB : 0x00000000008EA000
    [*] Process ID : 3672
[>] Trying to start hollowing process thread.
[+] Thread is resumed successfully.
[*] Done.
```

The scan outputs following result:

```
PS C:\Tools> .\ProcMemScan.exe -s

[>] Scanning all processes...

SUSPICIOUS PROCESSES
--------------------

 PID Process Name Reason
==== ============ ======
3672 explorer     Mapped file name for ImageBaseAddress cannot be specified.

[!] Found 1 suspicious process(es).
```

To scan a specific process, specify PID with `-p` as following:

```
PS C:\Tools> .\ProcMemScan.exe -s -p 3672

[*] Target process is 'explorer' (PID : 3672).
[>] Trying to scan target process.
[!] The specified process is suspicious.
    [*] IoC : Mapped file name for ImageBaseAddress cannot be specified.
[*] Done.
```
