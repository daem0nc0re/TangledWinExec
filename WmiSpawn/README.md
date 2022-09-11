# WmiSpawn

This is a PoC to invesitgate WMI process execution technique.
Using WMI functionallity, we can spawn any process as a child process of `WmiPrvSE.exe`.
This tool supports not only local machine's process execution but also remote machine's process execution.

## Usage
```
C:\Tools>WmiSpawn.exe -h

WmiSpawn - PoC for WMI process execution.

Usage: WmiSpawn.exe [Options]

        -h, --help     : Displays this help message.
        -d, --domain   : Specifies domain name. Used with -k flag.
        -u, --username : Specifies username. Used with -k or -n flag
        -p, --password : Specifies password. Used with -k or -n flag
        -s, --server   : Specifies remote server. Used with -k or -n flag
        -c, --command  : Specifies command to execute.
        -t, --timeout  : Specifies timeout in seconds. Defualt is 3 seconds.
        -k, --kerberos : Flag for Kerberos authentication.
        -n, --ntlm     : Flag for NTLM authentication.
        -v, --visible  : Flag to show GUI. Effective in local process execution.
        -f, --full     : Flag to enable all available privileges.
```

### Local Machine Process

To execute a process, provides a command by `-c` option.
Specified command will be executed by `WmiPrvSE.exe`.
If you want to show the process GUI, specifies `-v` flag.
By default, the process runs with only `Default Enabled` privileges.
To enable all available privileges, set `-f` flag:

```
C:\Tools>WmiSpawn.exe -c "notepad.exe C:\aa.txt"

[>] Trying to connect WMI server.
    [*] Server : \\CL01\root\cimv2
[+] Connected to the target server successfully.
[>] Trying to execute process via WMI.
    [*] Command Line : notepad.exe C:\aa.txt
    [*] Visible      : False
[+] Process will be executed from WmiPrvSE.exe.
    [*] Process ID : 3432
[*] Completed.


C:\Tools>powershell -c "Get-Process -Id 3432"

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    196      13     2872      12352       0.02   3432   1 notepad
```


### Remote Machine Process

To execute processes with WMI in remote machine, specify target hostname by `-s` option.
If you want to use NTLM authentication, set `-n` flag and provides administrative user credentials with `-u` option and `-p` options as follows:

```
C:\Tools>WmiSpawn.exe -c "notepad.exe" -s CL02 -u .\admin -p Passw0rd! -n

[*] NTLM authentication mode.
    [*] Username : .\admin
    [*] Password : Passw0rd!
[>] Trying to connect WMI server.
    [*] Server : \\CL02\root\cimv2
[+] Connected to the target server successfully.
[>] Trying to execute process via WMI.
    [*] Command Line : notepad.exe
    [*] Visible      : False
[+] Process will be executed from WmiPrvSE.exe.
    [*] Process ID : 3588
[*] Completed.
```

To use Kerberos authentication, use `-k` flag insted of `-n` flag.
This should work only in Active Directory domain machine.

```
C:\Tools>whoami
contoso\david

C:\Tools>WmiSpawn.exe -c "notepad.exe" -s CL02 -u contoso\jeff -p Passw0rd! -k

[*] Kerberos authentication mode.
    [*] Domain   : contoso.local
    [*] Username : contoso\jeff
    [*] Password : Passw0rd!
[>] Trying to connect WMI server.
    [*] Server : \\CL02\root\cimv2
[+] Connected to the target server successfully.
[>] Trying to execute process via WMI.
    [*] Command Line : notepad.exe
    [*] Visible      : False
[+] Process will be executed from WmiPrvSE.exe.
    [*] Process ID : 1868
[*] Completed.
```

If administrative account ticket is applied to your session, you can execute process without credentials as follows:

```
C:\Tools>hostname
CL01

C:\Tools>whoami
contoso\jeff

C:\Tools>WmiSpawn.exe -c "notepad.exe" -s CL02 -k

[*] Kerberos authentication mode.
    [*] Domain   : contoso.local
    [*] Username : (null)
    [*] Password : (null)
[>] Trying to connect WMI server.
    [*] Server : \\CL02\root\cimv2
[+] Connected to the target server successfully.
[>] Trying to execute process via WMI.
    [*] Command Line : notepad.exe
    [*] Visible      : False
[+] Process will be executed from WmiPrvSE.exe.
    [*] Process ID : 6396
[*] Completed.
```