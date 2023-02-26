# Tangled WinExec

This repository is for investigation of Windows process execution techniques.
Most of PoCs are given a name corresponding to the technique.



## Projects

* __[BlockingDLL](./BlockingDLL) :__ This toolset is for testing blocking DLL process. See [README.md](./BlockingDLL/README.md).

* __[CommandLineSpoofing](./CommandLineSpoofing) :__ This PoC performs Command Line Spoofing. This technique may not work for Windows 11.

* __[DarkLoadLibrary](./DarkLoadLibrary/) :__ PoCs in this directory are for testing Dark Load Library which is released by [@\_batsec\_](https://twitter.com/_batsec_). See [README.md](./DarkLoadLibrary/README.md)

* __[GhostlyHollowing](./GhostlyHollowing) :__ This PoC performs Ghostly Hollowing.

* __[Misc](./Misc) :__ This directory is for helper tools to development PoCs in this repository.

* __[PhantomDllHollower](./PhantomDllHollower) :__ This PoC performs Phantom DLL Hollowing. See [README.md](./PhantomDllHollower/README.md).

* __[PPIDSpoofing](./PPIDSpoofing) :__ This PoC performs PPID Spoofing.

* __[ProcessDoppelgaenging](./ProcessDoppelgaenging) :__ This PoC performs Process Doppelgänging. Due to kernel protection improvement for Microsoft Defender, this technique does not work for recent Windows OS (since about 2021, maybe). So if you want to test this technique in newer environment, must be stop `Microsoft/Windows Defender Antivirus Service`. See [the issue](https://github.com/hasherezade/process_doppelganging/issues/3) for [hasherezade](https://twitter.com/hasherezade)'s repository.

* __[ProcessGhosting](./ProcessGhosting) :__ This PoC performs Process Ghosting. Due to kernel protection, this technique does not work for newer Windows from 22H2.

* __[ProcessHerpaderping](./ProcessHerpaderping) :__ This PoC performs Process Herpaderping. Due to file lock issue, if you choose a fake image file smaller than you want to execute, file size shrinking will be failed and corrupt file signature for herpaderping process. To take full advantage of this technique, fake image file size should be larger than you want to execute. Due to kernel protection, this technique does not work for newer Windows from 22H2.

* __[ProcessHollowing](./ProcessHollowing) :__ This PoC performs Process Hollowing. Unlike the original, the PE image is parsed into a new memory area instead of using `ZwUnmapViewOfSection` / `NtUnmapViewOfSection`.

* __[ProcMemScan](./ProcMemScan) :__ This is a diagnostic tool to investigate remote process. See [README.md](./ProcMemScan/README.md).

* __[ProtectedProcess](./ProtectedProcess) :__ This toolset is for testing Protected Process. See [README.md](./ProtectedProcess/README.md).

* __[ReflectiveDLLInjection](./ReflectiveDLLInjection) :__ This toolset is for testing Reflective DLL Injection. See [README.md](./ReflectiveDLLInjection/README.md).

* __[TransactedHollowing](./TransactedHollowing) :__ This PoC performs Transacted Hollowing.

* __[WmiSpawn](./WmiSpawn) :__ This PoC tries to spawn process with WMI. The processes will be spawn as child processes of `WmiPrvSE.exe`. Supports local machine process execution and remote machine process execution. The usage can see [README.md](./WmiSpawn/README.md).

> __NOTE :__ Currently [ProcessHollowing](./ProcessGhosting) code does not works for Debug build. To test it, use Release build. See [this issue](https://github.com/daem0nc0re/TangledWinExec/issues/1).


## Reference

### Blocking DLL

* [Preventing 3rd Party DLLs from Injecting into your Malware](https://www.ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes)

* [Staying Under the Radar - Part 1 - PPID Spoofing and Blocking DLLs](https://crypt0ace.github.io/posts/Staying-under-the-Radar/)

* [PPID Spoofing & BlockDLLs with NtCreateUserProcess](https://offensivedefence.co.uk/posts/ntcreateuserprocess/)

### Command Line Spoofing

* [Hide Artifacts: Process Argument Spoofing](https://attack.mitre.org/techniques/T1564/010/)

* [The return of the spoof part 2: Command line spoofing](https://blog.nviso.eu/2020/02/04/the-return-of-the-spoof-part-2-command-line-spoofing/)


### Dark Load Library

* [GitHub - bats3c/DarkLoadLibrary](https://github.com/bats3c/DarkLoadLibrary)

* [Bypassing Image Load Kernel Callbacks](https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/)


### Phantom DLL Hollowing

* [Masking Malicious Memory Artifacts – Part I: Phantom DLL Hollowing](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing)

* [GitHub - forrest-orr/phantom-dll-hollower-poc](https://github.com/forrest-orr/phantom-dll-hollower-poc)

### PPID Spoofing

* [Access Token Manipulation: Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004/)

* [Parent PID Spoofing (Mitre:T1134)](https://www.hackingarticles.in/parent-pid-spoofing-mitret1134/)

* [How to Detect Parent PID (PPID) Spoofing Attacks](https://www.picussecurity.com/resource/blog/how-to-detect-parent-pid-ppid-spoofing-attacks)

* [Parent Process ID (PPID) Spoofing](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing)

* [The return of the spoof part 1: Parent process ID spoofing](https://blog.nviso.eu/2020/01/31/the-return-of-the-spoof-part-1-parent-process-id-spoofing/)


### Process Doppelgänging

* [Lost in Transaction: Process Doppelgänging](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf)

* [Process Injection: Process Doppelgänging](https://attack.mitre.org/techniques/T1055/013/)

* [Process Doppelgänging – a new way to impersonate a process](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/)


### Process Ghosting

* [What you need to know about Process Ghosting, a new executable image tampering attack](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack)

* [Process Ghosting Attack](https://www.hackingarticles.in/process-ghosting-attack/)


### Process Herpaderping

* [GitHub - jxy-s/herpaderping](https://github.com/jxy-s/herpaderping)

* [Process Herpaderping](https://jxy-s.github.io/herpaderping/)

* [Process Herpaderping (Mitre:T1055)](https://www.hackingarticles.in/process-herpaderping-mitret1055/)

### Process Hollowing

* [Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)

* [Process Hollowing and Portable Executable Relocations](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)


### Ghostly Hollowing and Transacted Hollowing

* [GitHub - hasherezade/transacted_hollowing](https://github.com/hasherezade/transacted_hollowing)

### Protected Process

* [Unknown Known DLLs](http://publications.alex-ionescu.com/Recon/Recon%202018%20-%20Unknown%20Known%20DLLs%20and%20other%20code%20integrity%20trust%20violations.pdf)

* [Unreal Mode : Breaking Protected Processes](https://www.nosuchcon.org/talks/2014/D3_05_Alex_ionescu_Breaking_protected_processes.pdf)

* [The Evolution of Protected Processes – Part 1: Pass-the-Hash Mitigations in Windows 8.1](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/)

* [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.crowdstrike.com/blog/evolution-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and/)

* [Protected Processes Part 3 : Windows PKI Internals (Signing Levels, Scenarios, Root Keys, EKUs & Runtime Signers)](https://www.crowdstrike.com/blog/protected-processes-part-3-windows-pki-internals-signing-levels-scenarios-signers-root-keys/)

* [Windows Exploitation Tricks: Exploiting Arbitrary Object Directory Creation for Local Elevation of Privilege](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html)

* [Injecting Code into Windows Protected Processes using COM - Part 1](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html)

* [Injecting Code into Windows Protected Processes using COM - Part 2](https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html)

* [Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/)

* [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/)

* [Debugging Protected Processes](https://itm4n.github.io/debugging-protected-processes/)

* [The End of PPLdump](https://itm4n.github.io/the-end-of-ppldump/)

* [Protecting Windows protected processes](https://www.elastic.co/blog/protecting-windows-protected-processes)

* [Relevance of Security Features Introduced in Modern Windows OS](https://aaltodoc.aalto.fi/bitstream/handle/123456789/38990/master_Aquilino_Broderick_2019.pdf?sequence=1&isAllowed=y)

* [Bypassing LSA Protection (aka Protected Process Light) without Mimikatz on Windows 10](https://redcursor.com.au/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10/)

* [Debugging the undebuggable and finding a CVE in Microsoft Defender for Endpoint](https://medium.com/falconforce/debugging-the-undebuggable-and-finding-a-cve-in-microsoft-defender-for-endpoint-ce36f50bb31)


### Reflective DLL Injection

* [GitHub - stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)


## Acknowledgments

Thanks for your research:

* Tal Liberman ([@tal_liberman](https://twitter.com/tal_liberman))

* Eugene Kogan ([@EuKogan](https://twitter.com/EuKogan))

* hasherezade ([@hasherezade](https://twitter.com/hasherezade))

* Gabriel Landau ([@GabrielLandau](https://twitter.com/GabrielLandau))

* Forrest Orr ([@_forrestorr](https://twitter.com/_forrestorr))

* Stephen Fewer ([@stephenfewer](https://twitter.com/stephenfewer))

* batsec ([@\_batsec\_](https://twitter.com/_batsec_))