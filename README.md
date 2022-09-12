# Tangled WinExec

This repository is for investigation of Windows process execution techniques.
Most of PoCs are given a name corresponding to the technique.



## Projects

* __[CommandLineSpoofing](./CommandLineSpoofing) :__ This PoC performs Command Line Spoofing.

* __[GhostlyHollowing](./GhostlyHollowing) :__ This PoC performs Ghostly Hollowing.

* __[PPIDSpoofing](./PPIDSpoofing) :__ This PoC performs PPID Spoofing.

* __[ProcessDoppelgaenging](./ProcessDoppelgaenging) :__ This PoC performs Process Doppelgänging. Due to kernel protection improvement, this technique does not work for recent Windows OS (> Windows 10 Version 1809, as far as I tested). See [the issue](https://github.com/hasherezade/process_doppelganging/issues/3) for [hasherezade](https://twitter.com/hasherezade)'s repository.

* __[ProcessGhosting](./ProcessGhosting) :__ This PoC performs Process Ghosting.

* __[ProcessHollowing](./ProcessHollowing) :__ This PoC performs Process Hollowing. Unlike the original, the PE image is parsed into a new memory area instead of using `ZwUnmapViewOfSection` / `NtUnmapViewOfSection`.

* __[TransactedHollowing](./TransactedHollowing) :__ This PoC performs Transacted Hollowing.

* __[WmiSpawn](./WmiSpawn) :__ This PoC tries to spawn process with WMI. The processes will be spawn as child processes of `WmiPrvSE.exe`. Supports local machine process execution and remote machine process execution. The usage can see [README.md](./WmiSpawn/README.md).

> __NOTE__: Currently [ProcessHollowing](./ProcessGhosting) code does not works for Debug build. To test it, use Release build. See [this issue](https://github.com/daem0nc0re/TangledWinExec/issues/1).


## Reference

### Command Line Spoofing

* [https://attack.mitre.org/techniques/T1564/010/](https://attack.mitre.org/techniques/T1564/010/)

* [https://blog.nviso.eu/2020/02/04/the-return-of-the-spoof-part-2-command-line-spoofing/](https://blog.nviso.eu/2020/02/04/the-return-of-the-spoof-part-2-command-line-spoofing/)

### PPID Spoofing

* [https://attack.mitre.org/techniques/T1134/004/](https://attack.mitre.org/techniques/T1134/004/)

* [https://www.hackingarticles.in/parent-pid-spoofing-mitret1134/](https://www.hackingarticles.in/parent-pid-spoofing-mitret1134/)

* [https://www.picussecurity.com/resource/blog/how-to-detect-parent-pid-ppid-spoofing-attacks](https://www.picussecurity.com/resource/blog/how-to-detect-parent-pid-ppid-spoofing-attacks)

* [https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing)

* [https://blog.nviso.eu/2020/01/31/the-return-of-the-spoof-part-1-parent-process-id-spoofing/](https://blog.nviso.eu/2020/01/31/the-return-of-the-spoof-part-1-parent-process-id-spoofing/)


### Process Doppelgänging

* [https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf)

* [https://attack.mitre.org/techniques/T1055/013/](https://attack.mitre.org/techniques/T1055/013/)

* [https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/)


### Process Ghosting

* [https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack)

* [https://www.hackingarticles.in/process-ghosting-attack/](https://www.hackingarticles.in/process-ghosting-attack/)


### Process Hollowing

* [https://attack.mitre.org/techniques/T1055/012/](https://attack.mitre.org/techniques/T1055/012/)

* [https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)


### GhostlyHollowing and Transacted Hollowing

* [https://github.com/hasherezade/transacted_hollowing](https://github.com/hasherezade/transacted_hollowing)


## Acknowledgments

Thanks for your research:

* Tal Liberman ([@tal_liberman](https://twitter.com/tal_liberman))

* Eugene Kogan ([@EuKogan](https://twitter.com/EuKogan))

* hasherezade ([@hasherezade](https://twitter.com/hasherezade))

* Gabriel Landau ([@GabrielLandau](https://twitter.com/GabrielLandau))
