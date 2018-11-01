# CVEs and PoCs Resources

## Genereal

Some CVEs PoCs repos on github or internet.

* First, see: [Awesome CVE PoC](https://github.com/qazbnm456/awesome-cve-poc) by [qazbnm456](https://github.com/qazbnm456).
* To search (without PoCs): [cve-search](https://github.com/cve-search/cve-search) you can use it off-line too.
* This is a nice Wrapper:[vFeed](https://github.com/toolswatch/vFeed).
* Automated Generation of Proofs of Vulnerability with [S2E](https://github.com/S2E/docs/blob/master/src/Tutorials/pov.rst)

## Linux

 * Spectre : [CVE-2017-5753,CVE-2017-5715](https://gist.github.com/Badel2/ba8826e6607295e6f26c5ed098d98d27)
 * Dirty Cow: [CVE-2016-5195](https://github.com/scumjr/dirtycow-vdso) [Others](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)
 * "Root" via dirtyc0w privilege escalation [exploit](https://gist.github.com/Arinerron/0e99d69d70a778ca13a0087fa6fdfd80)
 * Huge Dirty Cow: [CVE-2017-1000405](https://github.com/bindecy/HugeDirtyCowPOC)
 * SMEP,SMAP and Chrome Sandbox: [CVE-2017-5123](https://salls.github.io/Linux-Kernel-CVE-2017-5123/)
 * SambaCry: [CVE-2017-7494](https://securelist.com/sambacry-is-coming/78674/)
 * The Stack Clash: [CVE-2017-1000364](https://blog.qualys.com/securitylabs/2017/06/19/the-stack-clash)
 * GoAhead web server: [CVE-2017-17562](https://www.elttam.com.au/blog/goahead/)
 * [New bypass and protection techniques for ASLR on Linux](http://blog.ptsecurity.com/2018/02/new-bypass-and-protection-techniques.html)
 * Ubuntu CVES: [CVE-2017-16995](https://github.com/Spacial/csirt/blob/master/PoCs/ubuntu_%20CVE-2017-16995.c), [netfilter](https://github.com/Spacial/csirt/blob/master/PoCs/ubuntu_netfilter.c), [CVE-2013-1763](https://github.com/Spacial/csirt/blob/master/PoCs/ubuntu_%20CVE-2013-1763.c)
 * Linux Kernel Version 4.14 - 4.4 (Ubuntu && Debian): [CVE-2017-16995](https://github.com/iBearcat/CVE-2017-16995)
 * Meltdown/Spectre: [Understanding Spectre and Meltdown Vulnerability](https://miuv.blog/2018/03/20/understanding-spectre-and-meltdown-vulnerability-part-2/)
 * Linux Kernel TCP implementation vulnerable to Denial of Service: [CVE-2018-5390](https://www.kb.cert.org/vuls/id/962459)
 * Linux Kernel Vulnerability Can Lead to Privilege Escalation: Analyzing [CVE-2017-1000112](https://securingtomorrow.mcafee.com/mcafee-labs/linux-kernel-vulnerability-can-lead-to-privilege-escalation-analyzing-cve-2017-1000112/). repo: [kernel-exploits](https://github.com/xairy/kernel-exploits): A bunch of proof-of-concept exploits for the Linux kernel.
 * Malicious Command Execution via bash-completion: [CVE-2018-7738](https://blog.grimm-co.com/post/malicious-command-execution-via-bash-completion-cve-2018-7738/)
 * An integer overflow flaw was found in the Linux kernel's create_elf_tables() function: [CVE-2018-14634](https://access.redhat.com/security/cve/cve-2018-14634)
 
## Solaris

* Kernel Level Privilege Escalation in Oracle Solaris: [CVE-2018-2892](https://www.trustwave.com/Resources/SpiderLabs-Blog/CVE-2018-2892---Kernel-Level-Privilege-Escalation-in-Oracle-Solaris/)
 
## Windows

 * Office: [CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199)
 * WebDAV: [CVE-2017-11882](https://github.com/embedi/CVE-2017-11882)
 * WSDL Parser: [CVE-2017-8759](https://github.com/Voulnet/CVE-2017-8759-Exploit-sample)
 * MS .NET: [CVE-2017-8759](https://github.com/bhdresh/CVE-2017-8759)
 * WPAD/PAC: [aPAColypse now](https://googleprojectzero.blogspot.com.br/2017/12/apacolypse-now-exploiting-windows-10-in_18.html)
 * Meltdown/Spectre:[CVE-2017-5754,CVE-2017-5715](https://github.com/ionescu007/SpecuCheck)
 * Packager OLE: [CVE-2018-0802](https://github.com/rxwx/CVE-2018-0802)
 * Integer Overflow: [Integer Overflow](https://github.com/k0keoyo/Dark_Composition_case_study_Integer_Overflow) 
 * Hardcore corruption of my execve() vulnerability in WSL: [CVE-2018-0743](https://github.com/saaramar/execve_exploit)
 * Privilege Escalation Vulnerability in Windows Standard Collector Service: [CVE-2018-0952](https://www.atredis.com/blog/cve-2018-0952-privilege-escalation-vulnerability-in-windows-standard-collector-service)
 * [Exploit Published for Windows Task Scheduler Zero-Day](https://www.securityweek.com/exploit-published-windows-task-scheduler-zero-day). [poc](https://github.com/SandboxEscaper/randomrepo)
 * [PowerPool](https://www.welivesecurity.com/2018/09/05/powerpool-malware-exploits-zero-day-vulnerability/) malware exploits ALPC LPE zero-day vulnerability
 * You can't contain me! :: Analyzing and Exploiting an Elevation of Privilege Vulnerability in Docker for Windows: [CVE-2018-15514](https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html)
* [Invoke-WMILM](https://github.com/Cybereason/Invoke-WMILM): This is a PoC script for various methods to acheive authenticated remote code execution via WMI, without (at least directly) using the Win32_Process class. The type of technique is determined by the "Type" parameter.
* Use-after-free (UAF) vulnerability: [CVE-2018-8373](https://blog.trendmicro.com/trendlabs-security-intelligence/new-cve-2018-8373-exploit-spotted/)
* Microsoft Edge RCE: [CVE-2018-8495](https://leucosite.com/Microsoft-Edge-RCE/)
* Device Guard/CLM bypass using MSFT_ScriptResource: [CVE-2018–8212](https://posts.specterops.io/cve-2018-8212-device-guard-clm-bypass-using-msft-scriptresource-b6cc2318e885)

## macOS/iOS

 * RootPiper:  [Demo/PoC](https://github.com/Shmoopi/RootPipe-Demo)  [Tester](https://github.com/sideeffect42/RootPipeTester)
 * [Mac Privacy: Sandboxed Mac apps can record your screen at any time without you knowing](https://github.com/KrauseFx/krausefx.com/blob/master/_posts/2018-02-10-mac-privacy-sandboxed-mac-apps-can-take-screenshots.md) by [Felix Krause](https://github.com/KrauseFx)
* [ROPLevel6 Writeup](https://github.com/shmoo419/ExploitChallengeWriteups/blob/master/ROPLevel6/Writeup.md)
* Escaping the sandbox by misleading bluetoothd:[CVE-2018-4087](https://blog.zimperium.com/cve-2018-4087-poc-escaping-sandbox-misleading-bluetoothd) 
* [Reexport symbols for Mach-O and ELF.](https://github.com/xerub/reexport)
* [Jailbreak for iOS 10.x 64bit devices without KTRR](https://github.com/tihmstar/doubleH3lix)
* MS Office 2016 for Mac Privilege Escalation via a Legacy Package: [CVE-2018–8412](https://medium.com/0xcc/cve-2018-8412-ms-office-2016-for-mac-privilege-escalation-via-a-legacy-package-7fccdbf71d9b)
* blanket: Mach port replacement vulnerability in launchd on iOS 11.2.6 leading to sandbox escape, privilege escalation, and codesigning bypass ([CVE-2018-4280](https://github.com/bazad/blanket))
* brokentooth: POC for [CVE-2018-4327](https://github.com/omerporze/brokentooth)
* Kernel RCE caused by buffer overflow in Apple's ICMP packet-handling code: [CVE-2018-4407](https://lgtm.com/blog/apple_xnu_icmp_error_CVE-2018-4407)

## Android

* [Please Stop Naming Vulnerabilities: Exploring 6 Previously Unknown Remote Kernel Bugs Affecting Android Phones](https://pleasestopnamingvulnerabilities.com)

## Java

* Spring Data Commons: [CVE-2018-1273](https://gist.github.com/matthiaskaiser/bfb274222c009b3570ab26436dc8799e)

## Apache Struts

  * How to find 5 RCEs in Apache Struts with Semmle QL: [CVE-2018-11776](https://lgtm.com/blog/apache_struts_CVE-2018-11776)
  * Semmle Discovers Critical Remote Code Execution Vulnerability in Apache Struts: [CVE-2018-11776](https://semmle.com/news/apache-struts-CVE-2018-11776), [docker Poc](https://github.com/jas502n/St2-057), [other poc](https://github.com/mazen160/struts-pwn_CVE-2018-11776)
  * [Apache Struts Vulnerability POC Code Found on GitHub](https://news.hitb.org/content/apache-struts-vulnerability-poc-code-found-github)
  * [struts-pwn](https://github.com/mazen160/struts-pwn_CVE-2018-11776): An exploit for Apache Struts CVE-2018-11776

## BMC 

* HPE iLO4: [CVE-2017-12542](https://github.com/airbus-seclab/ilo4_toolbox/blob/master/README.rst)

## x86

 * Spectre: [CVE-2017-5753,CVE-2017-5715](https://spectreattack.com/)
 * Meltdown: [CVE-2017-5754](https://meltdownattack.com/)
 * Cyberus: [Meltdown](http://blog.cyberus-technology.de/posts/2018-01-03-meltdown.html)
 * L1 Terminal Fault: [CVE-2018-3615/CVE-2018-3620/CVE-2018-3646/INTEL-SA-00161](https://software.intel.com/security-software-guidance/software-guidance/l1-terminal-fault)

## ARM

 * [ARM exploitation for IoT – Episode 3](https://quequero.org/2017/11/arm-exploitation-iot-episode-3/)
 * [Multiple vulnerabilities found in Wireless IP Camera](https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html#backdoor-account): CVE-2017-8224, CVE-2017-8222, CVE-2017-8225, CVE-2017-8223, CVE-2017-8221
 * [DoubleDoor](https://blog.newskysecurity.com/doubledoor-iot-botnet-bypasses-firewall-as-well-as-modem-security-using-two-backdoor-exploits-88457627306d), IoT Botnet bypasses firewall as well as modem security using two backdoor exploits: CVE-2015–7755 and CVE-2016–10401
 * [i.MX7 M4 Atomic Cache Bug](https://rschaefertech.wordpress.com/2018/02/17/imx7-hardware-bug/)
 
## Others

 * PHPMailer: [CVE-2016-10033](https://github.com/opsxcq/exploit-CVE-2016-10033)
 * Apache Tomcat: [CVE-2017-12617](https://github.com/cyberheartmi9/CVE-2017-12617)
 * Palo Alto Networks firewalls: Palo Alto Networks firewalls remote root code	execution [CVE-2017-15944](http://seclists.org/fulldisclosure/2017/Dec/38)
 * [Thttps://fail0verflow.com/blog/2017/ps4-namedobj-exploit/](https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/) and  [A fully implemented kernel exploit for the PS4 on 4.05FW](https://github.com/Cryptogenic/PS4-4.05-Kernel-Exploit)
 * [HOW TO HACK A TURNED-OFF COMPUTER, OR RUNNING UNSIGNED CODE IN INTEL ME](https://www.blackhat.com/docs/eu-17/materials/eu-17-Goryachy-How-To-Hack-A-Turned-Off-Computer-Or-Running-Unsigned-Code-In-Intel-Management-Engine-wp.pdf) (CVE-2017-5705, CVE-2017-5706, CVE-2017-5707), [github](https://github.com/ptresearch/unME11)
 * Nintendo Switch JailBreak PoC:[CVE-2016-4657](https://github.com/iDaN5x/Switcheroo/wiki/Article)
 * [Play with FILE Structure - Yet Another Binary Exploit Technique](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)
 * [Geovision Inc. IP Camera](https://github.com/mcw0/PoC/blob/master/Geovision%20IP%20Camera%20Multiple%20Remote%20Command%20Execution%20-%20Multiple%20Stack%20Overflow%20-%20Double%20free%20-%20Unauthorized%20Access.txt), with a lot others in this [repo](https://github.com/mcw0/PoC)
 * [Zero-day vulnerability in Telegram](https://securelist.com/zero-day-vulnerability-in-telegram/83800/)
 * PHP PrestaShop 1.6.x Privilege Escalation: [CVE-2018-13784](https://www.ambionics.io/blog/prestashop-privilege-escalation)
 * [Bug or Backdoor](https://0x09al.github.io/security/ispconfig/exploit/vulnerability/2018/08/20/bug-or-backdoor-ispconfig-rce.html): Exploiting a Remote Code Execution in ISPConfig by 0x09AL Security blog.
 * SSH Exploit written in Python for CVE-2018-15473 with threading and export formats: [CVE-2018-15473](https://github.com/Rhynorater/CVE-2018-15473-Exploit), [analysis](https://sekurak.pl/openssh-users-enumeration-cve-2018-15473/)
 * From Compiler Optimization to Code Execution - VirtualBox VM Escape: [CVE-2018-2844](https://www.voidsecurity.in/2018/08/from-compiler-optimization-to-code.html). [poc](https://github.com/renorobert/virtualbox-cve-2018-2844/)
 * [VirtualBox 3D PoCs & exploits](https://github.com/niklasb/3dpwn) 
 * [Multiple Vulnerabilities on Kerui Endoscope Camera](https://utkusen.com/blog/multiple-vulnerabilities-on-kerui-endoscope-camera.html)
* [RICOH MP 2001 Printer Cross Site Scripting ≈ Packet Storm](https://packetstormsecurity.com/files/149443/RICOH-MP-2001-Printer-Cross-Site-Scripting.html), [code](https://dl.packetstormsecurity.net/1809-exploits/richomp2001-xss.txt), [Cross-Site Scripting](https://www.exploit-db.com/exploits/45460/)
* Oracle WebLogic WLS-WSAT Remote Code Execution Exploit: [CVE-2017-10271](https://github.com/kkirsche/CVE-2017-10271)
* WebLogic Exploit: [CVE-2017-10271](https://github.com/c0mmand3rOpSec/CVE-2017-10271)

 ## Additions
 
 Please, send pull requests for new additions.
 
 Thanks!
