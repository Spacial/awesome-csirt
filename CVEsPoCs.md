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
 
## macOS/iOS

 * RootPiper:  [Demo/PoC](https://github.com/Shmoopi/RootPipe-Demo)  [Tester](https://github.com/sideeffect42/RootPipeTester)
 * [Mac Privacy: Sandboxed Mac apps can record your screen at any time without you knowing](https://github.com/KrauseFx/krausefx.com/blob/master/_posts/2018-02-10-mac-privacy-sandboxed-mac-apps-can-take-screenshots.md) by [Felix Krause](https://github.com/KrauseFx)
* [ROPLevel6 Writeup](https://github.com/shmoo419/ExploitChallengeWriteups/blob/master/ROPLevel6/Writeup.md)
* Escaping the sandbox by misleading bluetoothd:[CVE-2018-4087](https://blog.zimperium.com/cve-2018-4087-poc-escaping-sandbox-misleading-bluetoothd) 
* [Reexport symbols for Mach-O and ELF.](https://github.com/xerub/reexport)
* [Jailbreak for iOS 10.x 64bit devices without KTRR](https://github.com/tihmstar/doubleH3lix)

## Android

* [Please Stop Naming Vulnerabilities: Exploring 6 Previously Unknown Remote Kernel Bugs Affecting Android Phones](https://pleasestopnamingvulnerabilities.com)

## Java

* Spring Data Commons: [CVE-2018-1273](https://gist.github.com/matthiaskaiser/bfb274222c009b3570ab26436dc8799e)

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
 * How to find 5 RCEs in Apache Struts with Semmle QL: [CVE-2018-11776](https://lgtm.com/blog/apache_struts_CVE-2018-11776)
 * Semmle Discovers Critical Remote Code Execution Vulnerability in Apache Struts: [CVE-2018-11776](https://semmle.com/news/apache-struts-CVE-2018-11776)
 * SSH Exploit written in Python for CVE-2018-15473 with threading and export formats: [CVE-2018-15473](https://github.com/Rhynorater/CVE-2018-15473-Exploit)

 ## Additions
 
 Please, send pull requests for new additions.
 
 Thanks!
