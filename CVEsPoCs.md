# CVEs Resources

## Genereal

Some CVEs PoCs repos on github or internet.

* First, see: [Awesome CVE PoC](https://github.com/qazbnm456/awesome-cve-poc) by [qazbnm456](https://github.com/qazbnm456).
* To search (without PoCs): [cve-search](https://github.com/cve-search/cve-search) you can use it off-line too.
* This is a nice Wrapper:[vFeed](https://github.com/toolswatch/vFeed).

## Linux

 * Spectre : [CVE-2017-5753,CVE-2017-5715](https://gist.github.com/Badel2/ba8826e6607295e6f26c5ed098d98d27)
 * Dirty Cow: [CVE-2016-5195](https://github.com/scumjr/dirtycow-vdso) [Others](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)
 * "Root" via dirtyc0w privilege escalation [exploit](https://gist.github.com/Arinerron/0e99d69d70a778ca13a0087fa6fdfd80)
 * Huge Dirty Cow: [CVE-2017-1000405](https://github.com/bindecy/HugeDirtyCowPOC)
 * SMEP,SMAP and Chrome Sandbox: [CVE-2017-5123](https://salls.github.io/Linux-Kernel-CVE-2017-5123/)
 * SambaCry: [CVE-2017-7494](https://securelist.com/sambacry-is-coming/78674/)
 * The Stack Clash: [CVE-2017-1000364](https://blog.qualys.com/securitylabs/2017/06/19/the-stack-clash)
 * GoAhead web server: [CVE-2017-17562](https://www.elttam.com.au/blog/goahead/)
 
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
 
## macOS

 * RootPiper:  [Demo/PoC](https://github.com/Shmoopi/RootPipe-Demo)  [Tester](https://github.com/sideeffect42/RootPipeTester)
 * [Mac Privacy: Sandboxed Mac apps can record your screen at any time without you knowing](https://github.com/KrauseFx/krausefx.com/blob/master/_posts/2018-02-10-mac-privacy-sandboxed-mac-apps-can-take-screenshots.md) by [Felix Krause](https://github.com/KrauseFx)
 
## iOS

* [ROPLevel6 Writeup](https://github.com/shmoo419/ExploitChallengeWriteups/blob/master/ROPLevel6/Writeup.md)

## x86

 * Spectre: [CVE-2017-5753,CVE-2017-5715](https://spectreattack.com/)
 * Meltdown: [CVE-2017-5754](https://meltdownattack.com/)
 * Cyberus: [Meltdown](http://blog.cyberus-technology.de/posts/2018-01-03-meltdown.html)
 
## ARM

 * [ARM exploitation for IoT – Episode 3](https://quequero.org/2017/11/arm-exploitation-iot-episode-3/)
 * [Multiple vulnerabilities found in Wireless IP Camera](https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html#backdoor-account): CVE-2017-8224, CVE-2017-8222, CVE-2017-8225, CVE-2017-8223, CVE-2017-8221
 
## Android

* [Please Stop Naming Vulnerabilities: Exploring 6 Previously Unknown Remote Kernel Bugs Affecting Android Phones](https://pleasestopnamingvulnerabilities.com)

## BMC 

* HPE iLO4: [CVE-2017-12542](https://github.com/airbus-seclab/ilo4_toolbox/blob/master/README.rst)

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
 
 ## Additions
 
 Please, send pull requests for new additions.
 
 Thanks!
