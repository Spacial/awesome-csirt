# Proof-of-Concept Exploits

> **Warning:** these files are exploit code for research, CTFs and authorized testing only. Some may be flagged by antivirus. Never run them on systems you do not own or have permission to test.

| File | Target / CVE | Type |
|---|---|---|
| [Cisco_ASA_CVE-2018-0101.py](Cisco_ASA_CVE-2018-0101.py) | Cisco ASA, CVE-2018-0101 (crash) | Python |
| [CVE-2017-1000112_container_escape.c](CVE-2017-1000112_container_escape.c) | Linux kernel, CVE-2017-18344 + CVE-2017-1000112 (container escape, Capsule8) | C |
| [CVE-2019-8646-messageleak.zip](CVE-2019-8646-messageleak.zip) | Apple iMessage, CVE-2019-8646 | ZIP archive (Python sources) |
| [CVE-2020-3452-cisco-asa.py](CVE-2020-3452-cisco-asa.py) | Cisco ASA path traversal, CVE-2020-3452 | Python |
| [cve-2021-33909-crasher.c](cve-2021-33909-crasher.c) | Linux kernel, CVE-2021-33909 (Sequoia) | C |
| [cve-2021-33910-crasher.c](cve-2021-33910-crasher.c) | systemd, CVE-2021-33910 | C |
| [cve-2021-33910-crasher](cve-2021-33910-crasher) | Compiled build of the file above (ELF x86-64) | **Binary**: do not run untrusted |
| [ubuntu_CVE-2013-1763.c](ubuntu_CVE-2013-1763.c) | Linux kernel (Ubuntu), CVE-2013-1763, with SMEP bypass | C |
| [ubuntu_CVE-2017-16995.c](ubuntu_CVE-2017-16995.c) | Linux kernel (Ubuntu 16.04.4), CVE-2017-16995, local privilege escalation | C |
| [ubuntu_netfilter.c](ubuntu_netfilter.c) | Linux kernel netfilter (Ubuntu), local privilege escalation (EDB 44300) | C |
| [unrealirc.py](unrealirc.py) | UnrealIRCd 3.2.8.1 backdoor (Python 3 port) | Python |

More CVE references: [lists/cves-pocs.md](../lists/cves-pocs.md).
