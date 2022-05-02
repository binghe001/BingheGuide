---
layout: post
category: binghe-code-hack
title: Armitage控制Metasploit
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Armitage控制Metasploit
lock: need
---

# Armitage控制Metasploit

Cortana能很好的控制Metasploit的功能。可以使用Cortana对Metasploit发出各种命令。

这里，我们以一个简单的脚本说明，比如这里我们创建了一个脚本ready.cna，内容如下：

```
cmd_async("hosts");
cmd_async("services");
on console_hosts{
    println("Hosts in the Database");
    println(" $3 ");
}

on console_services{
    println("Service in the Database");
    println(" $3 ");
}
```

这段脚本中，命令cmd_async发送hosts命令和services命令道Metasploit并确保它们被执行。`此外，这些console_*函数被用来打印这条命令的输出。Metasploit将执行这些命令。然而为了打印这个输出内容，需要定义console_*函数。 $3是一个变量`，在其中保存了命令的输出内容

接下来就是在Armitage中加载ready.cna脚本文件

依次单击Armitage->Scripts

![img](https://img-blog.csdnimg.cn/20190128211532403.png)

单击Load按钮

![img](https://img-blog.csdnimg.cn/20190128211547763.png)

选择read.cna脚本后单击打开按钮

![img](https://img-blog.csdnimg.cn/20190128211606475.png)

此时，我们选中ready.cna后单击Console按钮，如下：

![img](https://img-blog.csdnimg.cn/20190128211621474.png)

此时，我们发现在Cornata命令行中输出了相关的信息，如下：

![img](https://img-blog.csdnimg.cn/20190128211636564.png)

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)