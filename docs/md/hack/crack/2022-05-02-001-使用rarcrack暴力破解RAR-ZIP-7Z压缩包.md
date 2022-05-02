---
layout: post
category: binghe-code-hack
title: 使用rarcrack暴力破解RAR，ZIP，7Z压缩包
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: 使用rarcrack暴力破解RAR，ZIP，7Z压缩包
lock: need
---

# 使用rarcrack暴力破解RAR，ZIP，7Z压缩包

这里使用的软件名称叫rarcrack，其官方主页: http://rarcrack.sourceforge.net

该软件用于暴力破解压缩文件的密码，但仅支持RAR, ZIP, 7Z这三种类型的压缩包，其特点是可以使用多线程，而且可以随时暂停与继续(暂停时会在当前目录生成一个xml文件，里面显示了正在尝试的一个密码)。这是真正的暴力破解，因为连字典都没用
rarcrack安装方法

首先从官网下载安装包，然后执行如下命令

```bash
tar -xjf rarcrack-0.2.tar.bz2
cd rarcrack-0.2
make && make install
```

或者直接使用下述命令安装rarcrack

apt-get install rarcrack

rarcrack使用方法

执行命令: rarcrack 文件名 -threads 线程数 -type rar|zip|7z

同时，该软件自带了测试样例，在解压目录里，执行rarcrack test.zip —threads 4 —type zip，等待一会儿即可得到结果，其密码是100，很简单。在执行过程中，还会打印当前尝试的速度，比如:

```bash
Probing: 'oB' [527 pwds/sec]
Probing: 'Nh' [510 pwds/sec]
Probing: '0c3' [512 pwds/sec]
Probing: '0AV' [514 pwds/sec]
```

如果要改变当前密码破解的位置，可以直接打开xml，修改当前密码到那一行密码即可。xml内容如下:

```bash
<?xml version="1.0" encoding="UTF-8"?>
<rarcrack>
  <abc>0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ</abc>
  <current>104</current>
  <good_password>100</good_password>
</rarcrack>
```

在执行过程中，如果出现如下错误:

```bash
gcc -pthread rarcrack.cxml2-config --libs --cflags-O2 -o rarcrack  
/bin/sh: 1: xml2-config: not found  
In file included from rarcrack.c:21:0:  
rarcrack.h:25:48: 致命错误： libxml/xmlmemory.h：没有那个文件或目录  
编译中断。  
make: *** [all] 错误 1
```

那么可以执行sudo apt-get install libxml2-dev libxslt-dev进行修复。

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)