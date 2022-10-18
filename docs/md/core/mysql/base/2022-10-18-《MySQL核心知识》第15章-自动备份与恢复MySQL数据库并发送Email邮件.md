---
layout: post
category: binghe-code-interview
title: 第15章：自动备份与恢复MySQL数据库并发送Email邮件
tagline: by 冰河
tag: [offer,interview,binghe-code-offer,binghe-code-interview]
excerpt: 第15章：自动备份与恢复MySQL数据库并发送Email邮件
lock: need
---

# 《MySQL核心知识》第15章：自动备份与恢复MySQL数据库并发送Email邮件

**大家好，我是冰河~~**

今天是《MySQL核心知识》专栏的第15章，今天为大家系统的讲讲如何自动备份与恢复MySQL数据库并发送Email邮件，希望通过本章节的学习，小伙伴们能够举一反三，彻底掌握自动备份与恢复MySQL数据库并发送Email邮件相关的知识。好了，开始今天的正题吧。

## 背景案例

一个博客，一个网站最重要的就是数据库，所以经常备份数据是必须的.尽管 WordPress 有定时备份数据的插件，但只能备份当前的博客，不够灵活.适合个人小小博客，对于一些网站来说，就不适合了.现在很多人都拥有多个网站，showfom就有几个网站.每个网站都装个插件就比较麻烦了。况且不是每个网站都是WordPress 的 。

所以写了个自动备份mysql数据库的脚本，再加上gmail这个G级邮箱，备份多少数据都可以了。下面是代码:

```sql
mysqldump -uuser -ppassword --databases db1 db2 db3 > /home/website/backups/databackup.sql
tar zcf /home/website/backups/databackup.sql.tar.gz /home/website/backups/
echo "主题:数据库备份" | mutt -a /home/website/backups/databackup.sql.tar.gz -s "内容:数据库备份" www@gmail.com
rm -r /home/website/backups/*
```

我们也可以按照日期生成备份的SQL文件，具体如下：

```sql
ls_date=`date +%Y%m%d`
fileName=/home/website/backups/databackup_$ls_date.sql
mysqldump -uuser -ppassword --databases db1 db2 db3 > $fileName
```

将上面的代码保存为automysqlbackup.sh

然后利用crontab 实现动备份，在服务器命令行输入如下命令。

```bash
crontab -e
```

最好是使用如下命令。

```bash
vim /etc/crontab
```

输入以下内容。

```bash
00 00 * * * /home/website/automysqlbackup.sh
```

这样就实现了每天00:00自动备份mysql数据库并发送到Email。

## 脚本说明

再简单的说明下备份并发送邮件的脚本。

```sql
mysqldump -uuser -ppassword --databases db1 db2 db3 > /home/website/backups/databackup.sql
tar zcf /home/website/backups/databackup.sql.tar.gz /home/website/backups/
echo "主题:数据库备份" | mutt -a /home/website/backups/databackup.sql.tar.gz -s "内容:数据库备份" www@gmail.com
rm -r /home/website/backups/*
```

第一句是一次性备份多个数据库，这个要用root权限的用户才可以的。-u后面的是数据库用户名 -p后面的是数据库密码 无需空格 db1 db2 db3为需要备份的数据库名。如果数据库用户名没有root这个权限，可以改为如下所示。

```sql
mysqldump -uuser -ppassword db1 > /home/website/backups/db1.sql
mysqldump -uuser -ppassword db2 > /home/website/backups/db1.sql
mysqldump -uuser -ppassword db3 > /home/website/backups/db1.sql
```

第二句是将 backups 文件夹里面的数据文件压缩为文件名：databackup.sql.tar.gz

第三句是将压缩了的数据库文件发送到指定的邮箱。

其中的主题:数据库备份 ，就是邮件的主题， 内容:数据库备份，就是邮件的内用，

/home/website/backups/databackup.sql.tar.gz 为附件

www@gmail.com为要发送的Email。

此时，我们完成了自动备份的功能，接下来就是要恢复数据库的问题了。

## 数据恢复

恢复数据库很简单，只需要我们登录数据库后，利用“source 数据库脚本”的命令即可恢复数据库，比如：

```sql
mysql -uroot -proot
source /home/website/backups/databackup.sql
```

注意：有关更多MySQL数据备份与恢复的知识，大家可以查阅《MySQL技术大全：开发、优化与运维实战》一书。

**好了，如果文章对你有点帮助，记得给冰河一键三连哦，欢迎将文章转发给更多的小伙伴，冰河将不胜感激~~**

## 关于星球

**冰河技术** 知识星球《RPC手撸专栏》已经开始了，我会将《RPC手撸专栏》的源码放到知识星球中，同时在微信上会创建专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

### 星球提供的服务

冰河整理了星球提供的一些服务，如下所示。

加入星球，你将获得： 

1.学习从零开始手撸可用于实际场景的高性能、可扩展的RPC框架项目

2.学习SpringCloud Alibaba实战项目—从零开发微服务项目 

3.学习高并发、大流量业务场景的解决方案，体验大厂真正的高并发、大流量的业务场景 

4.学习进大厂必备技能：性能调优、并发编程、分布式、微服务、框架源码、中间件开发、项目实战 

5.提供站点 https://binghe001.github.io 所有学习内容的指导、帮助 

6.GitHub：https://github.com/binghe001/BingheGuide - 非常有价值的技术资料仓库，包括冰河所有的博客开放案例代码 

7.提供技术问题、系统架构、学习成长、晋升答辩等各项内容的回答 

8.定期的整理和分享出各类专属星球的技术小册、电子书、编程视频、PDF文件 

9.定期组织技术直播分享，传道、授业、解惑，指导阶段瓶颈突破技巧

### 如何加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

**好了，今天就到这儿吧，我是冰河，我们下期见~~**

## 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`学习加群`。



<div align="center">
    <img src="https://binghe001.github.io/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 9px;">冰河微信</div>
    <br/>
</div>



## 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true" width="180px">
    <div style="font-size: 9px;">公众号：冰河技术</div>
    <br/>
</div>


## 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe001.github.io/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 9px;">知识星球：冰河技术</div>
    <br/>
</div>