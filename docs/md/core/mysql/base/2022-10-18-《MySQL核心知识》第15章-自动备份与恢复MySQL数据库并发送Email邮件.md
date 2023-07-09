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

## 星球服务

加入星球，你将获得：

1.项目学习：微服务入门必备的SpringCloud  Alibaba实战项目、手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】、Seckill秒杀系统项目—进大厂必备高并发、高性能和高可用技能。

2.框架源码：手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】。

3.硬核技术：深入理解高并发系列（全册）、深入理解JVM系列（全册）、深入浅出Java设计模式（全册）、MySQL核心知识（全册）。

4.技术小册：深入理解高并发编程（第1版）、深入理解高并发编程（第2版）、从零开始手写RPC框架、SpringCloud  Alibaba实战、冰河的渗透实战笔记、MySQL核心知识手册、Spring IOC核心技术、Nginx核心技术、面经手册等。

5.技术与就业指导：提供相关就业辅导和未来发展指引，冰河从初级程序员不断沉淀，成长，突破，一路成长为互联网资深技术专家，相信我的经历和经验对你有所帮助。

冰河的知识星球是一个简单、干净、纯粹交流技术的星球，不吹水，目前加入享5折优惠，价值远超门票。加入星球的用户，记得添加冰河微信：hacker_binghe，冰河拉你进星球专属VIP交流群。

## 星球重磅福利

跟冰河一起从根本上提升自己的技术能力，架构思维和设计思路，以及突破自身职场瓶颈，冰河特推出重大优惠活动，扫码领券进行星球，**直接立减149元，相当于5折，** 这已经是星球最大优惠力度！

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu_149.png?raw=true" width="80%">
    <br/>
</div>

领券加入星球，跟冰河一起学习《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》，更有已经上新的《大规模分布式Seckill秒杀系统》，从零开始介绍原理、设计架构、手撸代码。后续更有硬核中间件项目和业务项目，而这些都是你升职加薪必备的基础技能。

**100多元就能学这么多硬核技术、中间件项目和大厂秒杀系统，如果是我，我会买他个终身会员！**

## 其他方式加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

## 星球规划

后续冰河还会在星球更新大规模中间件项目和深度剖析核心技术的专栏，目前已经规划的专栏如下所示。

### 中间件项目

* 《大规模分布式定时调度中间件项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式IM（即时通讯）项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式网关项目实战（非Demo）》：全程手撸代码。
* 《手写Redis》：全程手撸代码。
* 《手写JVM》全程手撸代码。

### 超硬核项目

* 《从零落地秒杀系统项目》：全程手撸代码，在阿里云实现压测（**已上新**）。
* 《大规模电商系统商品详情页项目》：全程手撸代码，在阿里云实现压测。
* 其他待规划的实战项目，小伙伴们也可以提一些自己想学的，想一起手撸的实战项目。。。


既然星球规划了这么多内容，那么肯定就会有小伙伴们提出疑问：这么多内容，能更新完吗？我的回答就是：一个个攻破呗，咱这星球干就干真实中间件项目，剖析硬核技术和项目，不做Demo。初衷就是能够让小伙伴们学到真正的核心技术，不再只是简单的做CRUD开发。所以，每个专栏都会是硬核内容，像《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》就是很好的示例。后续的专栏只会比这些更加硬核，杜绝Demo开发。

小伙伴们跟着冰河认真学习，多动手，多思考，多分析，多总结，有问题及时在星球提问，相信在技术层面，都会有所提高。将学到的知识和技术及时运用到实际的工作当中，学以致用。星球中不少小伙伴都成为了公司的核心技术骨干，实现了升职加薪的目标。

## 联系冰河

### 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`星球编号`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>



### 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>


### 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>



### 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>