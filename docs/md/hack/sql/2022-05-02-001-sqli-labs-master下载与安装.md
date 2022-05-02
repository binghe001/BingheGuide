---
layout: post
category: binghe-code-hack
title: sqli-labs-master 下载与安装
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: sqli-labs-master 下载与安装
lock: need
---

# sqli-labs-master 下载与安装

注意事项：

php版本一定要设置成 7 以下，7之后的mysql_都改成了mysqli_了，用7以上版本的话会报错

sqli-labs是一个非常好的学习sql注入的项目。

sqli-labs下载

sqli-labs下载地址：https://github.com/Audi-1/sqli-labs

完整的安装环境链接：https://download.csdn.net/download/l1028386804/10794776

安装

首先安装phpstudy或者xampp 

将下载的文件解压发在：phpstudy的WWW文件夹里 或者 xampp里面的htdocs文件夹里面

修改mysql文件的账号密码

在sqli-labs-master\sql-connections里面有个db-creds.inc文件，打开并修改账号密码

![](https://img-blog.csdnimg.cn/20181119234731663.png)

进入页面进行安装

打开网页输入：http://localhost/sqli-labs-master

![](https://img-blog.csdnimg.cn/20181119234816628.png)

点击第一个：Setup/reset Database for labs   出现下面页面为正确

![](https://img-blog.csdnimg.cn/20181119234839529.png)

安装完毕，接下来就可以测试各种SQL注入了。

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)