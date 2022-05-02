---
layout: post
category: binghe-code-hack
title: kali Metasploit 连接 Postgresql 默认密码
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: kali Metasploit 连接 Postgresql 默认密码
lock: need
---

# kali Metasploit 连接 Postgresql 默认密码

## 启动 postgresql 

```
service postgresql start
```

postgresql开机自启动

```
update-rc.d postgresql enable
```

## 自行测试 postgresql 是否安装成功

根据需要，自行 修改 postgres 默认密码，是否允许远程登录

## 初始化MSF数据库（关键步骤）

```
msfdb init
```

## 启动 msfconsole

```
msfconsole
```

## 检测 db 连接状态

```
db_status
```

## 如果连接异常会显示

```
msf > db_status
[*] postgresql selected, no connection
```

## 手动连接数据库

```
msf > db_connect msf:admin@127.0.0.1/msf
```

## 如果不想每次都手动连接，可以修改配置文件，设置数据库密码

```
vim /usr/share/metasploit-framework/config/database.yml
```

将 password 修改为 你的密码

# 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)