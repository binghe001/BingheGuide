---
layout: post
category: binghe-code-hack
title: metasploitable2修改密码
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: metasploitable2修改密码
lock: need
---

# metasploitable2修改密码

metasploitable2这个系统众所周知，一个用户名和密码是msfadmin。但是这个账号权限不全，我们想要改root密码来登陆为所欲为。也没试过破解，咱们索性就改了吧。

就简单几行代码。。

```bash
msfadmin@metasploitable:~$ sudo passwd root
[sudo] password for msfadmin:            #这里输入msfadmin的密码，也就是msfadmin
Enter new UNIX password:            #这里输两次要更改的root的密码
Retype new UNIX password:
passwd: password updated successfully
 
msfadmin@metasploitable:~$ su root     #然后切换过来就好了
Password:                       #输入你更改的root密码
root@metasploitable:~# id
uid=0(root) gid=0(root) groups=0(root)
```


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)