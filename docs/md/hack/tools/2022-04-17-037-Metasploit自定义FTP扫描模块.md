---
layout: post
category: binghe-code-hack
title: Metasploit自定义FTP扫描模块
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Metasploit自定义FTP扫描模块
lock: need
---

# Metasploit自定义FTP扫描模块

这里，我们编写的Ruby脚本ftp_version_by_binghe.rb如下：

```
##
# Author 冰河
# Date 2019-01-12
# Description 自定义FTP发现模块，用于主动发现目标机所在C段网络的FTP服务器，并主动进行自动化渗透
##
require 'msf/core'
class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  #初始化基础信息
  def initialize
    super(
      'Name'        => 'FTP Version Scanner Customized Module',
      'Description' => 'Detect FTP Version from the target and Attack All of The FTP Server.',
      'Author'      => 'binghe',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(21),
      ])
  end

  #程序入口
  def run_host(target_host)

    connect(true, false)

    if(banner)
    print_status("#{rhost} is running #{banner}")
    report_service(:host=>rhost, :port=>rport, :name=>"ftp", :info=>banner)
    end
    disconnect
   end
end
```

接下来我们将ftp_version_by_binghe.rb脚本上传到Kali服务器的/usr/share/metasploit-framework/modules/auxiliary/scanner/ftp目录下。

在运行这个脚本之前，我们先使用Metasploit中的msftidy工具检查一下此脚本的语法是否正确。

在Kali的命令行执行如下命令：

```
/usr/share/metasploit-framework/tools/dev/msftidy.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/ftp/ftp_version_by_binghe.rb 
```

未输出任何信息，证明脚本正确。

接下来，我们进行msf终端，运行我们自定义的FTP扫描模块：

```
msfconsole
use auxiliary/scanner/ftp/ftp_version_by_binghe 
show options
set RHOSTS 192.168.109.159
run
```

输出的结果为：

```
[*] 192.168.109.159:21    - 192.168.109.159 is running 220 (vsFTPd 2.3.4)

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)