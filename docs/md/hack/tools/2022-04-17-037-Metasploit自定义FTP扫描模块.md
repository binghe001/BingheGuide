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

## 