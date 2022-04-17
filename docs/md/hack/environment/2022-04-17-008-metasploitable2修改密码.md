# metasploitable2修改密码

metasploitable2这个系统众所周知，一个用户名和密码是msfadmin。但是这个账号权限不全，我们想要改root密码来登陆为所欲为。也没试过破解，咱们索性就改了吧。

就简单几行代码。。

```bash
msfadmin@metasploitable:~$ sudo passwd root
[sudo] password for msfadmin:            #这里输入msfadmin的密码，也就是msfadmin
Enter new UNIX password:            #这里输两次要更改的root的密码
Retype new UNIX password:
passwd: password updated successfully
 
msfadmin@metasploitable:~$ su root     #然后切换过来就好了
Password:                       #输入你更改的root密码
root@metasploitable:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 