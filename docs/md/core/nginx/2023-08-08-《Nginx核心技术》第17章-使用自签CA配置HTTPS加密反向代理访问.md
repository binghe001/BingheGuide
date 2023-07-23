---
layout: post
category: nginx-core-base
title: 第17章：使用自签CA配置HTTPS加密反向代理访问
tagline: by 冰河
tag: [nginx,nginx-core-base,nginx-core]
excerpt: 第17章：使用自签CA配置HTTPS加密反向代理访问
lock: need
---

# 《Nginx核心技术》第17章：使用自签CA配置HTTPS加密反向代理访问

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>星球项目地址：[https://binghe.gitcode.host/md/zsxq/introduce.html](https://binghe.gitcode.host/md/zsxq/introduce.html)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：用最简短的篇幅介绍Nginx最核心的知识，掌握使用自签CA配置HTTPS加密反向代理访问，并能够灵活运用到实际项目中，维护高可用系统。

**大家好，我是冰河~~**

今天给大家介绍《Nginx核心技术》的第17章：使用自签CA配置HTTPS加密反向代理访问，多一句没有，少一句不行，用最简短的篇幅讲述Nginx最核心的知识，好了，开始今天的内容。

## 17.1 本章概述

随着互联网的发展，很多公司和个人越来越重视网络的安全性，越来越多的公司采用HTTPS协议来代替了HTTP协议。为何说HTTPS协议比HTTP协议安全呢？小伙伴们自行百度吧！我就不说了。今天，我们就一起来聊聊如何使用自签CA配置Nginx的HTTPS加密反向代理。咳咳，小伙伴们快上车。

如果这篇文章对你有所帮助，请文末留言，点个赞，给个在看和转发，大家的支持是我持续创作的最大动力！

## 17.2 Nginx实现HTTPS

出于安全访问考虑，采用的CA是本机Openssl自签名生成的，因此无法通过互联网工信Root CA验证，所以会出现该网站不受信任或安全证书无效的提示，直接跳过，直接访问即可！

## 17.3 HTTPS的原理和访问过程

### 17.3.1 服务器必要条件

* 一个服务器私钥 KEY文件
* 一张与服务器域名匹配的CA证书（公钥，根据私钥key生成）

### 17.3.2 访问过程

(1)客户端浏览器通过https协议访问服务器的443端口，并获得服务器的证书（公钥）；客户端浏览器这时候会去找一些互联网可信的RootCA（权威证书颁发机构）验证当前获取到的证书是否合法有效，PS：这些RootCA是随操作系统一起预设安装在了系统里面的；

(2)如果RootCA验证通过，表示该证书是可信的，并且若证书中标注的服务器名称与当前访问的服务器URL地址一致，就会直接使用该证书中包含的公钥解密服务器通过自己的KEY（私钥）加密后传输过来的网页内容，从而正常显示页面内容；

(3)如果RootCA验证不通过，说明该证书是未获得合法的RootCA签名和授权，因此也就无法证明当前所访问的服务器的权威性，客户端浏览器这时候就会显示一个警告，提示用户当前访问的服务器身份无法得到验证，询问用户是否继续浏览！（通常自签名的CA证书就是这种情况）

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/core/nginx/2023-08-08-001.png?raw=true" width="80%">
    <br/>
</div>

这里需要注意，验证CA的有效性，只是证明当前服务器的身份是否合法有效，是否具有公信力以及身份唯一性，防止其他人仿冒该网站；但并不会影响到网页的加密功能，尽管CA证书无法得到权威证明，但是它所包含的公钥和服务器上用于加密页面的私钥依然是匹配的一对，所以服务器用自己的私钥加密的网页内容，客户端浏览器依然是可以用这张证书来解密，正常显示网页内容，所以当用户点击“继续浏览此网站（不推荐）”时，网页就可以打开了；

### 17.3.3 自签名CA证书生成

**1.用Openssl随机生成服务器密钥，和证书申请文件CSR**

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/core/nginx/2023-08-08-002.png?raw=true" width="80%">
    <br/>
</div>

**2.自己给自己签发证书**

在服务器命令行输入如下命令办法证书。

```bash
#opensslx509 -req -days 3650 -in moonfly.net.csr -signkeymoonfly.net.key -outmoonfly.net.crt 
```

* -days 3650  证书的有效期，自己给自己颁发证书，想有多久有效期，就弄多久，我一下弄了10年的有效期；
* -inmoonfly.net.csr指定CSR文件
* -signkeymoonfly.net.key指定服务器的私钥key文件
* -outmoonfly.net.crt 设置生成好的证书文件名

一条命令，自己给自己压钢印的身份证 moonfly.net.crt 就诞生了！

**注：其实严格来讲，这里生成的只是一张RootCA，并不是严格意义上的服务器证书ServerCA，真正的ServerCA是需要利用这张RootCA再给服务器签署办法出来的证书才算；不过我们这里只讲如何实现网页的SSL加密，所以就直接使用RootCA了，也是能正常实现加密功能的！**

## 17.4 NGINX配置启用HTTPS并配置加密反向代理

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/core/nginx/2023-08-08-003.png?raw=true" width="80%">
    <br/>
</div>

配置文件修改完毕后，用nginx -t 测试下配置无误，就reload一下nginx服务，检查443端口是否在监听：

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/core/nginx/2023-08-08-004.png?raw=true" width="80%">
    <br/>
</div>

配置完毕，https已经在工作了，现在可以通过https访问网站了

**好了，相信各位小伙伴们对使用自签CA配置HTTPS加密反向代理访问，有了进一步的了解，我是冰河，我们下期见~~**

## 星球服务

加入星球，你将获得：

1.项目学习：微服务入门必备的SpringCloud  Alibaba实战项目、手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】、Seckill秒杀系统项目—进大厂必备高并发、高性能和高可用技能。

2.框架源码：手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】。

3.硬核技术：深入理解高并发系列（全册）、深入理解JVM系列（全册）、深入浅出Java设计模式（全册）、MySQL核心知识（全册）。

4.技术小册：深入理解高并发编程（第1版）、深入理解高并发编程（第2版）、从零开始手写RPC框架、SpringCloud  Alibaba实战、冰河的渗透实战笔记、MySQL核心知识手册、Spring IOC核心技术、Nginx核心技术、面经手册等。

5.技术与就业指导：提供相关就业辅导和未来发展指引，冰河从初级程序员不断沉淀，成长，突破，一路成长为互联网资深技术专家，相信我的经历和经验对你有所帮助。

冰河的知识星球是一个简单、干净、纯粹交流技术的星球，不吹水，目前加入享5折优惠，价值远超门票。加入星球的用户，记得添加冰河微信：hacker_binghe，冰河拉你进星球专属VIP交流群。

## 星球重磅福利

跟冰河一起从根本上提升自己的技术能力，架构思维和设计思路，以及突破自身职场瓶颈，冰河特推出重大优惠活动，扫码领券进行星球，**直接立减149元，相当于5折，** 这已经是星球最大优惠力度！

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu_149.png?raw=true" width="80%">
    <br/>
</div>

领券加入星球，跟冰河一起学习《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》，更有已经上新的《大规模分布式Seckill秒杀系统》，从零开始介绍原理、设计架构、手撸代码。后续更有硬核中间件项目和业务项目，而这些都是你升职加薪必备的基础技能。

**100多元就能学这么多硬核技术、中间件项目和大厂秒杀系统，如果是我，我会买他个终身会员！**

## 其他方式加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

## 星球规划

后续冰河还会在星球更新大规模中间件项目和深度剖析核心技术的专栏，目前已经规划的专栏如下所示。

### 中间件项目

* 《大规模分布式定时调度中间件项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式IM（即时通讯）项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式网关项目实战（非Demo）》：全程手撸代码。
* 《手写Redis》：全程手撸代码。
* 《手写JVM》全程手撸代码。

### 超硬核项目

* 《从零落地秒杀系统项目》：全程手撸代码，在阿里云实现压测（**已上新**）。
* 《大规模电商系统商品详情页项目》：全程手撸代码，在阿里云实现压测。
* 其他待规划的实战项目，小伙伴们也可以提一些自己想学的，想一起手撸的实战项目。。。


既然星球规划了这么多内容，那么肯定就会有小伙伴们提出疑问：这么多内容，能更新完吗？我的回答就是：一个个攻破呗，咱这星球干就干真实中间件项目，剖析硬核技术和项目，不做Demo。初衷就是能够让小伙伴们学到真正的核心技术，不再只是简单的做CRUD开发。所以，每个专栏都会是硬核内容，像《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》就是很好的示例。后续的专栏只会比这些更加硬核，杜绝Demo开发。

小伙伴们跟着冰河认真学习，多动手，多思考，多分析，多总结，有问题及时在星球提问，相信在技术层面，都会有所提高。将学到的知识和技术及时运用到实际的工作当中，学以致用。星球中不少小伙伴都成为了公司的核心技术骨干，实现了升职加薪的目标。

## 联系冰河

### 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`星球编号`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>



### 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>


### 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>



### 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>