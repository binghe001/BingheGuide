---
layout: post
category: nginx-core-base
title: 第10章：Nginx配置WebSocket
tagline: by 冰河
tag: [nginx,nginx-core-base,nginx-core]
excerpt: 第10章：Nginx配置WebSocket
lock: need
---

# 《Nginx核心技术》第10章：Nginx配置WebSocket

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>星球项目地址：[https://binghe.gitcode.host/md/zsxq/introduce.html](https://binghe.gitcode.host/md/zsxq/introduce.html)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：用最简短的篇幅介绍Nginx最核心的知识，掌握Nginx如何配置WebSocket，并能够灵活运用到实际项目中，维护高可用系统。

**大家好，我是冰河~~**

今天给大家介绍《Nginx核心技术》的第10章：Nginx配置WebSocket，多一句没有，少一句不行，用最简短的篇幅讲述Nginx最核心的知识，好了，开始今天的内容。

## 10.1 本章概述

当今互联网领域，不管是APP还是H5，不管是微信端还是小程序，只要是一款像样点的产品，为了增加用户的交互感和用户粘度，多多少少都会涉及到聊天功能。而对于Web端与H5来说，实现聊天最简单的就是使用WebSocket了。而在实现WebSocket聊天的过程中，后台也往往会部署多个WebSocket服务，多个WebSocket服务之间，可以通过Nginx进行负载均衡。今天，我们就来一起说说Nginx是如何配置WebSocket的。

## 10.2 配置WebSocket

Nginx配置WebSocket也比较简单，只需要在nginx.conf文件中进行相应的配置。这种方式很简单，但是很有效，能够横向扩展WebSocket服务端的服务能力。

先直接展示配置文件，如下所示(使用的话直接复制，然后改改ip和port即可)

```bash
map $http_upgrade $connection_upgrade { 
	default upgrade; 
	'' close; 
} 
upstream wsbackend{ 
	server ip1:port1; 
	server ip2:port2; 
	keepalive 1000; 
} 
 
server { 
	listen 20038; 
	location /{ 
		proxy_http_version 1.1; 
		proxy_pass http://wsbackend; 
		proxy_redirect off; 
		proxy_set_header Host $host; 
		proxy_set_header X-Real-IP $remote_addr; 
		proxy_read_timeout 3600s; 
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 
		proxy_set_header Upgrade $http_upgrade; 
		proxy_set_header Connection $connection_upgrade; 
	} 
}
```

接下来，我们就分别分析上述配置的具体含义。

**首先：**

```bash
map $http_upgrade $connection_upgrade { 
	default upgrade; 
	'' close; 
} 
```

表示的是：

* 如果 $http_upgrade 不为 '' (空)，则 $connection_upgrade 为 upgrade 。
* 如果 $http_upgrade 为 '' (空)，则 $connection_upgrade 为 close。

**其次：**

```bash
upstream wsbackend{ 
	server ip1:port1; 
	server ip2:port2; 
	keepalive 1000; 
} 
```

表示的是 nginx负载均衡：

* 两台服务器 (ip1:port1)和(ip2:port2) 。
* keepalive 1000 表示的是每个nginx进程中上游服务器保持的空闲连接，当空闲连接过多时，会关闭最少使用的空闲连接.当然，这不是限制连接总数的，可以想象成空闲连接池的大小，设置的值应该是上游服务器能够承受的。

**最后：**

```bash
server { 
	listen 20038; 
	location /{ 
		proxy_http_version 1.1; 
		proxy_pass http://wsbackend; 
		proxy_redirect off;
		proxy_set_header Host $host; 
		proxy_set_header X-Real-IP $remote_addr; 
		proxy_read_timeout 3600s; 
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 
		proxy_set_header Upgrade $http_upgrade; 
		proxy_set_header Connection $connection_upgrade; 
	} 
} 
```

表示的是监听的服务器的配置 

* listen 20038 表示 nginx 监听的端口 
* locations / 表示监听的路径(/表示所有路径，通用匹配，相当于default) 
* proxt_http_version 1.1 表示反向代理发送的HTTP协议的版本是1.1，HTTP1.1支持长连接 
* proxy_pass http://wsbackend; 表示反向代理的uri，这里可以使用负载均衡变量 
* proxy_redirect off; 表示不要替换路径，其实这里如果是/则有没有都没关系，因为default也是将路径替换到proxy_pass的后边 
* proxy_set_header Host $host; 表示传递时请求头不变， $host是nginx内置变量，表示的是当前的请求头，proxy_set_header表示设置请求头 
* proxy_set_header X-Real-IP $remote_addr; 表示传递时来源的ip还是现在的客户端的ip 
* proxy_read_timeout 3600s； 表的两次请求之间的间隔超过 3600s 后才关闭这个连接，默认的60s，自动关闭的元凶 
* proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 表示X-Forwarded-For头不发生改变 
* proxy_set_header Upgrade $http_upgrade; 表示设置Upgrade不变 
* proxy_set_header Connection $connection_upgrade; 表示如果 $http_upgrade为upgrade，则请求为upgrade(websocket)，如果不是，就关闭连接

**好了，相信各位小伙伴们对Nginx如何配置WebSocket，有了进一步的了解，我是冰河，我们下期见~~**

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