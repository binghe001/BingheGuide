---
layout: post
category: mycat-core-base
title: 第02章：Mycat核心配置文件server.xml说明
tagline: by 冰河
tag: [mycat,mycat-core-base,mycat-core]
excerpt: 第02章：Mycat核心配置文件server.xml说明
lock: need
---

# 《Mycat核心技术》第02章：Mycat核心配置文件server.xml说明

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>星球项目地址：[https://binghe.gitcode.host/md/zsxq/introduce.html](https://binghe.gitcode.host/md/zsxq/introduce.html)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：介绍Mycat核心配置文件server.xml，理解server.xml文件在Mycat中的作用，并能够在实际项目中灵活使用Mycat进行分库分表。

**大家好，我是冰河~~**

今天给大家介绍《Mycat核心技术》的第02章：给大家简单介绍下Mycat中的核心配置文件server.xml，好了，开始今天的内容。

## 一、概述

 server.xml几乎保存了所有mycat需要的系统配置信息。其在代码内直接的映射类为SystemConfig类。现在就对这个文件中的配置，一一介绍。

## 二、user标签

```html
<user name="test">
	<property name="password">test</property>
	<property name="schemas">TESTDB</property>
	<property name="readOnly">true</property>
</user>
```

server.xml中的标签本就不多，这个标签主要用于定义登录mycat的用户和权限。

例如上面的例子中，我定义了一个用户，用户名为test、密码也为test，可访问的schema也只有TESTDB一个。如果我在schema.xml中定义了多个schema，那么这个用户是无法访问其他的schema。

在MySQL客户端看来则是无法使用use切换到这个其他的数据库。如果使用了use命令，则mycat会报出这样的错误提示。

```bash
ERROR 1044 (HY000): Access denied for user 'test' to database 'xxx'
```

这个标签嵌套的property标签则是具体声明的属性值，正如上面的例子。我们可以修改user标签的name属性来指定用户名；修改password内的文本来修改密码；修改readOnly为true 或false来限制用户是否只是可读的；修改schemas内的文本来控制用户可放问的schema；修改schemas内的文本来控制用户可访问的schema，同时访问多个schema的话使用 , 隔开，例如:

```html
<property name="schemas">TESTDB,db1,db2</property>
```

## 三、system标签

这个标签内嵌套的所有property标签都与系统配置有关，请注意，下面我会省去标签property直接使用这个标签的name属性内的值来介绍这个属性的作用。

## 四、defaultSqlParser属性

由于mycat最初是时候Foundation DB的sql解析器，而后才添加的Druid的解析器。所以这个属性用来指定默认的解析器。目前的可用的取值有：druidparser和 fdbparser。使用的时候可以选择其中的一种，目前一般都使用druidparser。

## 五、processors属性

这个属性主要用于指定系统可用的线程数，默认值为Runtime.getRuntime().availableProcessors()方法返回的值。主要影响processorBufferPool、processorBufferLocalPercent、processorExecutor属性。NIOProcessor的个数也是由这个属性定义的，所以调优的时候可以适当的调高这个属性。

## 六、processorBufferChunk属性

这个属性指定每次分配Socket Direct Buffer的大小，默认是4096个字节。这个属性也影响buffer pool的长度。

## 七、processorBufferPool属性

这个属性指定bufferPool计算 比例值。由于每次执行NIO读、写操作都需要使用到buffer，系统初始化的时候会建立一定长度的buffer池来加快读、写的效率，减少建立buffer的时间。

## 八、Mycat中两个主要的buffer池

BufferPool和ThreadLocalPool

BufferPool由ThreadLocalPool组合而成，每次从BufferPool中获取buffer都会优先获取ThreadLocalPool中的buffer，未命中之后才会去获取BufferPool中的buffer。也就是说ThreadLocalPool是作为BufferPool的二级缓存，每个线程内部自己使用的。

当然，这其中还有一些限制条件需要线程的名字是由$_开头。然而，BufferPool上的buffer则是每个NIOProcessor都共享的。默认这个属性的值为：

若bufferPool不是bufferChunk的整数倍，则总长度为前面计算得出的商 + 1 假设系统线程数为4，其他都为属性的默认值，则：

```bash
bufferPool ＝　4096 *　4 * 1000
BufferPool的总长度 : 4000 = 16384000 / 4096
```

## 九、processorBufferLocalPercent属性

前面提到了ThreadLocalPool。这个属性就是用来控制分配这个pool的大小用的，但其也并不是一个准确的值，也是一个比例值。这个属性默认值为100。

```bash
线程缓存百分比 = bufferLocalPercent / processors属性
```

例如，系统可以同时运行4个线程，使用默认值，则根据公式每个线程的百分比为25。最后根据这个百分比来计算出具体的

ThreadLocalPool的长度公式如下：

```bash
ThreadLocalPool的长度 = 线程缓存百分比 * BufferPool长度 / 100
```

假设BufferPool的长度为 4000，其他保持默认值。

那么最后每个线程建立上的ThreadLocalPool的长度为： 1000 = 25 * 4000 / 100

## 十、processorExecutor属性

这个属性主要用于指定NIOProcessor上共享的businessExecutor固定线程池大小。mycat在需要处理一些异步逻辑的时候会把任务提交到这个线程池中。新版本中这个连接池的使用频率不是很大了，可以设置一个较小的值。

## 十一、sequnceHandlerType属性

指定使用Mycat全局序列的类型。0为本地文件方式，1为数据库方式。默认是使用本地文件方式，文件方式主要只是用于测试使用。

## 十二、TCP连接相关属性

StandardSocketOptions.SO_RCVBUF
StandardSocketOptions.SO_SNDBUF
StandardSocketOptions.TCP_NODELAY

以上这三个属性，分别由：

```bash
frontSocketSoRcvbuf 默认值： 1024 * 1024
frontSocketSoSndbuf 默认值： 4 * 1024 * 1024
frontSocketNoDelay 默认值： 1
backSocketSoRcvbuf 默认值： 4 * 1024 * 1024
backSocketSoSndbuf 默认值： 1024 * 1024
backSocketNoDelay 默认值： 1
```

各自设置前后端TCP连接参数。Mycat在每次建立前、后端连接的时候都会使用这些参数初始化连接。可以按系统要求适当的调整这些buffer的大小。TCP连接参数的定义，可以查看Javadoc。

MySQL连接相关属性初始化MySQL前后端连接所涉及到的一些属性：

* packetHeaderSize : 指定MySQL协议中的报文头长度。默认4。
* maxPacketSize : 指定MySQL协议可以携带的数据最大长度。默认16M。
  idleTimeout : 指定连接的空闲超时时间。某连接在发起空闲检查下，发现距离上次使用超过了空闲时间，那么这个连接会被回收，就是被直接的关闭掉。默认30分钟。
* charset : 连接的初始化字符集。默认为utf8。
* txIsolation : 前端连接的初始化事务隔离级别，只在初始化的时候使用，后续会根据客户端传递过来的属性对后端数据库连接进行同步。默认为REPEATED_READ。
* sqlExecuteTimeout:SQL执行超时的时间，Mycat会检查连接上最后一次执行SQL的时间，若超过这个时间则会直接关闭这连接。默认时间为300秒。

## 十三、周期间隔相关属性

Mycat中有几个周期性的任务来异步的处理一些我需要的工作。这些属性就在系统调优的过程中也是比不可少的。

* processorCheckPeriod : 清理NIOProcessor上前后端空闲、超时和关闭连接的间隔时间。默认是1秒。
* dataNodeIdleCheckPeriod : 对后端连接进行空闲、超时检查的时间间隔，默认是60秒。
* dataNodeHeartbeatPeriod : 对后端所有读、写库发起心跳的间隔时间，默认是10秒。

## 十四、服务相关属性

这里介绍一个与服务相关的属性，主要会影响外部系统对myact的感知。

* bindIp : mycat服务监听的IP地址，默认值为0.0.0.0。
* serverPort : 定义mycat的使用端口，默认值为8066。
* managerPort : 定义mycat的管理端口，默认值为9066。

**好了，今天就到这儿吧，我是冰河，我们下期见~~**

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