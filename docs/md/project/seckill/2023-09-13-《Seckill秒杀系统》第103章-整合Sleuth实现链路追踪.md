---
title: 第103章：整合Sleuth实现链路追踪
pay: https://articles.zsxq.com/id_i68crg1dcwlj.html
---

# 《Seckill秒杀系统》第103章：整合Sleuth实现链路追踪

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：了解业务系统整合Sleuth实现链路追踪的落地方案，熟练掌握秒杀系统整合Sleuth实现链路追踪的落地方案，并能够灵活将实现方案应用到自身实际项目中。

**大家好，我是冰河~~**

随着互联网的不断发展，越来越多的企业会采用分布式、微服务的架构模式，但是这种架构模式下，由于服务模块之间复杂的调用关系，对于客服端请求的分析与处理就变得非常复杂，分布式链路追踪技术能够解决这个问题。

## 一、前言

在前面的章节中，我们已经学习了分布式链路追踪技术的核心原理与解决方案，从理论上清楚的了解了什么是分布式链路追踪技术。有了理论的基础后，接下来，我们就要在秒杀系统中实现链路追踪了。

## 二、本章诉求

在秒杀系统中整合Sleuth实现分布式链路追踪，在最简使用的基础上，实现抽样采集数据、追踪自定义线程池和自定义链路过滤器。通过秒杀系统，掌握业务中整合分布式链路追踪的方法，并能够灵活将实现方案应用到自身实际项目中。

## 三、Sleuth概述

Sleuth是SpringCloud中提供的一个分布式链路追踪组件，在设计上大量参考并借用了Google Dapper的设计。

### 3.1 Span简介

Span在Sleuth中代表一组基本的工作单元，当请求到达各个微服务时，Sleuth会通过一个唯一的标识，也就是SpanId来标记开始通过这个微服务，在当前微服务中执行的具体过程和执行结束，此时，通过SpanId标记的开始时间戳和结束时间戳，就能够统计到当前Span的调用时间，也就是当前微服务的执行时间。另外，也可以用过Span获取到事件的名称，请求的信息等数据。

**总结：远程调用和Span是一对一的关系，是分布式链路追踪中最基本的工作单元，每次发送一个远程调用服务就会产生一个 Span。Span Id 是一个 64 位的唯一 ID，通过计算 Span 的开始和结束时间，就可以统计每个服务调用所耗费的时间。**

### 3.2 Trace简介

Trace的粒度比Span的粒度大，Trace主要是由具有一组相同的Trace ID的Span组成的，从请求进入分布式系统入口经过调用各个微服务直到返回的整个过程，都是一个Trace。也就是说，当请求到达分布式系统的入口时，Sleuth会为请求创建一个唯一标识，这个唯一标识就是Trace Id，不管这个请求在分布式系统中如何流转，也不管这个请求在分布式系统中调用了多少个微服务，这个Trace Id都是不变的，直到整个请求返回。

**总结：一个 Trace 可以对应多个 Span，Trace和Span是一对多的关系。Trace Id是一个64 位的唯一ID。Trace Id可以将进入分布式系统入口经过调用各个微服务，再到返回的整个过程的请求串联起来，内部每通过一次微服务时，都会生成一个新的SpanId。Trace串联了整个请求链路，而Span在请求链路中区分了每个微服务。**

### 3.3 Annotation简介

Annotation记录了一段时间内的事件，内部使用的重要注解如下所示。

* cs（Client Send）客户端发出请求，标记整个请求的开始时间。
* sr（Server Received）服务端收到请求开始进行处理，通过sr与cs可以计算网络的延迟时间，例如：sr－ cs = 网络延迟（服务调用的时间）。
* ss（Server Send）服务端处理完毕准备将结果返回给客户端， 通过ss与sr可以计算服务器上的请求处理时间，例如：ss - sr = 服务器上的请求处理时间。
* cr（Client Reveived）客户端收到服务端的响应，请求结束。通过cr与cs可以计算请求的总时间，例如：cr - cs = 请求的总时间。

**总结：链路追踪系统内部定义了少量核心注解，用来定义一个请求的开始和结束，通过这些注解，我们可以计算出请求的每个阶段的时间。需要注解的是，这里说的请求，是在系统内部流转的请求，而不是从浏览器、APP、H5、小程序等发出的请求。**

## 四、整合Sleuth

Sleuth提供了分布式链路追踪能力，如果需要使用Sleuth的链路追踪功能，需要在秒杀系统中集成Sleuth。

### 4.1 最简使用

**（1）新增Sleuth依赖**

在秒杀系统的pom.xml文件中添加如下Sleuth的依赖。

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-sleuth</artifactId>
</dependency>
```

**（2）新增SeckillGatewayFilter类**

由于SpringCloud与SpringCloud Alibaba都升级到 2021.0.1版本后，SpringCloud Gateway无法正常获取到tranceId和SpanId。为此，我们在网关服务里新增一个SeckillGatewayFilter过滤器类。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
