---
title: 第105章：秒杀系统链路追踪可视化
pay: https://articles.zsxq.com/id_gkdo616fwap6.html
---

# 《Seckill秒杀系统》第105章：秒杀系统链路追踪可视化

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：掌握Sleuth整合ZipKin实现可视化的方式，理解Sleuth与Zipkin对接的核心原理，并能够灵活将实现方案应用到自身实际项目中。

**大家好，我是冰河~~**

秒杀系统已经整合了Sleuth实现链路追踪，针对Sleuth默认不支持Dubbo实现链路追踪的问题，我们也通过扩展Dubbo源码的方式进行了处理。目前，不管是通过HTTP方式调用接口，还是通过RPC方式调用接口，都可以实现链路追踪了。不过，有个问题就是目前实现的链路追踪还是通过微服务输出的日志进行实现。那我想通过可视化的方式进行查看，可以吗？安排！

## 一、前言

在前面整合Sleuth实现链路追踪时，我们是通过查看日志的情况来了解系统调用的链路情况，这并不是一种很好的解决方案，如果系统所包含的微服务越来越多，通过查看日志的方式来分析系统的调用是非常复杂的，在实际项目中根本不可行。此时，我们可以将Sleuth和ZipKin进行整合，利用ZipKin将日志进行聚合，将链路日志进行可视化展示，并支持全文检索。

## 二、本章诉求

整合Sleuth与Zipkin，实现链路追踪的可视化，利用ZipKin将日志进行聚合，将链路日志进行可视化展示，并支持全文检索。掌握Sleuth整合Zipkin的原理和实现方案，掌握Zipkin数据持久化的实现方案，并能够将其灵活应用到自身实际项目中。

## 三、ZipKin核心架构

Zipkin 是 Twitter 的一个开源项目，它基于Google Dapper论文实现，可以收集微服务运行过程中的实时链路数据，并进行展示。

### 3.1 ZipKin概述

Zipkin是一种分布式链路跟踪系统，能够收集微服务运行过程中的实时调用链路信息，并能够将这些调用链路信息展示到Web界面上供开发人员分析，开发人员能够从ZipKin中分析出调用链路中的性能瓶颈，识别出存在问题的应用程序，进而定位问题和解决问题。

### 3.2 ZipKin核心架构

ZipKin的核心架构如图105-1所示。

<div align="center">
    <img src="https://binghe.gitcode.host/images/project/seckill/seckill-2023-09-15-001.png?raw=true" width="80%">
    <br/>
</div>

<p align="right"><font size="1">注：图片来源：https://zipkin.io/pages/architecture.html</font></p>

其中，ZipKin核心组件的功能如下所示。

- Reporter：ZipKin中上报链路数据的模块，主要配置在具体的微服务应用中。
- Transport：ZipKin中传输链路数据的模块，此模块可以配置为Kafka，RocketMQ、RabbitMQ等。
- Collector：ZipKin中收集并消费链路数据的模块，默认是通过http协议收集，可以配置为Kafka消费。
- Storage：ZipKin中存储链路数据的模块，此模块的具体可以配置为ElasticSearch、Cassandra或者MySQL，目前ZipKin支持这三种数据持久化方式。
- API：ZipKin中的API 组件，主要用来提供外部访问接口。比如给客户端展示跟踪信息，或是开放给外部系统实现监控等。
- UI： ZipKin中的UI 组件，基于API组件实现的上层应用。通过UI组件用户可以方便并且很直观地查询和分析跟踪信息。  

Zipkin在总体上会分为两个端，一个是Zipkin服务端，一个是Zipkin客户端，客户端主要是配置在微服务应用中，收集微服务中的调用链路信息，将数据发送给ZipKin服务端。

## 四、整合ZipKin

Zipkin总体上分为服务端和客户端，我们需要下载并启动ZipKin服务端的Jar包，在微服务中集成ZipKin的客户端。


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码