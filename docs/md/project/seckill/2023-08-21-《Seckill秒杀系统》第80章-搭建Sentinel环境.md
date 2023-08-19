---
title: 第80章：Sentinel概述与本地搭建环境
pay: https://articles.zsxq.com/id_ofdkbfo5ptww.html
---

# 《Seckill秒杀系统》第80章：Sentinel概述与本地搭建环境

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：掌握本地搭建Sentinel环境的方法，重点掌握Sentinel的特征与基本原理，并能够灵活将Sentinel应用到自身实际项目中。

**大家好，我是冰河~~**

随着微服务的流行，服务和服务之间的稳定性变得越来越重要。Sentinel 以流量为切入点，从流量控制、熔断降级、系统负载保护等多个维度保护服务的稳定性。

## 一、前言

在《[第8章：秒杀系统研发环境搭建](https://articles.zsxq.com/id_0icjzih3iia1.html)》一章中，我们实现了通过docker-compose一键安装研发环境，但有些小伙伴可能由于网络问题，有些Docker镜像下载很慢，这里，对于Sentinel来说，就带着大家一起搭建一个本地Sentinel的环境。

## 二、本章诉求

简单介绍下Sentinel相关的知识，并搭建一套Sentinel本地环境，掌握本地搭建Sentinel环境的方法，重点掌握Sentinel的特征与基本原理，并能够灵活将Sentinel应用到自身实际项目中。

## 三、关于Sentinel

随着微服务的流行，服务和服务之间的稳定性变得越来越重要。Sentinel 以流量为切入点，从流量控制、熔断降级、系统负载保护等多个维度保护服务的稳定性。

### Sentinel的特征

- **丰富的应用场景**：Sentinel 承接了阿里巴巴近 10 年的双十一大促流量的核心场景，例如秒杀（即突发流量控制在系统容量可以承受的范围）、消息削峰填谷、集群流量控制、实时熔断下游不可用应用等。
- **完备的实时监控**：Sentinel 同时提供实时的监控功能。您可以在控制台中看到接入应用的单台机器秒级数据，甚至 500 台以下规模的集群的汇总运行情况。
- **广泛的开源生态**：Sentinel 提供开箱即用的与其它开源框架/库的整合模块，例如与 Spring  Cloud、Apache Dubbo、gRPC、Quarkus 的整合。您只需要引入相应的依赖并进行简单的配置即可快速地接入  Sentinel。同时 Sentinel 提供 Java/Go/C++ 等多语言的原生实现。
- **完善的 SPI 扩展机制**：Sentinel 提供简单易用、完善的 SPI 扩展接口。您可以通过实现扩展接口来快速地定制逻辑。例如定制规则管理、适配动态数据源等。

### Sentinel的主要特性

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-001.png?raw=true" width="80%">
    <br/>
</div>

### Sentinel的开源生态

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-002.png?raw=true" width="80%">
    <br/>
</div>

Sentinel 分为两个部分:

- 核心库（Java 客户端）不依赖任何框架/库，能够运行于所有 Java 运行时环境，同时对 Dubbo / Spring Cloud 等框架也有较好的支持。
- 控制台（Dashboard）基于 Spring Boot 开发，打包后可以直接运行，不需要额外的 Tomcat 等应用容器

注意：上述内容来自Sentinel官方文档，链接地址为：[https://github.com/alibaba/Sentinel/wiki/%E4%BB%8B%E7%BB%8D](https://github.com/alibaba/Sentinel/wiki/介绍)

## 四、搭建Sentinel环境

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码