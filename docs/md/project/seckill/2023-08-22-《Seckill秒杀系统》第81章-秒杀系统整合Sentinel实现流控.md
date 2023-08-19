---
title: 第81章：秒杀系统整合Sentinel实现流控
pay: https://articles.zsxq.com/id_88wejhb2hgzg.html
---

# 《Seckill秒杀系统》第81章：秒杀系统整合Sentinel实现流控

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：掌握在秒杀系统中基于Nacos整合Sentinel的方法，重点理解Sentinel实现流控的核心原理，并能够将Sentinel灵活应用到自身实际项目中。

**大家好，我是冰河~~**

虽然秒杀系统是专门为应对瞬时高并发、大流量场景而涉及的系统，但是秒杀系统承载的流量也不是无限的，也会存在上限，所以，需要对进入秒杀系统的流量进行管控，不能让所有流量不加刷选和鉴别的流入秒杀系统。否则，可能会给秒杀系统带来灾难性的后果。

## 一、前言

Sentinel 承接了阿里巴巴近 10 年的双十一大促流量的核心场景，例如秒杀（即突发流量控制在系统容量可以承受的范围）、消息削峰填谷、集群流量控制、实时熔断下游不可用应用等。Sentinel成功经受住了互联网大厂高并发场景的考验，所以，我们研发的秒杀系统中，采用了Sentinel进行流控。

## 二、本章诉求

整合Nacos与Sentinel，使秒杀系统启动时能够自动读取Nacos中的配置，在秒杀系统中引入Sentinel相关的依赖，并且整合Sentinel后，实现对接口流量的管控。

## 三、配置Nacos

本章，旨在通过Sentinel读取Nacos中的配置来实现流控规则，在秒杀系统中整合Sentinel之前，先在Nacos中添加一些Sentinel的配置。

### 3.1 添加命名空间

在Nacos中，添加命名空间的步骤如下所示。

（1）在浏览器打开Nacos界面，登录后，在找到命名空间，如图81-1所示。

<div align="center">
    <img src="https://binghe.gitcode.host/images/project/seckill/seckill-2023-08-22-001.png?raw=true" width="60%">
    <br/>
</div>


（2）按照图81-2所示添加命名空间后，点击确定按钮即可。

<div align="center">
    <img src="https://binghe.gitcode.host/images/project/seckill/seckill-2023-08-22-002.png?raw=true" width="60%">
    <br/>
</div>

### 3.2 添加Sentinel配置

在Nacos中添加Sentinel的步骤如下所示。

（1）在Nacos中打开配置列表页面，如图81-3所示。

<div align="center">
    <img src="https://binghe.gitcode.host/images/project/seckill/seckill-2023-08-22-003.png?raw=true" width="60%">
    <br/>
</div>


这里注意的是，在配置列表中要切换到sentinel-config命名空间。点击右上角的 **+** 添加Sentinel配置。

（2）按照图81-4所示添加Sentinel流控配置。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码