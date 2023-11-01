---
title: 第45章：ThreadLocal内存泄露分析
pay: https://articles.zsxq.com/id_g8i50u1mshoi.html
---

# 《并发设计模式》第45章-线程特有存储模式-ThreadLocal内存泄露分析

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：了解什么是线程特有存储模式，重点理解线程特有存储模式解决线程安全的核心思路与原理，掌握ThreadLocal内存移除的场景，学会内存泄露问题分析，能够融会贯通，并能够结合自身项目实际场景思考如何将线程特有存储模式灵活应用到自身实际项目中。

**大家好，我是冰河~~**

ThreadLocal能够在线程本地存储对应的变量，从而有效的避免线程安全问题。但是使用ThreadLocal时，稍微不注意就有可能造成内存泄露的问题。那么ThreadLocal在哪些场景下会出现内存泄露？哪些场景下不会出现内存泄露？出现内存泄露的根本原因又是什么呢？

## 一、背景故事

小菜基于ThreadLocal很好的解决了用户信息错乱的问题，并且在老王的指导下，很快掌握了什么是线程特有存储模式，也能够通过线程特有存储模式解决格式化日期时间的线程安全问题，同时，也了解到线程特有存储模式在JDK中的应用场景。但是，回到问题本身，小菜一直在思考着几个问题：ThreadLocal在哪些场景下会出现内存泄露？哪些场景下不会出现内存泄露？出现内存泄露的根本原因又是什么呢？带着这几个疑问，小菜又开始研究起了ThreadLocal。但是，只是通过阅读ThreadLocal的源码，不太直观，也有点让人费劲。于是，小菜觉得还是让老王给自己讲讲来的快。就这样，在老王的耐心指导下，小菜也彻底搞懂了心中的疑问。

## 二、ThreadLocal内部结构

为了更好的说明ThreadLocal内存泄露的场景，以及具体的原因，先来了解下ThreadLocal的内部结构，如图45-1所示。

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/core/concurrent/2023-11-01-001.png?raw=true" width="80%">
    <br/>
</div>

可以看到，ThreadLocal对象是存储在每个Thread线程内部的ThreadLocalMap中的，并且在ThreadLocalMap中有一个Entry数组，Entry数组中的每一个元素都是一个Entry对象，每个Entry对象中存储着一个ThreadLocal对象与其对应的value值，每个Entry对象在Entry数组中的位置是通过ThreadLocal对象的threadLocalHashCode计算出来的，以此来快速定位Entry对象在Entry数组中的位置。所以，在Thread中，可以存储多个ThreadLocal对象。

## 三、不会出现内存泄露的场景

了解完ThreadLocal的内部存储结构后，我们先来思考下哪些场景下ThreadLocal不会发生内存泄露，假设我们单独开启一个线程，并且将变量存储到ThreadLocal中，如图45-2所示。

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/core/concurrent/2023-11-01-002.png?raw=true" width="80%">
    <br/>
</div>

可以看到，Thread线程在正常执行的情况下，会引用ThreadLocalMap的实例对象，只要Thread线程一直在执行任务，这种引用关系就一直存在。当Thread线程执行任务结束退出时，Thread线程与ThreadLocalMap实例对象之间的引用关系就不存在了，如图45-3所示。

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/core/concurrent/2023-11-01-003.png?raw=true" width="80%">
    <br/>
</div>

## 查看全文

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码