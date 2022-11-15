---
title: 第38章：基于SPI扩展CGLib反射机制调用真实方法
pay: https://articles.zsxq.com/id_lp85axls7tlj.html
---

# 《RPC手撸专栏》第38章：基于SPI扩展CGLib反射机制调用真实方法

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客1：[https://binghe001.github.io](https://binghe001.github.io)
<br/>博客2：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe001.github.io/md/all/all.html](https://binghe001.github.io/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在前面的章节中，我们在服务消费者端基于SPI扩展了JDK、CGLib、Javassist、ByteBuddy和ASM动态代理机制。在服务提供者端，基于SPI扩展了JDK反射机制调用真实方法的功能。

## 一、前言

`之前基于SPI扩展了JDK反射机制调用真实方法，还能扩展其他的方式调用真实方法吗？`

在前面的文章中，我们基于SPI扩展了JDK反射机制调用真实方法的功能，并且已经完美经过了测试的验证。其实，小伙伴们都知道，之前我们实现了基于JDK和CGLib两种方式调用真实方法。所以，接下来，我们就要实现基于SPI扩展CGLib反射机制调用真实方法。

## 二、目标

`目标很明确：基于SPI扩展CGLib反射机制调用真实方法！`

在上一章中，在服务提供者端基于SPI扩展了JDK反射机制调用真实方法的功能。在服务提供者端实现了调用真实方法高度的扩展性，今天，我们就再次基于SPI扩展CGLib反射机制调用真实方法。

好了，目标明确了，接下来就是撸起袖子加油干了！

## 三、设计

`如果让你设计基于SPI扩展CGLib反射机制调用真实方法，你会怎么设计呢？`

基于SPI扩展CGLib反射机制调用真实方法的流程图如图38-1所示。

![图38-1](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-11-15-001.png)

由图38-1可以看到，服务提供者会以SPI的形式引用调用真实方法的SPI接口，基于JDK和CGLib的反射机制调用真实方法的类是SPI接口的实现类，服务提供者会通过SPI加载JDK和CGLib反射机制调用真实方法的实现类。而JDK和CGLib反射机制调用真实方法的实现类会实现SPI接口，最终调用真实方法。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

基于SPI扩展CGLib反射机制调用真实方法的核心类关系如图38-2所示。

![图38-2](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-11-15-002.png)


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码