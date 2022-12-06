---
title: 第39章：基于SPI扩展Javassist反射机制调用真实方法
pay: https://articles.zsxq.com/id_wgicowxzrwal.html
---

# 《RPC手撸专栏》第39章：基于SPI扩展Javassist反射机制调用真实方法

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在前面的章节中，我们在服务消费者端基于SPI扩展了JDK、CGLib、Javassist、ByteBuddy和ASM动态代理机制。在服务提供者端，基于SPI扩展了JDK和CGLib反射机制调用真实方法的功能。

## 一、前言

`之前基于SPI扩展了JDK和CGLib反射机制调用真实方法，还能扩展其他的方式调用真实方法吗？`

在前面的文章中，我们基于SPI扩展了使用JDK和CGLib反射机制调用真实方法的功能，并且已经完美经过了测试的验证。其实，小伙伴们都知道，之前我们实现了基于JDK和CGLib两种方式调用真实方法，但是后来我们对服务提供者调用真实方法进行了基于SPI的动态扩展，后续我们也会支持更多的反射机制调用真实方法。

## 二、目标

`目标很明确：基于SPI扩展Javassist反射机制调用真实方法！`

经过前面两篇文章，我们已经完美的基于SPI扩展了服务提供者调用真实方法的功能，并且基于SPI动态扩展了JDK和CGLib反射机制，在服务提供者端实现了调用真实方法高度的扩展性。但对于一个成熟和完善的RPC框架而言，仅仅支持两种方式调用真实方法是远远不够的。

当然，小伙伴们可以根据自己的实际需要，基于SPI动态扩展更多的反射类型。但冰河仍然想带着大家在我们自己手写的RPC框架中一起内置更多的反射类型，以便大家在使用RPC框架时，能够以不同的配置参数选择使用不同的反射类型。

本章，我们就继续基于SPI扩展Javassist反射机制调用真实方法。

## 三、设计

`如果让你设计基于SPI扩展Javassist反射机制调用真实方法，你会怎么设计呢？`

基于SPI扩展Javassist反射机制调用真实方法的流程图如图39-1所示。

![图39-1](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-11-16-001.png)

由图39-1可以看出，服务提供者会以SPI的形式引用调用真实方法的SPI接口，基于JDK、CGLib和Javassist的反射机制调用真实方法的类是SPI接口的实现类，服务提供者会通过SPI加载JDK、CGLib和Javassist反射机制调用真实方法的实现类。而JDK、CGLib和Javassist反射机制调用真实方法的实现类会实现SPI接口，最终调用真实方法。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

基于SPI扩展Javassist反射机制调用真实方法的核心类关系如图39-2所示。

![图39-2](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-11-16-002.png)


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码