---
title: 第35章：基于SPI扩展ByteBuddy动态代理机制
pay: https://articles.zsxq.com/id_sth5wav0oicw.html
---

# 《RPC手撸专栏》第35章：基于SPI扩展ByteBuddy动态代理机制

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客1：[https://binghe001.github.io](https://binghe001.github.io)
<br/>博客2：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe001.github.io/md/all/all.html](https://binghe001.github.io/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在前面的章节中，我们基于SPI扩展了JDK、CGLib和Javassist动态代理机制，但这还不够，我还想扩展其他的动态代理机制，来吧，一起再扩展吧。

## 一、前言

`继续扩展其他的动态代理机制，你能搞定吗？`

在前面的文章中，已经实现了基于SPI扩展JDK、CGLib和Javassist动态代理的功能，冰河进一步相信各位小伙伴们已经非常清楚如何使用SPI扩展动态代理的功能了，也非常清楚使用SPI如何扩展其他功能了。但是冰河还是要为大家再多扩展下RPC框架中支持的动态代理类型。这次要基于SPI扩展哪种动态代理呢？

没错，我们这次要基于SPI扩展的动态代理就是业界有名的ByteBuddy。

## 二、目标

`目标很明确：基于SPI扩展ByteBuddy动态代理机制。`

在前面的文章中，我们基于SPI机制扩展了JDK、CGLib和Javassist动态代理，在一定程度上增强了动态代理的扩展性，为了使RPC框架内置的动态代理功能更加丰富，我们可以再扩展一些动态代理功能。

为了进一步增强动态代理的功能，我们还要基于SPI进一步扩展ByteBuddy动态代理功能，让用户对动态代理功能有更多的选择和参考。

接下来，我们就开始在RPC框架中基于SPI扩展实现ByteBuddy动态代理。

## 三、设计

`如果让你设计基于SPI扩展ByteBuddy动态代理机制，你会怎么设计呢？`

基于SPI扩展ByteBuddy动态代理机制的流程如图35-1所示。

![图35-1](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-11-10-001.png)

由图35-1可以看出，使用SPI机制扩展ByteBuddy动态代理的功能后，与图32-1一样，服务消费者RPC客户端会引用动态代理工厂接口，并基于SPI动态加载代理工厂接口的实现类。这种方式能够极大的增强动态代理功能的扩展性。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

基于SPI再次扩展ByteBuddy动态代理机制的核心类关系如图35-2所示。

![图35-2](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-11-10-002.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码