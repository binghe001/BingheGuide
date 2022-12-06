---
title: 第34章：基于SPI扩展Javassist动态代理机制
pay: https://articles.zsxq.com/id_i2tz6xldl3hc.html
---

# 《RPC手撸专栏》第34章：基于SPI扩展Javassist动态代理机制

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在前面的章节中，我们基于SPI扩展了JDK和CGLib动态代理机制，但这远远不够，我还想扩展其他的动态代理机制。

## 一、前言

`继续扩展其他的动态代理机制？`

在前面的文章中，已经实现了基于SPI扩展JDK和CGLib动态代理的功能，相信各位小伙伴们已经非常清楚如何使用SPI扩展动态代理的功能了，也非常清楚使用SPI如何扩展其他功能了。但是冰河还是要多为大家多在RPC框架中集成几种动态代理功能。这次要基于SPI扩展哪种动态代理呢？

没错，就是业界有名的Javassist。

## 二、目标

`目标很明确：基于SPI扩展Javassist动态代理机制。`

在前面的文章中，我们基于SPI机制扩展了JDK动态代理和CGLib动态代理，在一定程度上增强了动态代理的扩展性，但是在一个通用型RPC框架中，只集成两种动态代理方式是远远不够的。

为了进一步增强动态代理的功能，我们还要基于SPI进一步扩展Javassist动态代理功能，让用户对动态代理功能有更多的选择。

接下来，我们就开始在RPC框架中基于SPI扩展实现Javassist动态代理。

## 三、设计

`如果让你设计基于SPI扩展Javassist动态代理机制，你会怎么设计呢？`

基于SPI扩展CGLib动态代理机制的流程如图34-1所示。

![图34-1](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-11-09-001.png)

由图34-1可以看出，使用SPI机制扩展Javassist动态代理的功能后，与图32-1一样，服务消费者RPC客户端会引用动态代理工厂接口，并基于SPI动态加载代理工厂接口的实现类。这种方式能够极大的增强动态代理功能的扩展性。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

基于SPI再次扩展Javassist动态代理机制的核心类关系如图34-2所示。

![图34-2](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-11-09-002.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码