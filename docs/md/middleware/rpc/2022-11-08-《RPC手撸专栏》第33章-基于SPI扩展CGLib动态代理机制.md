---
title: 第33章：基于SPI扩展CGLib动态代理机制
pay: https://articles.zsxq.com/id_ncdserhiza68.html
---

# 《RPC手撸专栏》第33章：基于SPI扩展CGLib动态代理机制

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客1：[https://binghe001.github.io](https://binghe001.github.io)
<br/>博客2：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe001.github.io/md/all/all.html](https://binghe001.github.io/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在前面的章节中，我们基于SPI扩展了JDK动态代理机制，但这远远不够，我还想扩展其他的动态代理机制。

## 一、前言

`继续扩展其他的动态代理机制？`

在前面的文章中，已经实现了基于SPI扩展JDK动态代理的功能，但是对于一个较为成熟和完善的RPC框架来说，只支持JDK动态代理是远远不够的，我们还需要内置更多的动态代理功能，让用户有所选择的使用某一种动态代理功能。

那怎么办呢？撸起袖子加油干吧，冲！！

## 二、目标

`目标很明确：基于SPI扩展CGLib动态代理机制。`

动态代理机制能够在原有方法的基础上增强很多功能，比如在执行方法的前后执行一些其他的逻辑。在不修改原有逻辑的情况下新增一些功能等等。

为了进一步增强动态代理的功能，在原有基于SPI扩展JDK动态代理的基础上，我们还要基于SPI进一步扩展CGLib动态代理功能，让用户对动态代理功能有更多的选择。

开始吧，基于SPI扩展CGLib动态代理功能。

## 三、设计

`如果让你设计基于SPI扩展CGLib动态代理机制，你会怎么设计呢？`

基于SPI扩展CGLib动态代理机制的流程如图33-1所示。

![图33-1](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-11-08-001.png)

由图33-1可以看出，使用SPI机制扩展CGLib动态代理的功能后，与图32-1一样，服务消费者RPC客户端会引用动态代理工厂接口，并基于SPI动态加载代理工厂接口的实现类。这种方式能够极大的增强动态代理功能的扩展性。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

基于SPI再次扩展CGLib动态代理机制的核心类关系如图33-2所示。

![图33-2](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-11-08-002.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码