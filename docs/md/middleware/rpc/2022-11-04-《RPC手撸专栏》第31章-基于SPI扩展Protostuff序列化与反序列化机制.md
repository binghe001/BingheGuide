---
title: 第31章：基于SPI扩展Protostuff序列化与反序列化机制
pay: https://articles.zsxq.com/id_oldx0om9zxqc.html
---

# 《RPC手撸专栏》第31章：基于SPI扩展Protostuff序列化与反序列化机制

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在前面的章节中，我们实现了对标Dubbo的SPI基础功能，并基于SPI扩展了JDK、Json、Hessian2、FST与Kryo的序列化与反序列化方式，就序列化模块而言，整体具备了高度的可扩展性。来吧，我们进一步扩展序列化与反序列化机制。

## 一、前言

`这次又要怎么扩展呢？`

与前面文章的节奏一样，在前面的章节中，在涉及到数据的编解码过程中，我们实现了基于SPI扩展JDK、Json、Hessian2、FST与Kryo的序列化与反序列化方式。这次我还想继续扩展序列化与反序列化的类型，怎么办呢？

还能怎么办呢？撸起袖子加油干吧！

## 二、目标

`目标很明确：新增Protostuff序列化与反序列化方式！`

在前面的文章中，也已经说明了：对于RPC这种远程调用的底层基础设施框架来说，其性能的高低直接影响着整套分布式系统的性能。数据在网络中传输就涉及到数据的编解码，数据的编解码又会涉及到数据的序列化与反序列化，使用一款高效的序列化与反序列化框架有助于提升RPC框架的性能。

Protocol Buffer是谷歌出品的一种高性能的数据交换格式，独立于语言和平台，类似于json。Google提供了多种语言的实现：java、c++、go和python。对象序列化城Protocol Buffer之后可读性差，但是相比xml，json，它占用小，速度快。适合做数据存储或 RPC 数据交换格式。

但是相对于我们常用的json来说，Protocol  Buffer门槛更高，因为需要编写.proto文件，再把它编译成目标语言，这样使用起来就很麻烦。但是现在有了Protostuff之后，就不需要依赖.proto文件了，他可以直接对POJO进行序列化和反序列化，使用起来非常简单。

好了，本章就基于SPI扩展支持Protostuff序列化与反序列化方式。

## 三、设计

`如果让你设计基于SPI扩展Protostuff序列化与反序列化，你会怎么设计呢？`

基于SPI再次扩展Protostuff的序列化与反序列化机制后，整体流程如图31-1所示。

![图31-1](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-11-04-001.png)

由图31-1可以看出，在实现数据的编解码过程中，再次扩展基于Protostuff的序列化和反序列化方式后，自定义的编解码器会通过SPI机制加载序列化与反序列化的具体实现方式，程序会根据具体需要加载某一种特定的序列化与反序列化方式，同样不会在程序中硬编码写死。

* 基于JDK的序列化与反序列化方式的Key为jdk。
* 基于Json的序列化与反序列化方式的Key为json。
* 基于Hessian2的序列化与反序列化方式的Key为hessian2。
* 基于FST的序列化与反序列化方式的Key为fst。
* 基于Kryo的序列化与反序列化方式的Key为kryo。
* 基于Protostuff的序列化与反序列化方式的Key为protostuff。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

基于SPI再次扩展Kryo的序列化与反序列化机制的核心类关系如图31-2所示。

![图31-2](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-11-04-002.png)


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
