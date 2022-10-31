---
title: 第28章：基于SPI扩展Hessian2序列化与反序列化机制
pay: https://articles.zsxq.com/id_23d9f8sx8imj.html
---

# 《RPC手撸专栏》第28章：基于SPI扩展Hessian2序列化与反序列化机制

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe001.github.io](https://binghe001.github.io)
<br/>文章汇总：[https://binghe001.github.io/md/all/all.html](https://binghe001.github.io/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在前面的章节中，我们实现了对标Dubbo的SPI基础功能，并基于SPI扩展了JDK与Json的序列化与反序列化方式，就序列化模块而言，整体具备了高度的可扩展性。

## 一、前言

`这次又要怎么扩展呢？`

在前面的章节中，在涉及到数据的编解码过程中，我们实现了基于SPI扩展JDK与Json的序列化与反序列化方式。但是，JDK序列化与反序列化方式不能跨语言调用，Json序列化与反序列化虽然可以跨语言调用，但是其性能不是很高，今天我们再次对序列化与反序列化方式进行扩展。

## 二、目标

`目标：新增Hessian2序列化与反序列化方式！`

Hessian2提供了完整的序列化规范，可以允许跨语言实现序列化和反序列化。能够将类的描述信息写入序列化文件中，这种方式可以保证反序列化时新旧版本对象的兼容性。同时，Hessian2在内容的序列化上做了优化，能够将需要序列化的多个相同的对象只写入一次，其他用到该对象的地方只使用对象的引用，而不重新写入对象的描述信息和值信息。

本章，我们就在实现原有序列化与反序列化方式的基础上，新增基于Hessian2的序列化方式。

## 三、设计

`如果让你设计基于SPI扩展Hessian2序列化与反序列化方式，你会怎么做呢？`

基于SPI再次扩展Hessian2的序列化与反序列化机制后，整体流程如图28-1所示。

![图28-1](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-10-31-001.png)

由图28-1可以看出，在实现数据的编解码过程中，再次扩展基于Hessian2的序列化和反序列化方式后，自定义的编解码器会通过SPI机制加载序列化与反序列化的具体实现方式，程序会根据具体需要加载某一种特定的序列化与反序列化方式，同样不会在程序中硬编码写死。

* 基于JDK的序列化与反序列化方式的Key为jdk。
* 基于Json的序列化与反序列化方式的Key为json。
* 基于Hessian2的序列化与反序列化方式的Key为hessian2。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

基于SPI再次扩展Hessian2的序列化与反序列化机制的核心类关系如图28-2所示。

![图28-2](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-10-31-002.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码