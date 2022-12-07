---
title: 第57章：基于SPI扩展实现Zookeeper注册中心
pay: https://articles.zsxq.com/id_xkq21xwlnq48.html
---

# 《RPC手撸专栏》第57章：基于SPI扩展实现Zookeeper注册中心

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客1：[https://binghe001.github.io](https://binghe001.github.io)
<br/>博客2：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe001.github.io/md/all/all.html](https://binghe001.github.io/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在前面的章节中，我们基于SPI扩展了JDK、Json、Hessian2、FST、Kryo和Protostuff序列化与反序列化机制，在服务消费者端基于SPI扩展了JDK、CGLib、Javassist、ByteBuddy和ASM动态代理机制。在服务提供者端，基于SPI扩展了JDK、CGLib、Javassist、ByteBuddy和ASM反射机制调用真实方法的功能，并且基于SPI扩展实现了负载均衡策略和增强型负载均衡策略。

## 一、前言

`肝完负载均衡，我们再来肝注册中心...`

在前面的文章中，我们基于SPI扩展了序列化与反序列化机制、动态代理机制、反射机制、负载均衡策略与增强型负载均衡策略。接下来，我们就一起对注册中心下手。

**注意：为了更好的学习《RPC手撸专栏》后续的内容，也为了让星球的小伙伴提升项目的参与感，冰河只带着大家基于SPI扩展实现Zookeeper的注册中心，框架原本的计划是基于SPI扩展实现Zookeeper、Consul、Etcd、Euraka和Nacos等注册中心，框架需要支持并实现的Consul、Etcd、Euraka和Nacos等注册中心，本章结束后以作业的形式留给小伙伴们自行实现，实现方式可参考本章基于SPI扩展实现Zookeeper注册中心的实现方式和源码。**

## 二、目标

`目标很明确：基于SPI扩展实现Zookeeper注册中心！`

在前面的文章中，已经实现了Zookeeper注册中心，但是在具体使用注册中心的功能时，在代码中直接创建了ZookeeperRegistryService类的对象，这样非常不利于注册中心模块的扩展。本章，要对注册中心模块进行SPI改造，通过SPI接口就能够动态加载具体的注册中心实现类。

## 三、设计

`如果让你设计基于SPI扩展实现Zookeeper注册中心的流程，你会怎么设计呢？`

基于SPI扩展实现Zookeeper注册中心的流程如图57-1所示。

![图57-1](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-12-07-002.png)

由图57-1可以看出如下信息：

（1）服务提供者会通过自定义类扫描器整合注册中心，将服务注册到注册中心。

（2）服务注册到注册中心的元数据，例如服务的名称、服务的版本号、服务地址、服务端口和服务分组等信息，元数据会贯穿整个服务的注册与发现流程。

（3）服务注册与发现SPI接口对外提供服务注册与发现的方法，服务提供者通过自定义扫描器会调用服务注册与发现SPI接口的方法实现服务注册功能。

（4）基于服务注册与发现的SPI接口，服务提供者会基于SPI接口实现多个服务注册与发现的实现类，每个实现类对应着一种注册中心服务。

（5）服务消费者会通过服务注册与发现的SPI接口订阅注册中心的服务，会从注册中心获取到服务提供者发布的服务信息，实现服务发现的功能。

（7）服务消费者从注册中心获取到服务提供者发布的服务信息后，会基于SPI机制动态加载普通算法（我们将第42章~第50章实现的负载均衡算法统称为普通算法）、基于增强型加权随机算法、基于增强型加权轮询算法、基于增强型加权Hash算法、基于增强型加权源IP地址Hash算法、基于增强型Zookeeper一致性Hash算法和最少连接数算法的负载均衡策略，从多个服务中选择一个进行远程网络连接。

（8）服务消费者会直接与根据基于SPI机制动态加载的负载均衡策略选择出的服务提供者建立连接，实现数据交互。也就是说，后续服务消费者会与服务提供者直接实现数据交互。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

基于SPI扩展实现Zookeeper注册中心的核心类关系如图57-2所示。

![图57-2](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-12-07-003.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
