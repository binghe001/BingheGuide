---
title: 第25章：对标Dubbo实现SPI扩展机制的基础功能
pay: https://articles.zsxq.com/id_cvhib8cm8iaf.html
---

# 《RPC手撸专栏》第25章：对标Dubbo实现SPI扩展机制的基础功能

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

我们写的RPC框架不仅实现了服务消费者与服务提供者之间正常的数据交互，也实现了注册中心的基础服务功能，同时，服务提供者正常整合了注册中心，实现了服务注册功能，服务消费者也正常整合了注册中心，实现了服务发现功能。并且在服务消费者端实现了负载均衡功能，整体功能越来越完善了。

## 一、前言

`我想进一步提升程序的扩展性，怎么办呢？`

在前面的章节中，服务提供者整合了注册中心，能够在启动时，使用自定义类扫描器扫描标注有@RpcService注解的类，并解析@RpcService注解，将发布的服务的元数据注册到注册中心。同时，服务消费者也整合了注册中心，实现了服务的动态发现功能。

服务消费者整合注册中心之后，再也不用在服务消费者的代码里写死服务提供者监听的IP地址和端口号了。服务消费者实现了无需提前知道，也无需提前关注服务提供者部署在哪台服务器，服务提供者到底是监听的哪个IP和哪个端口号，只需要从注册中心获取服务提供者注册的元数据信息，从元数据信息中解析出对应的IP地址和端口号即可直接与服务提供者建立网络连接。

服务消费者端实现了基于随机算法的负载均衡策略，能够从获取到的多个服务提供者服务中，随机选择一个建立网络连接，进行远程通信。

至此，我们自己手写的RPC框架的功能正在一步步完善中。但是，真要想在实际项目中使用的话，还是有很多工作要做的。比如，需要进一步提升程序的扩展性该如何实现呢？

## 二、目标

`目标很明确：实现SPI的基础功能，以便后续基于SPI扩展框架各模块的功能！`

截止到目前，我们自己写的RPC框架中，预留了大量的扩展点，这些扩展点大部分都是基于某一种特定的实现方式来实现的。也就是在程序中写死了某一种实现方式。

例如，在bhrpc-registry-zookeeper工程下的io.binghe.rpc.registry.zookeeper.ZookeeperRegistryService类中的init()方法中，创建ServiceLoadBalancer接口的对象serviceLoadBalancer时，就写死创建的是RandomServiceLoadBalancer对象，源码片段如下所示。

```java
//负载均衡接口
private ServiceLoadBalancer<ServiceInstance<ServiceMeta>> serviceLoadBalancer;
@Override
public void init(RegistryConfig registryConfig) throws Exception {
    //############省略其他代码#############
    //TODO 默认创建基于随机算法的负载均衡策略，后续基于SPI扩展
    this.serviceLoadBalancer = new RandomServiceLoadBalancer<ServiceInstance<ServiceMeta>>();
}
```

如果框架中使用这种方式实现代码的功能，后续是很难扩展的。就拿上面这代代码来说，如果我们要在服务消费者端实现基于轮询策略的负载均衡，那就要修改框架的源代码了，这种方式是万万不可取的。

好在Java中提供了SPI机制能够动态扩展对应的功能，在我们实现的RPC框架中，会进一步扩展SPI的基础功能，实现对标Dubbo的SPI扩展机制。

## 三、设计

`如果让你设计对标Dubbo的SPI扩展机制，你会怎么设计呢？`

基于SPI机制加载接口实现类的总体流程如图25-1所示。

![图25-1](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-10-26-001.png)

由图25-1可以看出如下信息：

（1）使用SPI机制时需要定义一个SPI接口，SPI接口与Java中的普通接口相比，一般会在SPI接口上标注一个特殊的注解。

（2）SPI接口会有多个SPI实现类，同样的，SPI实现类与SPI接口一样，一般也会在SPI实现类上标注一个特殊的注解。

（3）具体功能里会引用SPI接口。

（4）具体功能里不会直接创建SPI实现类的对象，而是通过SPI加载机制来动态加载SPI的实现类。

（5）通过SPI加载机制加载的SPI实现类对象，会赋值给SPI接口引用。

（6）在具体功能里通过SPI接口调用的就是通过SPI加载机制加载的SPI实现类实现的具体逻辑。

接下来，以负载均衡策略为例，看看对标Dubbo的SPI扩展机制后，实现的效果如图25-2所示。

![图25-2](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-08-15-003.png)

可以看到，实现的效果就是对标了Dubbo的SPI扩展机制。

## 四、实现

`说了这么多，具体要怎么实现呢？`

### 核心类实现关系

对标Dubbo实现SPI扩展机制的基础功能核心类关系如图25-3所示。

![图25-3](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2022-10-26-002.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码