---
layout: post
category: binghe-code-rpc
title: 第fix-02章：修复Zookeeper一致性Hash负载均衡泛型类型不匹配的问题
tagline: by 冰河
tag: [rpc,mykit-rpc,binghe-code-rpc]
excerpt: 第fix-02章：修复Zookeeper一致性Hash负载均衡泛型类型不匹配的问题
lock: need
---

# 《RPC手撸专栏》第fix-02章：修复Zookeeper一致性Hash负载均衡泛型类型不匹配的问题

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客1：[https://binghe001.github.io](https://binghe001.github.io)
<br/>博客2：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

在写《RPC手撸专栏》的过程中，针对专栏版本的代码，在书写的过程中，会提前埋一些坑进去，使各位星球的小伙伴在调试代码的过程中，能够自己去发现问题，并且分析问题，最好也能够自己解决问题。经过自己发现问题->分析问题->解决问题的过程，能够提升大家对于RPC框架源码的参与过程，更重要的是，能够不断提升大家自己发现问题、分析问题和解决问题的能力，这种能够力才是程序员最核心的竞争力。

## 一、问题描述

`本章要解决什么问题呢？`

在负载均衡类型的设计中，最终设计了负载均衡和增强型负载均衡类型，这两种大的负载均衡类型与注册中心整合的过程中，最初分别使用了两种不同的泛型SPI接口进行区分，后来为了统一负载均衡类型SPI接口的调用，将两种泛型类型的SPI接口合并成了一种。但是在调用基于Zookeeper的负载均衡类型实现类的方法时，抛出了泛型类型不匹配的异常。

## 二、问题分析

`这个问题是如何产生的呢？`

将负载均衡类型和增强型负载均衡类型的泛型SPI接口合并后，基于Zookeeper一致性Hash的负载均衡类型泛型类型为：`ServiceInstance<ServiceMeta>`，调用负载均衡SPI接口的实例对象的泛型类型为：`ServiceMeta`。这就造成了泛型类型不匹配的问题。

相关类的源码如下所示。

**（1）ZKConsistentHashLoadBalancer类**

ZKConsistentHashLoadBalancer类表示基于Zookeeper一致性Hash的负载均衡实现类，源码详见：bhrpc-loadbalancer-consistenthash-zk工程下的io.binghe.rpc.loadbalancer.consistenthash.ZKConsistentHashLoadBalancer，修改前的源码如下所示。

```java
@SPIClass
public class ZKConsistentHashLoadBalancer implements ServiceLoadBalancer<ServiceInstance<ServiceMeta>> {
    private final static int VIRTUAL_NODE_SIZE = 10;
    private final static String VIRTUAL_NODE_SPLIT = "#";
    private final Logger logger = LoggerFactory.getLogger(ZKConsistentHashLoadBalancer.class);
    @Override
    public ServiceInstance<ServiceMeta> select(List<ServiceInstance<ServiceMeta>> servers, int hashCode, String ip) {
        logger.info("基于Zookeeper的一致性Hash算法的负载均衡策略...");
        TreeMap<Integer, ServiceInstance<ServiceMeta>> ring = makeConsistentHashRing(servers);
        TreeMap<Integer, T> ring = makeConsistentHashRing(servers);
        return allocateNode(ring, hashCode);
    }
    private ServiceInstance<ServiceMeta> allocateNode(TreeMap<Integer, ServiceInstance<ServiceMeta>> ring, int hashCode) {
        Map.Entry<Integer, ServiceInstance<ServiceMeta>> entry = ring.ceilingEntry(hashCode);
        Map.Entry<Integer, T> entry = ring.ceilingEntry(hashCode);
        if (entry == null) {
            entry = ring.firstEntry();
        }
        return entry.getValue();
    }
    private TreeMap<Integer, ServiceInstance<ServiceMeta>> makeConsistentHashRing(List<ServiceInstance<ServiceMeta>> servers) {
        TreeMap<Integer, ServiceInstance<ServiceMeta>> ring = new TreeMap<>();
        for (ServiceInstance<ServiceMeta> instance : servers) {
            for (int i = 0; i < VIRTUAL_NODE_SIZE; i++) {
                ring.put((buildServiceInstanceKey(instance) + VIRTUAL_NODE_SPLIT + i).hashCode(), instance);
            }
        return ring;
    }
    private String buildServiceInstanceKey(ServiceInstance<ServiceMeta> instance) {
        ServiceMeta payload = instance.getPayload();
        return String.join(":", payload.getServiceAddr(), String.valueOf(payload.getServicePort()));
    }
}
```

**（2）ZookeeperRegistryService类**

ZookeeperRegistryService类表示基于Zookeeper的注册中心实现类，源码详见：bhrpc-registry-zookeeper工程下的io.binghe.rpc.registry.zookeeper.ZookeeperRegistryService，修改前的源码如下所示。

```java
@SPIClass
public class ZookeeperRegistryService implements RegistryService {
    public static final int BASE_SLEEP_TIME_MS = 1000;
    public static final int MAX_RETRIES = 3;
    public static final String ZK_BASE_PATH = "/binghe_rpc";

    private ServiceDiscovery<ServiceMeta> serviceDiscovery;
    //负载均衡接口
    private ServiceLoadBalancer<ServiceInstance<ServiceMeta>> serviceLoadBalancer;

    private ServiceLoadBalancer<ServiceMeta> serviceEnhancedLoadBalancer;

    @Override
    public void init(RegistryConfig registryConfig) throws Exception {
        CuratorFramework client = CuratorFrameworkFactory.newClient(registryConfig.getRegistryAddr(), new ExponentialBackoffRetry(BASE_SLEEP_TIME_MS, MAX_RETRIES));
        client.start();
        JsonInstanceSerializer<ServiceMeta> serializer = new JsonInstanceSerializer<>(ServiceMeta.class);
        this.serviceDiscovery = ServiceDiscoveryBuilder.builder(ServiceMeta.class)
                .client(client)
                .serializer(serializer)
                .basePath(ZK_BASE_PATH)
                .build();
        this.serviceDiscovery.start();
        //增强型负载均衡策略
        if (registryConfig.getRegistryLoadBalanceType().toLowerCase().contains(RpcConstants.SERVICE_ENHANCED_LOAD_BALANCER_PREFIX)){
            this.serviceEnhancedLoadBalancer = ExtensionLoader.getExtension(ServiceLoadBalancer.class, registryConfig.getRegistryLoadBalanceType());
        }else{
            this.serviceLoadBalancer = ExtensionLoader.getExtension(ServiceLoadBalancer.class, registryConfig.getRegistryLoadBalanceType());
        }
    }

    @Override
    public void register(ServiceMeta serviceMeta) throws Exception {
        ServiceInstance<ServiceMeta> serviceInstance = ServiceInstance
                .<ServiceMeta>builder()
                .name(RpcServiceHelper.buildServiceKey(serviceMeta.getServiceName(), serviceMeta.getServiceVersion(), serviceMeta.getServiceGroup()))
                .address(serviceMeta.getServiceAddr())
                .port(serviceMeta.getServicePort())
                .payload(serviceMeta)
                .build();
        serviceDiscovery.registerService(serviceInstance);
    }

    @Override
    public void unRegister(ServiceMeta serviceMeta) throws Exception {
        ServiceInstance<ServiceMeta> serviceInstance = ServiceInstance
                .<ServiceMeta>builder()
                .name(serviceMeta.getServiceName())
                .address(serviceMeta.getServiceAddr())
                .port(serviceMeta.getServicePort())
                .payload(serviceMeta)
                .build();
        serviceDiscovery.unregisterService(serviceInstance);
    }

    @Override
    public ServiceMeta discovery(String serviceName, int invokerHashCode, String sourceIp) throws Exception {
        Collection<ServiceInstance<ServiceMeta>> serviceInstances = serviceDiscovery.queryForInstances(serviceName);
        if (serviceLoadBalancer != null){
            return getServiceMetaInstance(invokerHashCode, sourceIp, (List<ServiceInstance<ServiceMeta>>) serviceInstances);
        }
        return this.serviceEnhancedLoadBalancer.select(ServiceLoadBalancerHelper.getServiceMetaList((List<ServiceInstance<ServiceMeta>>) serviceInstances), invokerHashCode, sourceIp);
    }

    private ServiceMeta getServiceMetaInstance(int invokerHashCode, String sourceIp, List<ServiceInstance<ServiceMeta>> serviceInstances) {
        ServiceInstance<ServiceMeta> instance = this.serviceLoadBalancer.select(serviceInstances, invokerHashCode, sourceIp);
        if (instance != null) {
            return instance.getPayload();
        }
        return null;
    }

    @Override
    public void destroy() throws IOException {
        serviceDiscovery.close();
    }
}
```

## 三、问题解决

`问题该如何解决呢？`

最核心的解决方案就是将ZKConsistentHashLoadBalancer类的泛型抽象化，不以具体的类型标注泛型类型，可以在调调用SPI接口时，做到通用化。修改后的源码如下所示。

**（1）ZKConsistentHashLoadBalancer类**

ZKConsistentHashLoadBalancer类表示基于Zookeeper一致性Hash的负载均衡实现类，源码详见：bhrpc-loadbalancer-consistenthash-zk工程下的io.binghe.rpc.loadbalancer.consistenthash.ZKConsistentHashLoadBalancer，修改后的源码如下所示。

```java
@SPIClass
public class ZKConsistentHashLoadBalancer<T> implements ServiceLoadBalancer<T> {
    private final static int VIRTUAL_NODE_SIZE = 10;
    private final static String VIRTUAL_NODE_SPLIT = "#";
    private final Logger logger = LoggerFactory.getLogger(ZKConsistentHashLoadBalancer.class);
    @Override
    public T select(List<T> servers, int hashCode, String ip) {
        logger.info("基于Zookeeper的一致性Hash算法的负载均衡策略...");
        TreeMap<Integer, T> ring = makeConsistentHashRing(servers);
        return allocateNode(ring, hashCode);
    }

    private T allocateNode(TreeMap<Integer, T> ring, int hashCode) {
        Map.Entry<Integer, T> entry = ring.ceilingEntry(hashCode);
        if (entry == null) {
            entry = ring.firstEntry();
        }
        if (entry == null){
            throw new RuntimeException("not discover useful service, please register service in registry center.");
        }
        return entry.getValue();
    }
    private TreeMap<Integer, T> makeConsistentHashRing(List<T> servers) {
        TreeMap<Integer, T> ring = new TreeMap<>();
        for (T instance : servers) {
            for (int i = 0; i < VIRTUAL_NODE_SIZE; i++) {
                ring.put((buildServiceInstanceKey(instance) + VIRTUAL_NODE_SPLIT + i).hashCode(), instance);
            }
        }
        return ring;
    }
    private String buildServiceInstanceKey(T instance) {
        return Objects.toString(instance);
    }
}
```

**（2）ZookeeperRegistryService类**

ZookeeperRegistryService类表示基于Zookeeper的注册中心实现类，源码详见：bhrpc-registry-zookeeper工程下的io.binghe.rpc.registry.zookeeper.ZookeeperRegistryService，修改后的源码如下所示。

```java
@SPIClass
public class ZookeeperRegistryService implements RegistryService {
    public static final int BASE_SLEEP_TIME_MS = 1000;
    public static final int MAX_RETRIES = 3;
    public static final String ZK_BASE_PATH = "/binghe_rpc";
    private ServiceDiscovery<ServiceMeta> serviceDiscovery;
    //负载均衡接口
    private ServiceLoadBalancer<ServiceMeta> serviceLoadBalancer;
    @Override
    public void init(RegistryConfig registryConfig) throws Exception {
        CuratorFramework client = CuratorFrameworkFactory.newClient(registryConfig.getRegistryAddr(), new ExponentialBackoffRetry(BASE_SLEEP_TIME_MS, MAX_RETRIES));
        client.start();
        JsonInstanceSerializer<ServiceMeta> serializer = new JsonInstanceSerializer<>(ServiceMeta.class);
        this.serviceDiscovery = ServiceDiscoveryBuilder.builder(ServiceMeta.class)
                .client(client)
                .serializer(serializer)
                .basePath(ZK_BASE_PATH)
                .build();
        this.serviceDiscovery.start();
        this.serviceLoadBalancer = ExtensionLoader.getExtension(ServiceLoadBalancer.class, registryConfig.getRegistryLoadBalanceType());
    }
    @Override
    public void register(ServiceMeta serviceMeta) throws Exception {
        ServiceInstance<ServiceMeta> serviceInstance = ServiceInstance
                .<ServiceMeta>builder()
                .name(RpcServiceHelper.buildServiceKey(serviceMeta.getServiceName(), serviceMeta.getServiceVersion(), serviceMeta.getServiceGroup()))
                .address(serviceMeta.getServiceAddr())
                .port(serviceMeta.getServicePort())
                .payload(serviceMeta)
                .build();
        serviceDiscovery.registerService(serviceInstance);
    }
    @Override
    public void unRegister(ServiceMeta serviceMeta) throws Exception {
        ServiceInstance<ServiceMeta> serviceInstance = ServiceInstance
                .<ServiceMeta>builder()
                .name(serviceMeta.getServiceName())
                .address(serviceMeta.getServiceAddr())
                .port(serviceMeta.getServicePort())
                .payload(serviceMeta)
                .build();
        serviceDiscovery.unregisterService(serviceInstance);
    }
    @Override
    public ServiceMeta discovery(String serviceName, int invokerHashCode, String sourceIp) throws Exception {
        Collection<ServiceInstance<ServiceMeta>> serviceInstances = serviceDiscovery.queryForInstances(serviceName);
        return this.serviceLoadBalancer.select(ServiceLoadBalancerHelper.getServiceMetaList((List<ServiceInstance<ServiceMeta>>) serviceInstances), invokerHashCode, sourceIp);
    }
    @Override
    public ServiceMeta select(List<ServiceMeta> serviceMetaList, int invokerHashCode, String sourceIp) {
        return this.serviceLoadBalancer.select(serviceMetaList, invokerHashCode, sourceIp);
    }
    @Override
    public List<ServiceMeta> discoveryAll() throws Exception {
        List<ServiceMeta> serviceMetaList = new ArrayList<>();
        Collection<String> names = serviceDiscovery.queryForNames();
        if (names == null || names.isEmpty()) return serviceMetaList;
        for (String name : names){
            Collection<ServiceInstance<ServiceMeta>> serviceInstances = serviceDiscovery.queryForInstances(name);
            List<ServiceMeta> list = this.getServiceMetaFromServiceInstance((List<ServiceInstance<ServiceMeta>>) serviceInstances);
            serviceMetaList.addAll(list);
        }
        return serviceMetaList;
    }
    private List<ServiceMeta> getServiceMetaFromServiceInstance(List<ServiceInstance<ServiceMeta>> serviceInstances){
        List<ServiceMeta> list = new ArrayList<>();
        if (serviceInstances == null || serviceInstances.isEmpty()) return list;
        IntStream.range(0, serviceInstances.size()).forEach((i)->{
            ServiceInstance<ServiceMeta> serviceInstance = serviceInstances.get(i);
            list.add(serviceInstance.getPayload());
        });
        return list;
    }
    @Override
    public void destroy() throws IOException {
        serviceDiscovery.close();
    }
}
```

至此，Zookeeper一致性Hash负载均衡泛型类型不匹配的问题修复。

## 四、问题总结

`修改完问题不总结下怎么行？`

我们自己手写的RPC框架不是一蹴而就的，它是一个不断优化和不断调整的过程，冰河也会将这些调整的过程整理好分享给各位星球的小伙伴。

总之，我们写的RPC框架正在一步步实现它该有的功能。

最后，我想说的是：学习《RPC手撸专栏》一定要塌下心来，一步一个脚印，动手实践，认真思考，遇到不懂的问题，可以直接到星球发布主题进行提问。一定要记住：纸上得来终觉浅，绝知此事要躬行的道理。否则，一味的CP，或者光看不练，不仅失去了学习的意义，到头来更是一无所获。

**好了，本章就到这里吧，我是冰河，我们下一章见~~**

## 五、关于星球

大家可以加入 **冰河技术** 知识星球，和星球小伙伴们一起学习《SpringCloud Alibaba实战》专栏和《RPC手撸专栏》，冰河技术知识星球的《RPC手撸专栏》是个连载大几十篇的专栏（目前已更新几十大篇章，110+篇文章，110+工程源码，120+源码Tag分支，真正的企业级、分布式、高并发、高性能、高可用，可扩展的RPC框架，仍在持续更新）。

另外，星球中《企业级大规模分布式调度系统》和《企业级大规模分布式IM系统》也已经提升日程，期待你的加入，与星球小伙伴一起开发企业级中间件项目，一起提升硬核技术！

### 星球提供的服务

冰河整理了星球提供的一些服务，如下所示。

加入星球，你将获得：

1.学习从零开始手撸可用于实际场景的高性能RPC框架项目

2.学习SpringCloud Alibaba实战项目—从零开发微服务项目

3.学习高并发、大流量业务场景的解决方案，体验大厂真正的高并发、大流量的业务场景

4.学习进大厂必备技能：性能调优、并发编程、分布式、微服务、框架源码、中间件开发、项目实战

5.提供站点 https://binghe.gitcode.host 所有学习内容的指导、帮助

6.GitHub：https://github.com/binghe001/BingheGuide - 非常有价值的技术资料仓库，包括冰河所有的博客开放案例代码

7.提供技术问题、系统架构、学习成长、晋升答辩等各项内容的回答

8.定期的整理和分享出各类专属星球的技术小册、电子书、编程视频、PDF文件

9.定期组织技术直播分享，传道、授业、解惑，指导阶段瓶颈突破技巧

### 如何加入星球

加入星球：扫描优惠券二维码即可加入星球。

![sa-2022-04-21-007](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-28-008.png)


* **扫码** ：通过扫描优惠券二维码加入星球。
* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

**好了，今天就到这儿吧，我是冰河，我们下期见~~**

## 写在最后

如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


## 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`学习加群`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>



## 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>


## 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>