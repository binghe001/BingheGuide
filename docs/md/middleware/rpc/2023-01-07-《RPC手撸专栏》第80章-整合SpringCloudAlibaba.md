---
layout: post
category: binghe-code-rpc
title: 第80章：整合SpringCloud Alibaba实际项目
tagline: by 冰河
tag: [rpc,mykit-rpc,binghe-code-rpc]
excerpt: 第80章：整合SpringCloud Alibaba实际项目
lock: need
---

# 《RPC手撸专栏》第80章：整合SpringCloud Alibaba实际项目

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客1：[https://binghe001.github.io](https://binghe001.github.io)
<br/>博客2：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

目前，我们自己手写的RPC框架已经完成了整体设计、服务提供者的实现、服务消费者的实现、注册中心的实现、负载均衡的实现、SPI扩展序列化机制、SPI扩展动态代理机制、SPI扩展反射机制、SPI扩展负载均衡策略、SPI扩展增强型负载均衡策略、SPI扩展实现注册中心、心跳机制、增强型心跳机制、重试机制、整合Spring、整合SpringBoot和整合Docker等篇章，共计80+篇文章。

## 一、前言

`我们自己手写的RPC框架可以整合SpringCloud Alibaba吗？`

我们自己手写的RPC框架从一开始的定位就是可在真实场景使用的、高性能、可扩展的RPC框架，采用微内核，插件化的架构设计，其最核心的内核都是采用SPI机制进行扩展。

所以，我们自己手写的RPC框架是要能够支持在真实场景下使用的，本章，我们就一起将手写的bhrpc框架整合到《[SpringCloud Alibaba](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247502755&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏的实际项目中。

**注意：《[SpringCloud Alibaba](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247502755&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏对应的项目源码需要加入冰河技术知识星球获取，目前，星球发放了优惠券，名额不多，大家可以到《[2023，新的一年，新的规划！（文末有福利）](https://mp.weixin.qq.com/s/wGwpkZ4Rk4spfP5K8tseTQ)》一文中获取优惠券。本章，是在《[SpringCloud Alibaba](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247502755&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏对应的项目源码基础上进行改造，将项目中原本使用的Fegin框架替换成我们自己手写的bhrpc框架。建议小伙伴们加入星球获取源码，根据文章进行实操。**

**另外，《[SpringCloud Alibaba](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247502755&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏源码整合bhrpc框架后的完整代码，也需要加入冰河技术知识星球获取。**

## 二、目标

`目标很明确：将我们自己手写的bhrpc框架整合到SpringCloud Alibaba项目中!`

发布到**冰河技术**知识星球的《RPC手撸专栏》文章已连载80+篇，从零开始手写了一个可在真实场景使用的、高性能、可扩展的RPC框架，采用微内核，插件化的架构设计，并且，其最核心的内核都是采用SPI机制进行扩展。

既然这个RPC框架的定位是可以在真实的场景使用，那最基本的要求就是要能够整合到真实的项目中使用。为了更好的将我们自己手写的RPC框架整合到微服务项目中，本章，我们将手写的bhrpc框架整合到《[SpringCloud Alibaba](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247502755&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏的实际项目中。

## 三、设计

`手写的RPC框架整合SpringCloud Alibaba项目后，如何设计项目的交互流程？`

在《[SpringCloud Alibaba](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247502755&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏中，选择了大家都比较熟悉的电商项目中的用户、商品和订单模块为例。一方面是这些模块的业务逻辑比较简单，另一方面，案例最终会以微服务的形式呈现给大家，专栏原有的代码是使用Fegin作为远程调用的框架，我们要做的就是将Fegin替换成我们自己手写的bhrpc框架，替换后的项目交互流程如图80-1所示。

![图80-1](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2023-01-07-001.png)

由图80-1可以看出，用户微服务、商品微服务和订单微服务的交互流程比较简单，服务与服务之间的交互都会采用我们自己手写的bhrpc框架进行实现。另外，从服务与服务之间的交互流程也可以看出，用户微服务和商品微服务作为服务提供者对外提供服务，订单微服务作为服务消费者来消费用户微服务和商品微服务对外提供的服务。

## 四、实现

`如果让你基于SA实战专栏的源码整合bhrpc框架，你会如何实现呢？`

本节，我们就基于《[SpringCloud Alibaba](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247502755&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏的源码整合自己手写的bhrpc框架，替换掉原有项目中使用的Fegin框架。

### 1.新增shop-service-api工程

**（1）新增shop-service-api工程**

在父工程shop-springcloud-alibaba下新建shop-service-api子工程，并在shop-service-api子工程的pom.xml文件中添加如下配置。

```xml
<dependencies>
    <dependency>
        <groupId>io.binghe.shop</groupId>
        <artifactId>shop-bean</artifactId>
        <version>${project.version}</version>
    </dependency>
</dependencies>
```

shop-service-api子工程的作用就是将shop-user工程中的UserService接口和shop-product工程中的ProductService接口单独分离出来，便于后续整合bhrpc框架。

**（2）新增UserService接口**

UserService接口的源码详见：shop-service-api工程下的io.binghe.shop.service.UserService，如下所示。

```java
public interface UserService {
    /**
     * 根据id获取用户信息
     */
    User getUserById(Long userId);
}
```

删除shop-user工程下的io.binghe.shop.user.service.UserService接口，并修改shop-user工程中的报错信息，将报错类中原本依赖io.binghe.shop.user.service.UserService接口修改成依赖io.binghe.shop.service.UserService接口。

**（3）新增ProductService接口**

ProductService接口的源码详见：shop-service-api工程下的io.binghe.shop.service.ProductService，如下所示。

```java
public interface ProductService {
    /**
     * 根据商品id获取商品信息
     */
    Product getProductById(Long pid);
    /**
     * 扣减商品库存
     */
    int updateProductStockById(Integer count, Long id);
}
```

删除shop-product工程下的io.binghe.shop.product.service.ProductService接口，并修改shop-product工程中的报错信息，将报错类中原本依赖io.binghe.shop.product.service.ProductService接口修改成依赖io.binghe.shop.service.ProductService接口。

### 2.改造shop-user工程

shop-user工程对应bhrpc框架的服务提供者角色。

**（1）添加pom.xml依赖**

shop-user工程作为bhrpc框架的服务提供者，在pom.xml需要添加如下依赖。

```xml
<dependency>
    <groupId>io.binghe.rpc</groupId>
    <artifactId>bhrpc-spring-boot-starter-provider</artifactId>
    <version>${bhrpc.version}</version>
</dependency>

<dependency>
    <groupId>io.binghe.shop</groupId>
    <artifactId>shop-service-api</artifactId>
    <version>${project.version}</version>
</dependency>
</dependencies>
```

**（2）修改UserServiceImpl类**

UserServiceImpl类的源码详见：shop-user工程下的io.binghe.shop.user.service.impl.UserServiceImpl，需要将UserServiceImpl类上标注的Spring中的@Service注解，替换成bhrpc框架中的@RpcService注解，修改后的源码如下所示。

```java
@RpcService(interfaceClass = UserService.class, version = "1.0.0", group = "binghe")
public class UserServiceImpl implements UserService {
    @Autowired
    private UserMapper userMapper;

    @Override
    public User getUserById(Long userId) {
        return userMapper.selectById(userId);
    }
}
```

可以看到，在UserServiceImpl类上标注了bhrpc框架中的@RpcService注解，并且指定了interfaceClass、version和group属性。

**（3）修改UserStarter类**

UserStarter类的源码详见：shop-user工程下的io.binghe.shop.UserStarter，主要是在UserStarter类上添加@ComponentScan注解，修改后的源码如下所示。

```java
@SpringBootApplication
@ComponentScan(basePackages = {"io.binghe.shop", "io.binghe.rpc"})
@EnableTransactionManagement(proxyTargetClass = true)
@MapperScan(value = { "io.binghe.shop.user.mapper" })
@EnableDiscoveryClient
@EnableAsync
public class UserStarter {
    public static void main(String[] args){
        SpringApplication.run(UserStarter.class, args);
    }
}
```

可以看到，在UserStarter类上标注了@ComponentScan注解，并指定了扫描的包路径为io.binghe.shop和io.binghe.rpc，使其既能够扫描到微服务项目中包下的类，也能够扫描到bhrpc框架包下的类。

**（4）添加配置**

由于项目使用了Nacos作为配置中心，所以，需要在Nacos添加shop-user工程作为服务提供者的配置，登录Nacos管理端，找到shop-user工程的配置，如下所示。

![rpc-2023-01-07-002](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2023-01-07-002.png)

点击编辑按钮，在原有配置的基础上，添加如下配置信息。

```yaml
bhrpc:
  binghe:
    provider:
      # rpc server
      serverAddress: 127.0.0.1:20880
      # serverRegistryAddress
      serverRegistryAddress: 127.0.0.1:20880
      # zookeeper server
      registryAddress: 127.0.0.1:2181
      # registry center type
      registryType: zookeeper
      #registry loadbalance type
      registryLoadBalanceType: zkconsistenthash
      # reflect type
      reflectType: cglib
      # heartbeatInterval
      heartbeatInterval: 30000
```

可以看到，配置的内容都是bhrpc框架的服务提供者启动时，需要读取的一些参数信息。配置完成后，点击发布按钮进行发布。

至此，shop-user工程改造完成，是不是非常简单呢？我们自己手写的bhrpc框架整合SpringCloud Alibaba项目就是这么简单。

### 3.改造shop-product工程

shop-product工程对应bhrpc框架的服务提供者角色。改造shop-product工程的步骤与改造shop-user工程的步骤基本相同。

**（1）添加pom.xml依赖**

shop-product工程同样作为bhrpc框架的服务提供者，在pom.xml需要添加如下依赖。

```xml
<dependency>
    <groupId>io.binghe.rpc</groupId>
    <artifactId>bhrpc-spring-boot-starter-provider</artifactId>
    <version>${bhrpc.version}</version>
</dependency>

<dependency>
    <groupId>io.binghe.shop</groupId>
    <artifactId>shop-service-api</artifactId>
    <version>${project.version}</version>
</dependency>
```

**（2）修改ProductServiceImpl类**

ProductServiceImpl类的源码详见：shop-product工程下的io.binghe.shop.product.service.impl.ProductServiceImpl，需要将ProductServiceImpl类上标注的Spring中的@Service注解，替换成bhrpc框架中的@RpcService注解，修改后的源码如下所示。

```java
@RpcService(interfaceClass = ProductService.class, version = "1.0.0", group = "binghe")
public class ProductServiceImpl implements ProductService {
    @Autowired
    private ProductMapper productMapper;
    @Override
    public Product getProductById(Long pid) {
        return productMapper.selectById(pid);
    }

    @Override
    public int updateProductStockById(Integer count, Long id) {
        return productMapper.updateProductStockById(count, id);
    }
}
```

可以看到，在ProductServiceImpl类上标注了bhrpc框架中的@RpcService注解，并且指定了interfaceClass、version和group属性。

**（3）修改ProductStarter类**

ProductStarter类的源码详见：shop-product工程下的io.binghe.shop.ProductStarter，主要是在ProductStarter类上添加@ComponentScan注解，修改后的源码如下所示。

```java
@SpringBootApplication
@ComponentScan(basePackages = {"io.binghe.shop", "io.binghe.rpc"})
@MapperScan(value = { "io.binghe.shop.product.mapper" })
@EnableTransactionManagement(proxyTargetClass = true)
@EnableDiscoveryClient
public class ProductStarter {
    public static void main(String[] args){
        SpringApplication.run(ProductStarter.class, args);
    }
}
```

可以看到，在ProductStarter类上标注了@ComponentScan注解，并指定了扫描的包路径为io.binghe.shop和io.binghe.rpc，使其既能够扫描到微服务项目中包下的类，也能够扫描到bhrpc框架包下的类。

**（4）添加配置**

由于项目使用了Nacos作为配置中心，所以，需要在Nacos添加shop-product工程作为服务提供者的配置，登录Nacos管理端，找到shop-product工程的配置，如下所示。

![rpc-2023-01-07-003](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2023-01-07-003.png)

点击编辑按钮，在原有配置的基础上，添加如下配置信息。

```yaml
bhrpc:
  binghe:
    provider:
      # rpc server
      serverAddress: 127.0.0.1:20881
      # serverRegistryAddress
      serverRegistryAddress: 127.0.0.1:20881
      # zookeeper server
      registryAddress: 127.0.0.1:2181
      # registry center type
      registryType: zookeeper
      #registry loadbalance type
      registryLoadBalanceType: zkconsistenthash
      # reflect type
      reflectType: cglib
      # heartbeatInterval
      heartbeatInterval: 30000
```

可以看到，配置的内容也都是bhrpc框架的服务提供者启动时，需要读取的一些参数信息。配置完成后，点击发布按钮进行发布。

至此，shop-product工程改造完成，也是非常简单的。

### 4.改造shop-order工程

shop-order工程对应bhrpc框架的服务消费者角色。

**（1）添加pom.xml依赖**

shop-order工程作为bhrpc框架的服务消费者，在pom.xml需要添加如下依赖。

```xml
<dependency>
    <groupId>io.binghe.rpc</groupId>
    <artifactId>bhrpc-spring-boot-starter-consumer</artifactId>
    <version>${bhrpc.version}</version>
</dependency>

<dependency>
    <groupId>io.binghe.shop</groupId>
    <artifactId>shop-service-api</artifactId>
    <version>${project.version}</version>
</dependency>
```

**（2）新增OrderServiceV9Impl类**

为了不影响整体项目原有的逻辑，复制OrderServiceV8Impl类的代码，新增成为OrderServiceV9Impl类，OrderServiceV9Impl类的源码详见：shop-order工程下的io.binghe.shop.order.service.impl.OrderServiceV9Impl，类框架代码如下所示。

```java
@Slf4j
@Service("orderServiceV9")
public class OrderServiceV9Impl implements OrderService {
}
```

**（3）改造OrderServiceV9Impl类**

将OrderServiceV9Impl类中，原本userService和productService成员变量上标注的Spring中的@Autowired注解替换成bhrpc框架中的@RpcReference注解，替换后的源码如下所示。

```java
@RpcReference(registryType = "zookeeper", registryAddress = "127.0.0.1:2181", loadBalanceType = "zkconsistenthash", version = "1.0.0", group = "binghe", serializationType = "protostuff", proxy = "cglib", timeout = 30000, async = false)
private UserService userService;

@RpcReference(registryType = "zookeeper", registryAddress = "127.0.0.1:2181", loadBalanceType = "zkconsistenthash", version = "1.0.0", group = "binghe", serializationType = "protostuff", proxy = "cglib", timeout = 30000, async = false)
private ProductService productService;
```

可以看到，userService和productService成员变量上标注了bhrpc框架中的@RpcReference注解，并且配置了服务消费者启动时需要的一些参数信息。

**注意：需要将OrderServiceV9Impl类中的UserService改成引用io.binghe.shop.service.UserService接口，将ProductService改成引用io.binghe.shop.service.ProductService接口，修改OrderServiceV9Impl类中的一些报错信息。**

**（4）修改OrderStarter类**

OrderStarter类的源码详见：shop-order工程下的io.binghe.shop.OrderStarter，主要是在OrderStarter类上添加@ComponentScan注解，修改后的源码如下所示。

```java
@SpringBootApplication
@ComponentScan(basePackages = {"io.binghe.shop", "io.binghe.rpc"})
@EnableTransactionManagement(proxyTargetClass = true)
@MapperScan(value = { "io.binghe.shop.order.mapper" })
@EnableDiscoveryClient
@EnableFeignClients
public class OrderStarter {
    public static void main(String[] args){
        SpringApplication.run(OrderStarter.class, args);
    }
}
```

可以看到，在OrderStarter类上标注了@ComponentScan注解，并指定了扫描的包路径为io.binghe.shop和io.binghe.rpc，使其既能够扫描到微服务项目中包下的类，也能够扫描到bhrpc框架包下的类。

**（5）添加配置**

由于项目使用了Nacos作为配置中心，所以，需要在Nacos添加shop-order工程作为服务消费者的配置，登录Nacos管理端，找到shop-order工程的配置，如下所示。

![rpc-2023-01-07-004](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2023-01-07-004.png)

点击编辑按钮，在原有配置的基础上，添加如下配置信息。

```yaml
bhrpc:
  binghe:
    consumer:
      # zookeeper server
      registryAddress: 127.0.0.1:2181
      # registry center type
      registryType: zookeeper
      # registry loadbalance type
      loadBalanceType: zkconsistenthash
      # proxy type
      proxy: cglib
      # version
      version: 1.0.0
      # group
      group: binghe
      # zkconsistenthash
      serializationType: protostuff
      # timeout
      timeout: 30000
      # async
      async: false
      # oneway
      oneway: false
      # heartbeatInterval
      heartbeatInterval: 15000
      # retryInterval
      retryInterval: 1000
      # retryTimes
      retryTimes: 3
```

可以看到，配置的内容都是bhrpc框架的服务消费者启动时，需要读取的一些参数信息。配置完成后，点击发布按钮进行发布。

**（6）修改OrderController类**

OrderController类的源码详见：shop-order工程下的io.binghe.shop.order.controller.OrderController，主要是将OrderController类中使用@Qualifier注解标识的orderServiceV8修改成orderServiceV9，如下所示。

```java
@Autowired
@Qualifier(value = "orderServiceV9")
private OrderService orderService;
```

至此，shop-order工程改造完成，也是非常简单的。

目前，在SpringCloud Alibaba项目中整合我们自己手写的RPC框架就完成了，是不是非常简单呢？没错，我们自己手写的bhrpc框架整合SpringCloud Alibaba项目就是这么简单！

## 五、测试

`整合完不测试下怎么行？`

### 1.启动服务

分别启动Nacos、RocketMQ、Sentinel、ZipKin、Seata和Zookeeper服务，对应服务的版本在源码的README.md文件中有说明。

### 2.启动工程

按顺序分别启动shop-user工程、shop-product工程、shop-order工程和shop-gateway工程。

* 启动shop-user工程

输出如下信息，没有报错，说明bhrpc框架监听的是20880端口，表示启动成功。

```bash
i.b.r.p.common.server.base.BaseServer    : Server started on port 20880
```

* shop-product工程

输出如下信息，没有报错，说明bhrpc框架监听的是20881端口，表示启动成功。

```bash
i.b.r.p.common.server.base.BaseServer    : Server started on port 20881
```

* shop-order工程

输出如下信息，没有报错，说明启动成功。

```bash
o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8081 (http) with context path '/order'
```

* shop-gateway工程

输出如下信息，没有报错，说明启动成功。

```bash
io.binghe.shop.GatewayStarter            : Started GatewayStarter in 9.604 seconds (JVM running for 10.964)
```

### 3.查询数据表数据

（1）打开cmd终端，进入MySQL命令行，并进入shop商城数据库，如下所示。

```sql
C:\Users\binghe>mysql -uroot -p
Enter password: ****
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 15
Server version: 5.7.35 MySQL Community Server (GPL)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use shop;
Database changed
```

（2）查看商品数据表，如下所示。

```sql
mysql> select * from t_product;
+------+------------+-------------+-------------+
| id   | t_pro_name | t_pro_price | t_pro_stock |
+------+------------+-------------+-------------+
| 1001 | 华为       |     2399.00 |         100 |
| 1002 | 小米       |     1999.00 |         100 |
| 1003 | iphone     |     4999.00 |         100 |
+------+------------+-------------+-------------+
3 rows in set (0.00 sec)
```

这里，我们以id为1001的商品为例，此时发现商品的库存为100。

（3）查询订单数据表，如下所示。

```sql
mysql> select * from t_order;
Empty set (0.00 sec)
```

可以发现订单数据表为空。

（4）查询订单条目数据表，如下所示。

```sql
mysql> select * from t_order_item;
Empty set (0.00 sec)
```

可以看到，订单条目数据表为空。

### 4.访问项目

打开浏览器访问`http://localhost:10002/server-order/order/submit_order?userId=1001&productId=1001&count=1`，如下所示。

![rpc-2023-01-07-005](https://binghe.gitcode.host/assets/images/middleware/rpc/rpc-2023-01-07-005.png)

可以看到，项目返回的结果为success，表示项目执行成功。

### 5.再次查看数据表数据

（1）查看商品数据表，如下所示。

```sql
mysql> select * from t_product;
+------+------------+-------------+-------------+
| id   | t_pro_name | t_pro_price | t_pro_stock |
+------+------------+-------------+-------------+
| 1001 | 华为       |     2399.00 |          99 |
| 1002 | 小米       |     1999.00 |         100 |
| 1003 | iphone     |     4999.00 |         100 |
+------+------------+-------------+-------------+
3 rows in set (0.00 sec)
```

这里，id为1001的商品库存为99，说明库存已经减少了1。

（2）查询订单数据表，如下所示。

```sql
mysql> select * from t_order;
+-------------------+-----------+-------------+-------------+-----------+---------------+
| id                | t_user_id | t_user_name | t_phone     | t_address | t_total_price |
+-------------------+-----------+-------------+-------------+-----------+---------------+
| 96829539832958976 |      1001 | binghe      | 13212345678 | 北京      |       2399.00 |
+-------------------+-----------+-------------+-------------+-----------+---------------+
1 row in set (0.00 sec)
```

可以看到，在t_order表中新增了一张订单数据表，订单的总金额为2399.00元。

（3）查询订单条目数据表，如下所示。

```sql
mysql> select * from t_order_item;
+-------------------+-------------------+----------+------------+-------------+----------+
| id                | t_order_id        | t_pro_id | t_pro_name | t_pro_price | t_number |
+-------------------+-------------------+----------+------------+-------------+----------+
| 96829541082861568 | 96829539832958976 |     1001 | 华为       |     2399.00 |        1 |
+-------------------+-------------------+----------+------------+-------------+----------+
1 row in set (0.00 sec)
```

可以看到，订单条目数据表中条了一条订单条目数据，商品的id为1001，商品名称为华为，商品的价格为2399.00，下单的商品数量为1。

根据测试结果可以看出，我们已经正确在SpringCloud Alibaba项目中整合了我们自己手写的bhrpc框架。

## 六、总结

`实现了功能不总结下怎么行？`

在完成整合Spring的篇章后，我们又开启了整合SpringBoot的篇章，首先，我们完成了服务提供者整合SpringBoot的功能，并基于SpringBoot接入了服务提供者。同时，实现了服务消费者整合SpringBoot的功能，并且基于SpringBoot接入了服务消费者。

在整合Docker章节，我们实现了基于Docker接入了服务提供者和基于Docker接入了服务消费者。

本章，我们更进一步将手写的bhrpc框架整合到SpringCloud Alibaba项目。

总之，我们写的RPC框架正在一步步实现它该有的功能。

最后，我想说的是：学习《RPC手撸专栏》一定要塌下心来，一步一个脚印，动手实践，认真思考，遇到不懂的问题，可以直接到星球发布主题进行提问。一定要记住：纸上得来终觉浅，绝知此事要躬行的道理。否则，一味的CP，或者光看不练，不仅失去了学习的意义，到头来更是一无所获。

**好了，本章就到这里吧，我是冰河，我们下一章见~~**

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