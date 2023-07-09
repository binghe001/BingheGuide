---
layout: post
category: binghe-code-springcloudalibaba
title: 第10章：项目整合Sentinel实现限流与容错
tagline: by 冰河
tag: [springcloud,springcloudalibaba,binghe-code-springcloudalibaba]
excerpt: SA实战 ·《SpringCloud Alibaba实战》第10章-服务容错：项目整合Sentinel实现限流与容错
lock: need
---

# SA实战 ·《SpringCloud Alibaba实战》第10章-服务容错：项目整合Sentinel实现限流与容错

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

**大家好，我是冰河~~**

> 一不小心《[SpringCloud Alibaba实战](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247500408&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏都更新到第10章了，再不上车就跟不上了，小伙伴们快跟上啊！
>
> 注意：本项目完整源码加入 **冰河技术** 知识星球即可获取，文末有优惠券。

在《[SpringCloud Alibaba实战](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247500408&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏前面的文章中，我们实现了用户微服务、商品微服务和订单微服务之间的远程调用，并且实现了服务调用的负载均衡。同时，我们详细介绍了服务雪崩和服务容错的一些方案。

## 文章总览

![sa-2022-05-03-018](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-018.png)

## 章节概述

今天，我们就使用Sentinel实现接口的限流，并使用Feign整合Sentinel实现服务容错的功能，让小伙伴们体验下微服务使用了服务容错功能的效果。因为我们整个专栏的内容仅仅围绕着SpringCloud Alibaba技术栈展开，所以，这里我们使用的服务容错组件是阿里开源的Sentinel。

当然，能够实现服务容错功能的组件不仅仅有Sentinel，比如：Hystrix和Resilience4J也能够实现服务容错的目的，关于Hystrix和Resilience4J不是本专栏的重点，冰河就不再赘述了，小伙伴们可以自行了解。

## 关于Sentinel

随着微服务的流行，服务和服务之间的稳定性变得越来越重要。Sentinel 以流量为切入点，从流量控制、熔断降级、系统负载保护等多个维度保护服务的稳定性。

### Sentinel的特征

- **丰富的应用场景**：Sentinel 承接了阿里巴巴近 10 年的双十一大促流量的核心场景，例如秒杀（即突发流量控制在系统容量可以承受的范围）、消息削峰填谷、集群流量控制、实时熔断下游不可用应用等。
- **完备的实时监控**：Sentinel 同时提供实时的监控功能。您可以在控制台中看到接入应用的单台机器秒级数据，甚至 500 台以下规模的集群的汇总运行情况。
- **广泛的开源生态**：Sentinel 提供开箱即用的与其它开源框架/库的整合模块，例如与 Spring  Cloud、Apache Dubbo、gRPC、Quarkus 的整合。您只需要引入相应的依赖并进行简单的配置即可快速地接入  Sentinel。同时 Sentinel 提供 Java/Go/C++ 等多语言的原生实现。
- **完善的 SPI 扩展机制**：Sentinel 提供简单易用、完善的 SPI 扩展接口。您可以通过实现扩展接口来快速地定制逻辑。例如定制规则管理、适配动态数据源等。

### Sentinel的主要特性

![sa-2022-05-03-001](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-001.png)

### Sentinel的开源生态

![sa-2022-05-03-002](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-002.png)



Sentinel 分为两个部分:

- 核心库（Java 客户端）不依赖任何框架/库，能够运行于所有 Java 运行时环境，同时对 Dubbo / Spring Cloud 等框架也有较好的支持。
- 控制台（Dashboard）基于 Spring Boot 开发，打包后可以直接运行，不需要额外的 Tomcat 等应用容器

注意：上述内容来自Sentinel官方文档，链接地址为：[https://github.com/alibaba/Sentinel/wiki/%E4%BB%8B%E7%BB%8D](https://github.com/alibaba/Sentinel/wiki/%E4%BB%8B%E7%BB%8D)

## 项目整合Sentinel

在微服务项目中整合Sentinel是非常简单的，只需要在项目的pom.xml文件中引入Sentinel的依赖即可，不过在使用Sentinel时，需要安装Sentinel的控制台。

### 安装Sentinel控制台

Sentinel 提供一个轻量级的控制台, 它提供机器发现、单机资源实时监控以及规则管理等功能。

（1）到链接 [https://github.com/alibaba/Sentinel/releases](https://github.com/alibaba/Sentinel/releases) 下载Sentinel控制台，如下所示，我这里下载的Sentinel控制台是1.8.4版本。

![sa-2022-05-03-003](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-003.png)

（2）Sentinel控制台下载完成后，在本地启动Sentinel控制台，如下所示。

```bash
java -Dserver.port=8888 -Dcsp.sentinel.dashboard.server=localhost:8888 -Dproject.name=sentinel-dashboard -jar sentinel-dashboard-1.8.4.jar
```

小伙伴们如果想在CentOS服务器上以后台进程方式启动Sentinel控制台，可以使用如下命令

```bash
nohup java -Dserver.port=8888 -Dcsp.sentinel.dashboard.server=localhost:8888 -Dproject.name=sentinel-dashboard -jar sentinel-dashboard-1.8.4.jar >> /dev/null &
```

启动后在浏览器中输入 `http://localhost:8888` 访问Sentinel控制台，如下所示。

![sa-2022-05-03-004](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-004.png)

输入默认的用户名sentinel和密码sentinel，登录Sentinel控制台，如下所示。

![sa-2022-05-03-005](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-005.png)

至此，Sentinel控制台下载并启动成功。

### 项目集成Sentinel

（1）在订单微服务的shop-order的pom.xml文件中添加Sentinel的相关依赖，如下所示。

```xml
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-sentinel</artifactId>
</dependency>
```

（2）在订单微服务的shop-order的application.yml文中加入Sentinel相关的配置，如下所示。

```yaml
spring:
  cloud:
    sentinel:
      transport:
        port: 9999   #指定和Sentinel控制台交互的端口，任意指定一个未使用的端口即可
        dashboard: 127.0.0.1:8888  #Sentinel控制台服务地址
```

（3）为了让大家直观的感受到Sentinel的功能，这里我们先在订单微服务的`io.binghe.shop.order.controller.OrderController`类中新增一个测试接口，如下所示。

```java
@GetMapping(value = "/test_sentinel")
public String testSentinel(){
    log.info("测试Sentinel");
    return "sentinel";
}
```

（4）启动订单微服务，在浏览器中输入`http://localhost:8080/order/test_sentinel`访问在订单微服务中新增的接口，如下所示。

![sa-2022-05-03-006](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-006.png)

（5）刷新Sentinel页面，会发现已经显示了订单微服务的菜单，如下所示。

![sa-2022-05-03-007](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-007.png)

**注意：直接启动订单微服务和Sentinel，会发现Sentinel中没有订单微服务的数据，因为Sentinel是懒加载机制，所以需要访问一下接口，再去访问Sentinel 就有数据了。**

至此，订单微服务成功集成了Sentinel。

### 集成Sentinel限流功能

这里，我们使用Sentinel为`http://localhost:8080/order/test_sentinel`接口限流，步骤如下所示。

（1）在Sentinel控制台找到server-order下的簇点链路菜单，如下所示。

![sa-2022-05-03-008](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-008.png)

（2）在簇点链路列表中找到`/test_sentinel`，在右侧的操作中选择流控，如下所示。

![sa-2022-05-03-009](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-009.png)点击流控按钮会显示 **新增流控规则** 的弹出框，如下所示。

![sa-2022-05-03-010](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-010.png)

这里，我们在单机阈值后直接填写1，如下所示。

![sa-2022-05-03-011](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-011.png)

配置好之后点击新增按钮。上述配置表示`http://localhost:8080/order/test_sentinel`接口的QPS为1，每秒访问1次。如果每秒访问的次数超过1次，则会被Sentinel限流。

（3）在浏览器上不断刷新`http://localhost:8080/order/test_sentinel`接口，当每秒中访问的次数超过1次时，会被Sentinel限流，如下所示。

![sa-2022-05-03-012](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-012.png)



### 对提交订单的接口限流

在提交订单的接口 `http://localhost:8080/order/submit_order`上实现限流，步骤如下。

（1）首先访问下提交订单的接口 `http://localhost:8080/order/submit_order`，使得Sentinel中能够捕获到提交订单的接口，并点击操作中的流控按钮，如下所示。

![sa-2022-05-03-013](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-013.png)

**这里的注意点还是：直接启动订单微服务和Sentinel，会发现Sentinel中没有订单微服务的数据，因为Sentinel是懒加载机制，所以需要访问一下接口，再去访问Sentinel 就有数据了。**

（2）在新增流控规则显示框中的QPS单机阈值设置为1，点击新增按钮，如下所示。

![sa-2022-05-03-014](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-014.png)

（3）在浏览器中不断刷新 `http://localhost:8080/order/submit_order?userId=1001&productId=1001&count=1` 使得每秒访问的频率超过1次，会被Sentinel限流，如下所示。

![sa-2022-05-03-015](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-015.png)

至此，项目中集成了Sentinel并使用Sentinel实现了接口的限流。

## Feign整合Sentinel实现容错

我们之前在项目中集成了Sentinel，并使用Sentinel实现了限流，如果订单微服务的下游服务，比如用户微服务和商品微服务出现故障，无法访问时，那订单微服务该如何实现服务容错呢？使用Sentinel就可以轻松实现。

### 添加依赖并开启支持

（1）在订单微服务的shop-order的pom.xml文件中添加Sentinel的相关依赖，如下所示。

```xml
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-sentinel</artifactId>
</dependency>
```

注意：这一步是为了整个案例的完整性加上的，如果小伙伴们按照文章实现了项目整合Sentinel，并在订单微服务的shop-order的pom.xml文件中添加了上述配置，则可忽略此步骤。

（2）在订单微服务的application.yml文件中添加如下配置开启Feign对Sentinel的支持。

```yaml
feign:
  sentinel:
    enabled: true
```

### 为远程调用实现容错

（1）需要在订单微服务shop-order中，为远程调用接口实现容错方法。这里，先为用户微服务实现容错。在订单微服务中新建`io.binghe.shop.order.Feign.fallback` 包，并在 `io.binghe.shop.order.Feign.fallback`包下创建UserServiceFallBack类实现UserService接口，用于调用用户微服务的容错类，如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 用户服务容错类
 */
@Component
public class UserServiceFallBack implements UserService {
    @Override
    public User getUser(Long uid) {
        User user = new User();
        user.setId(-1L);
        return user;
    }
}
```

**注意：容错类需要实现一个被容错的接口，并实现这个接口的方法。**

接下来，在订单微服务的`io.binghe.shop.order.Feign.UserService`接口上的@FeignClient注解上指定容错类，如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 调用用户微服务的接口
 */
@FeignClient(value = "server-user", fallback = UserServiceFallBack.class)
public interface UserService {

    @GetMapping(value = "/user/get/{uid}")
    User getUser(@PathVariable("uid") Long uid);
}
```

（2）在订单微服务中的 `io.binghe.shop.order.Feign.fallback`包下创建ProductServiceFallBack类实现ProductService接口，用于调用商品微服务的容错类，如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 商品微服务的容错类
 */
@Component
public class ProductServiceFallBack implements ProductService {
    @Override
    public Product getProduct(Long pid) {
        Product product = new Product();
        product.setId(-1L);
        return product;
    }

    @Override
    public Result<Integer> updateCount(Long pid, Integer count) {
        Result<Integer> result = new Result<>();
        result.setCode(1001);
        result.setCodeMsg("触发了容错逻辑");
        return result;
    }
}
```

接下来，在订单微服务的`io.binghe.shop.order.fegin.ProductService`接口的@FeignClient注解上指定容错类，如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 调用商品微服务的接口
 */
@FeignClient(value = "server-product", fallback = ProductServiceFallBack.class)
public interface ProductService {

    /**
     * 获取商品信息
     */
    @GetMapping(value = "/product/get/{pid}")
    Product getProduct(@PathVariable("pid") Long pid);

    /**
     * 更新库存数量
     */
    @GetMapping(value = "/product/update_count/{pid}/{count}")
    Result<Integer> updateCount(@PathVariable("pid") Long pid, @PathVariable("count") Integer count);
}
```

（3）修改订单微服务的业务实现类中提交订单的业务方法，这里修改的方法位于`io.binghe.shop.order.service.impl.OrderServiceV6Impl`类中，同时需要将类上的@Service注解中指定bean的名称为orderServiceV6。

```java
@Slf4j
@Service("orderServiceV6")
public class OrderServiceV6Impl implements OrderService {
    //省略所有代码
}
```

在提交订单的业务方法中，修改前的代码片段如下所示。

```java
User user = userService.getUser(orderParams.getUserId());
if (user == null){
    throw new RuntimeException("未获取到用户信息: " + JSONObject.toJSONString(orderParams));
}
Product product = productService.getProduct(orderParams.getProductId());
if (product == null){
    throw new RuntimeException("未获取到商品信息: " + JSONObject.toJSONString(orderParams));
}
//#####################省略N行代码##########################
Result<Integer> result = productService.updateCount(orderParams.getProductId(), orderParams.getCount());
if (result.getCode() != HttpCode.SUCCESS){
    throw new RuntimeException("库存扣减失败");
}
```

修改后的代码片段如下所示。

```java
User user = userService.getUser(orderParams.getUserId());
if (user == null){
    throw new RuntimeException("未获取到用户信息: " + JSONObject.toJSONString(orderParams));
}
if (user.getId() == -1){
    throw new RuntimeException("触发了用户微服务的容错逻辑: " + JSONObject.toJSONString(orderParams));
}
Product product = productService.getProduct(orderParams.getProductId());
if (product == null){
    throw new RuntimeException("未获取到商品信息: " + JSONObject.toJSONString(orderParams));
}
if (product.getId() == -1){
    throw new RuntimeException("触发了商品微服务的容错逻辑: " + JSONObject.toJSONString(orderParams));
}
//#####################省略N行代码##########################
Result<Integer> result = productService.updateCount(orderParams.getProductId(), orderParams.getCount());
if (result.getCode() == 1001){
    throw new RuntimeException("触发了商品微服务的容错逻辑: " + JSONObject.toJSONString(orderParams));
}
if (result.getCode() != HttpCode.SUCCESS){
    throw new RuntimeException("库存扣减失败");
}
```

可以看到，修改后的提交订单的业务方法主要增加了服务容错的判断逻辑。

（4）在`io.binghe.shop.order.controller.OrderController`中注入bean名称为orderServiceV6的OrderService对象，如下所示。

```java
@Autowired
@Qualifier(value = "orderServiceV6")
private OrderService orderService;
```

至此，我们在项目中使用Sentinel实现了服务容错的功能。

### 测试服务容错

（1）停掉所有的商品微服务（也就是只启动用户微服务和订单微服务），在浏览器中访问`http://localhost:8080/order/submit_order?userId=1001&productId=1001&count=1`，结果如下所示。

![sa-2022-05-03-016](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-016.png)

返回的原始数据如下所示。

```bash
{"code":500,"codeMsg":"执行失败","data":"触发了商品微服务的容错逻辑: {\"count\":1,\"empty\":false,\"productId\":1001,\"userId\":1001}"}
```

说明停掉所有的商品微服务后，触发了商品微服务的容错逻辑。

（2）停掉所有的用户微服务（也就是只启动商品微服务和订单微服务）在浏览器中访问`http://localhost:8080/order/submit_order?userId=1001&productId=1001&count=1`，结果如下所示。

![sa-2022-05-03-017](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-017.png)

返回的原始数据如下所示。

```bash
{"code":500,"codeMsg":"执行失败","data":"触发了用户微服务的容错逻辑: {\"count\":1,\"empty\":false,\"productId\":1001,\"userId\":1001}"}
```

（3）停掉所有的用户微服务和商品微服务（也就是只启动订单微服务），在浏览器中访问`http://localhost:8080/order/submit_order?userId=1001&productId=1001&count=1`，结果如下所示。

![sa-2022-05-03-017](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-03-017.png)

返回的原始数据如下所示。

```bash
{"code":500,"codeMsg":"执行失败","data":"触发了用户微服务的容错逻辑: {\"count\":1,\"empty\":false,\"productId\":1001,\"userId\":1001}"}
```

说明项目集成Sentinel成功实现了服务的容错功能。

## 容错扩展

如果想要在订单微服务中获取到容错时的具体信息时，可以按照如下方式实现容错方案。

### 实现容错时获取异常

（1）在订单微服务shop-order中新建`io.binghe.shop.order.fegin.fallback.factory`包，在`io.binghe.shop.order.fegin.fallback.factory`包中新建UserServiceFallBackFactory类，并实现FallbackFactory接口，FallbackFactory接口的泛型指定为UserService，源码如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 用户微服务容错Factory
 */
@Component
public class UserServiceFallBackFactory implements FallbackFactory<UserService> {
    @Override
    public UserService create(Throwable cause) {
        return new UserService() {
            @Override
            public User getUser(Long uid) {
                User user = new User();
                user.setId(-1L);
                return user;
            }
        };
    }
}
```

（2）在订单微服务的 `io.binghe.shop.order.fegin.UserService` 接口上的@FeignClient注解上指定fallbackFactory属性，如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 调用用户微服务的接口
 */
//@FeignClient(value = "server-user", fallback = UserServiceFallBack.class)
@FeignClient(value = "server-user", fallbackFactory = UserServiceFallBackFactory.class)
public interface UserService {
    @GetMapping(value = "/user/get/{uid}")
    User getUser(@PathVariable("uid") Long uid);
}
```

（3）在`io.binghe.shop.order.fegin.fallback.factory`包中新建ProductServiceFallBackFactory类，并实现FallbackFactory接口，FallbackFactory接口的泛型指定为ProductService，源码如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 商品微服务容错Factory
 */
@Component
public class ProductServiceFallBackFactory implements FallbackFactory<ProductService> {
    @Override
    public ProductService create(Throwable cause) {
        return new ProductService() {
            @Override
            public Product getProduct(Long pid) {
                Product product = new Product();
                product.setId(-1L);
                return product;
            }

            @Override
            public Result<Integer> updateCount(Long pid, Integer count) {
                Result<Integer> result = new Result<>();
                result.setCode(1001);
                result.setCodeMsg("触发了容错逻辑");
                return result;
            }
        };
    }
}
```

（4）在订单微服务的 `io.binghe.shop.order.fegin.ProductService` 接口上的@FeignClient注解上指定fallbackFactory属性，如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 调用商品微服务的接口
 */
//@FeignClient(value = "server-product", fallback = ProductServiceFallBack.class)
@FeignClient(value = "server-product", fallbackFactory = ProductServiceFallBackFactory.class)
public interface ProductService {

    /**
     * 获取商品信息
     */
    @GetMapping(value = "/product/get/{pid}")
    Product getProduct(@PathVariable("pid") Long pid);

    /**
     * 更新库存数量
     */
    @GetMapping(value = "/product/update_count/{pid}/{count}")
    Result<Integer> updateCount(@PathVariable("pid") Long pid, @PathVariable("count") Integer count);
}
```

### 测试服务容错

与“Feign整合Sentinel实现容错-测试服务容错”中的测试方法相同，这里不再赘述。

至此，使用Sentinel实现限流和容错的功能就完成了。

**最后，需要注意的是：使用Sentinel实现服务容错时，fallback和fallbackFactory只能使用其中一种方式实现服务容错，二者不能同时使用。**

**好了，至此，我们使用Sentinel实现了服务的限流与容错功能，限于篇幅，文中并未给出完整的源代码，想要完整源代码的小伙伴可加入【冰河技术】知识星球获取源码。也可以加我微信：hacker_binghe，一起交流技术。**

**另外，一不小心就写了10章了，小伙伴们你们再不上车就跟不上了！！！**

## 星球服务

加入星球，你将获得：

1.项目学习：微服务入门必备的SpringCloud  Alibaba实战项目、手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】、Seckill秒杀系统项目—进大厂必备高并发、高性能和高可用技能。

2.框架源码：手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】。

3.硬核技术：深入理解高并发系列（全册）、深入理解JVM系列（全册）、深入浅出Java设计模式（全册）、MySQL核心知识（全册）。

4.技术小册：深入理解高并发编程（第1版）、深入理解高并发编程（第2版）、从零开始手写RPC框架、SpringCloud  Alibaba实战、冰河的渗透实战笔记、MySQL核心知识手册、Spring IOC核心技术、Nginx核心技术、面经手册等。

5.技术与就业指导：提供相关就业辅导和未来发展指引，冰河从初级程序员不断沉淀，成长，突破，一路成长为互联网资深技术专家，相信我的经历和经验对你有所帮助。

冰河的知识星球是一个简单、干净、纯粹交流技术的星球，不吹水，目前加入享5折优惠，价值远超门票。加入星球的用户，记得添加冰河微信：hacker_binghe，冰河拉你进星球专属VIP交流群。

## 星球重磅福利

跟冰河一起从根本上提升自己的技术能力，架构思维和设计思路，以及突破自身职场瓶颈，冰河特推出重大优惠活动，扫码领券进行星球，**直接立减149元，相当于5折，** 这已经是星球最大优惠力度！

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu_149.png?raw=true" width="80%">
    <br/>
</div>

领券加入星球，跟冰河一起学习《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》，更有已经上新的《大规模分布式Seckill秒杀系统》，从零开始介绍原理、设计架构、手撸代码。后续更有硬核中间件项目和业务项目，而这些都是你升职加薪必备的基础技能。

**100多元就能学这么多硬核技术、中间件项目和大厂秒杀系统，如果是我，我会买他个终身会员！**

## 其他方式加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

## 星球规划

后续冰河还会在星球更新大规模中间件项目和深度剖析核心技术的专栏，目前已经规划的专栏如下所示。

### 中间件项目

* 《大规模分布式定时调度中间件项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式IM（即时通讯）项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式网关项目实战（非Demo）》：全程手撸代码。
* 《手写Redis》：全程手撸代码。
* 《手写JVM》全程手撸代码。

### 超硬核项目

* 《从零落地秒杀系统项目》：全程手撸代码，在阿里云实现压测（**已上新**）。
* 《大规模电商系统商品详情页项目》：全程手撸代码，在阿里云实现压测。
* 其他待规划的实战项目，小伙伴们也可以提一些自己想学的，想一起手撸的实战项目。。。


既然星球规划了这么多内容，那么肯定就会有小伙伴们提出疑问：这么多内容，能更新完吗？我的回答就是：一个个攻破呗，咱这星球干就干真实中间件项目，剖析硬核技术和项目，不做Demo。初衷就是能够让小伙伴们学到真正的核心技术，不再只是简单的做CRUD开发。所以，每个专栏都会是硬核内容，像《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》就是很好的示例。后续的专栏只会比这些更加硬核，杜绝Demo开发。

小伙伴们跟着冰河认真学习，多动手，多思考，多分析，多总结，有问题及时在星球提问，相信在技术层面，都会有所提高。将学到的知识和技术及时运用到实际的工作当中，学以致用。星球中不少小伙伴都成为了公司的核心技术骨干，实现了升职加薪的目标。

## 联系冰河

### 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`星球编号`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>



### 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>


### 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>



### 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>