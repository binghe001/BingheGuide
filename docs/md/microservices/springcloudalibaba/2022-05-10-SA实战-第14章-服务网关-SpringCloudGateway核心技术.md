---
layout: post
category: binghe-code-springcloudalibaba
title: 第14章：SpringCloud Gateway核心技术
tagline: by 冰河
tag: [springcloud,springcloudalibaba,binghe-code-springcloudalibaba]
excerpt: SA实战 ·《SpringCloud Alibaba实战》第14章-服务网关加餐：SpringCloud Gateway核心技术
lock: need
---

# SA实战 ·《SpringCloud Alibaba实战》第14章-服务网关加餐：SpringCloud Gateway核心技术


作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

**大家好，我是冰河~~**

> 一不小心《[SpringCloud Alibaba实战](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247500408&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏都更新到第14章了，再不上车就跟不上了，小伙伴们快跟上啊！
>
> 注意：本项目完整源码加入 **[冰河技术](https://public.zsxq.com/groups/48848484411888.html)** 知识星球即可获取，文末有优惠券。

在《[SpringCloud Alibaba实战](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247500408&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏前面的文章中，我们实现了用户微服务、商品微服务和订单微服务之间的远程调用，并且实现了服务调用的负载均衡。也基于阿里开源的Sentinel实现了服务的限流与容错，并详细介绍了Sentinel的核心技术与配置规则，同时，简单介绍了服务网关，并对SpringCloud Gateway的核心架构进行了简要说明，也在项目中整合了SpringCloud Gateway网关实现了通过网关访问后端微服务，另外，也能够SpringCloud Gateway整合Sentinel实现了网关的限流功能。今天，我们再进一步介绍下SpringCloud Gateway网关的核心技术。

## 本章总览

![sa-2022-05-10-013](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-013.png)

## 本章概述

SpringCloud Gateway能够实现多种网关功能，比如路由转发、断言、过滤器、熔断、限流、降级、自定义谓词配置、自定义过滤器等等多种功能。今天，我们就一起来聊聊SpringCloud Gateway中的断言、过滤器与熔断机制。

## 网关断言

断言的英文是Predicate，也可以翻译成谓词。主要的作用就是进行条件判断，可以在网关中实现多种条件判断，只有所有的判断结果都通过时，也就是所有的条件判断都返回true，才会真正的执行路由功能。

### SpringCloud Gateway内置断言

SpringCloud Gateway包括许多内置的断言工厂，所有这些断言都与HTTP请求的不同属性匹配。

#### 基于日期时间类型的断言

基于日期时间类型的断言根据时间做判断，主要有三个：

* AfterRoutePredicateFactory： 接收一个日期参数，判断请求日期是否晚于指定日期
* BeforeRoutePredicateFactory： 接收一个日期参数，判断请求日期是否早于指定日期
* BetweenRoutePredicateFactory： 接收两个日期参数，判断请求日期是否在指定时间段内

#### 使用示例

```bash
- After=2022-05-10T23:59:59.256+08:00[Asia/Shanghai]
```

#### 基于远程地址的断言

RemoteAddrRoutePredicateFactory：接收一个IP地址段，判断请求主机地址是否在地址段中。

#### 使用示例

```bash
- RemoteAddr=192.168.0.1/24
```

#### 基于Cookie的断言

CookieRoutePredicateFactory：接收两个参数， cookie 名字和一个正则表达式。 判断请求cookie是否具有给定名称且值与正则表达式匹配。

#### 使用示例

```bash
- Cookie=name, binghe.
```

#### 基于Header的断言

HeaderRoutePredicateFactory：接收两个参数，标题名称和正则表达式。 判断请求Header是否具有给定名称且值与正则表达式匹配。

#### 使用示例

```bash
- Header=X-Request-Id, \d+
```

#### 基于Host的断言

HostRoutePredicateFactory：接收一个参数，主机名模式。判断请求的Host是否满足匹配规则。

#### 使用示例

```bash
- Host=**.binghe.com
```

#### 基于Method请求方法的断言

MethodRoutePredicateFactory：接收一个参数，判断请求类型是否跟指定的类型匹配。

#### 使用示例

```bash
- Method=GET
```

#### 基于Path请求路径的断言

PathRoutePredicateFactory：接收一个参数，判断请求的URI部分是否满足路径规则。

#### 使用示例

```bash
- Path=/binghe/{segment}
```

#### 基于Query请求参数的断言

QueryRoutePredicateFactory ：接收两个参数，请求参数和正则表达式， 判断请求参数是否具有给定名称且值与正则表达式匹配。

#### 使用示例

```bash
- Query=name, binghe.
```

#### 基于路由权重的断言

WeightRoutePredicateFactory：接收一个[组名,权重], 然后对于同一个组内的路由按照权重转发。

#### 使用示例

```bash
- id: weight1
  uri: http://localhost:8080
  predicates:
    - Path=/api/**
    - Weight=group1,2
  filters:
    - StripPrefix=1
- id: weight2
  uri: http://localhost:8081
  predicates:
    - Path=/api/**
    - Weight=group1,8
  filters:
    - StripPrefix=1
```

### 演示内置断言

在演示的示例中，我们基于Path请求路径的断言判断请求路径是否符合规则，基于远程地址的断言判断请求主机地址是否在地址段中，并且限制请求的方式为GET方式。整个演示的过程以访问用户微服务的接口为例。

（1）由于在开发项目时，所有的服务都是在我本地启动的，首先查看下我本机的IP地址，如下所示。

![sa-2022-05-10-001](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-001.png)

可以看到，我本机的IP地址为192.168.0.27，属于192.168.0.1/24网段。

（2）在服务网关模块shop-gateway中，将application.yml文件备份成application-sentinel.yml文件，并将application.yml文件中的内容修改成application-simple.yml文件中的内容。接下来，在application.yml文件中的`spring.cloud.gateway.routes`节点下的`- id: user-gateway`下面进行断言配置，配置后的结果如下所示。

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-gateway
          uri: http://localhost:8060
          order: 1
          predicates:
            - Path=/server-user/**
            - RemoteAddr=192.168.0.1/24
            - Method=GET
          filters:
            - StripPrefix=1
```

**注意：完整的配置参见案例完整源代码。**

（3）配置完成后启动用户微服务和网关服务，通过网关服务访问用户微服务，在浏览器中输入`http://localhost:10001/server-user/user/get/1001`，如下所示。

![sa-2022-05-10-002](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-002.png)

可以看到通过`http://localhost:10001/server-user/user/get/1001`链接不能正确访问到用户信息。

接下来，在浏览器中输入`http://192.168.0.27:10001/server-user/user/get/1001`，能够正确获取到用户的信息。

![sa-2022-05-10-003](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-003.png)

（4）停止网关微服务，将基于远程地址的断言配置成`- RemoteAddr=192.168.1.1/24`，也就是将基于远程地址的断言配置成与我本机IP地址不在同一个网段，这样就能演示请求主机地址不在地址段中的情况，修改后的基于远程地址的断言配置如下所示。

```bash
- RemoteAddr=192.168.1.1/24
```

（5）重启网关服务，再次在浏览器中输入`http://localhost:10001/server-user/user/get/1001`，如下所示。

![sa-2022-05-10-004](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-004.png)

可以看到通过`http://localhost:10001/server-user/user/get/1001`链接不能正确访问到用户信息。

接下来，在浏览器中输入`http://192.168.0.27:10001/server-user/user/get/1001`，也不能正确获取到用户的信息了。

![sa-2022-05-10-005](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-005.png)

### 自定义断言

SpringCloud Gateway支持自定义断言功能，我们可以在具体业务中，基于SpringCloud Gateway自定义特定的断言功能。

#### 自定义断言概述

SpringCloud Gateway虽然提供了多种内置的断言功能，但是在某些场景下无法满足业务的需要，此时，我们就可以基于SpringCloud Gateway自定义断言功能，以此来满足我们的业务场景。

#### 实现自定义断言

这里，我们基于SpringCloud Gateway实现断言功能，实现后的效果是在服务网关的application.yml文件中的`spring.cloud.gateway.routes`节点下的`- id: user-gateway`下面进行如下配置。

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-gateway
          uri: http://localhost:8060
          order: 1
          predicates:
            - Path=/server-user/**
            - Name=binghe
          filters:
            - StripPrefix=1
```

通过服务网关访问用户微服务时，只有在访问的链接后面添加`?name=binghe`参数时才能正确访问用户微服务。

（1）在网关服务shop-gateway中新建`io.binghe.shop.predicate`包，在包下新建NameRoutePredicateConfig类，主要定义一个Spring类型的name成员变量，用来接收配置文件中的参数，源码如下所示。

```java
/**
 * @author binghe
 * @version 1.0.0
 * @description 接收配置文件中的参数
 */
@Data
public class NameRoutePredicateConfig implements Serializable {
    private static final long serialVersionUID = -3289515863427972825L;
    private String name;
}
```

（2）实现自定义断言时，需要新建类继承`org.springframework.cloud.gateway.handler.predicate.AbstractRoutePredicateFactory`类，在`io.binghe.shop.predicate`包下新建NameRoutePredicateFactory类，继承`org.springframework.cloud.gateway.handler.predicate.AbstractRoutePredicateFactory`类，并覆写相关的方法，源码如下所示。

```java
/**
 * @author binghe
 * @version 1.0.0
 * @description 自定义断言功能
 */
@Component
public class NameRoutePredicateFactory extends AbstractRoutePredicateFactory<NameRoutePredicateConfig> {

    public NameRoutePredicateFactory() {
        super(NameRoutePredicateConfig.class);
    }

    @Override
    public Predicate<ServerWebExchange> apply(NameRoutePredicateConfig config) {
        return (serverWebExchange)->{
            String name = serverWebExchange.getRequest().getQueryParams().getFirst("name");
            if (StringUtils.isEmpty(name)){
                name = "";
            }
            return name.equals(config.getName());
        };
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("name");
    }
}
```

（3）在服务网关的application.yml文件中的`spring.cloud.gateway.routes`节点下的`- id: user-gateway`下面进行如下配置。

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-gateway
          uri: http://localhost:8060
          order: 1
          predicates:
            - Path=/server-user/**
            - Name=binghe
          filters:
            - StripPrefix=1
```

（4）分别启动用户微服务与网关服务，在浏览器中输入`http://localhost:10001/server-user/user/get/1001`，如下所示。

![sa-2022-05-10-006](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-006.png)

可以看到，在浏览器中输入`http://localhost:10001/server-user/user/get/1001`，无法获取到用户信息。

（5）在浏览器中输入`http://localhost:10001/server-user/user/get/1001?name=binghe`，如下所示。

![sa-2022-05-10-007](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-007.png)

可以看到，在访问链接后添加`?name=binghe`参数后，能够正确获取到用户信息。

至此，我们实现了自定义断言功能。

## 网关过滤器

过滤器可以在请求过程中，修改请求的参数和响应的结果等信息。在生命周期的角度总体上可以分为前置过滤器（Pre）和后置过滤器(Post)。在实现的过滤范围角度可以分为局部过滤器（GatewayFilter）和全局过滤器（GlobalFilter）。局部过滤器作用的范围是某一个路由，全局过滤器作用的范围是全部路由。

* Pre前置过滤器：在请求被网关路由之前调用，可以利用这种过滤器实现认证、鉴权、路由等功能，也可以记录访问时间等信息。
* Post后置过滤器：在请求被网关路由到微服务之后执行。可以利用这种过滤器修改HTTP的响应Header信息，修改返回的结果数据（例如对于一些敏感的数据，可以在此过滤器中统一处理后返回），收集一些统计信息等。
* 局部过滤器（GatewayFilter）：也可以称为网关过滤器，这种过滤器主要是作用于单一路由或者某个路由分组。
* 全局过滤器（GlobalFilter）：这种过滤器主要作用于所有的路由。

### 局部过滤器

局部过滤器又称为网关过滤器，这种过滤器主要是作用于单一路由或者某个路由分组。

#### 局部过滤器概述

在SpringCloud Gateway中内置了很多不同类型的局部过滤器，主要如下所示。

| 过滤器                      | 作用                                                         | 参数                                                         |
| --------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| AddRequestHeader            | 为原始请求添加Header                                         | Header的名称及值                                             |
| AddRequestParameter         | 为原始请求添加请求参数                                       | 参数名称及值                                                 |
| AddResponseHeader           | 为原始响应添加Header                                         | Header的名称及值                                             |
| DedupeResponseHeader        | 剔除响应头中重复的值                                         | 需要去重的Header名 称及去重策略                              |
| Hystrix                     | 为路由引入Hystrix的断路器保护                                | HystrixCommand的名 称                                        |
| FallbackHeaders             | 为fallbackUri的请求头中添加具 体的异常信息                   | Header的名称                                                 |
| PrefixPath                  | 为原始请求路径添加前缀                                       | 前缀路径                                                     |
| PreserveHostHeader          | 为请求添加一个 preserveHostHeader=true的属 性， 路由过滤器会检查该属性以 决定是否要发送原始的Host | 无                                                           |
| RequestRateLimiter          | 用于对请求限流， 限流算法为令 牌桶                           | keyResolver、 rateLimiter、 statusCode、 denyEmptyKey、 emptyKeyStatus |
| RedirectTo                  | 将原始请求重定向到指定的URL                                  | http状态码及重定向的 url                                     |
| RemoveHopByHopHeadersFilter | 为原始请求删除IETF组织规定的 一系列Header                    | 默认就会启用， 可以通 过配置指定仅删除哪些 Header            |
| RemoveRequestHeader         | 为原始请求删除某个Header                                     | Header名称                                                   |
| RemoveResponseHeader        | 为原始响应删除某个Header                                     | Header名称                                                   |
| RewritePath                 | 重写原始的请求路径                                           | 原始路径正则表达式以 及重写后路径的正则表 达式               |
| RewriteResponseHeader       | 重写原始响应中的某个Header                                   | Header名称， 值的正 则表达式， 重写后的值                    |
| SaveSession                 | 在转发请求之前， 强制执行 WebSession::save操作               | 无                                                           |
| secureHeaders               | 为原始响应添加一系列起安全作 用的响应头                      | 无， 支持修改这些安全 响应头的值                             |
| SetPath                     | 修改原始的请求路径                                           | 修改后的路径                                                 |
| SetResponseHeader           | 修改原始响应中某个Header的值                                 | Header名称， 修改后 的值                                     |
| SetStatus                   | 修改原始响应的状态码                                         | HTTP 状态码， 可以是 数字， 也可以是字符串                   |
| StripPrefix                 | 用于截断原始请求的路径                                       | 使用数字表示要截断的 路径的数量                              |
| Retry                       | 针对不同的响应进行重试                                       | retries、 statuses、 methods、 series                        |
| RequestSize                 | 设置允许接收最大请求包的大 小。 如果请求包大小超过设置的 值， 则返回 413 Payload Too Large | 请求包大小， 单位为字 节， 默认值为5M                        |
| ModifyRequestBody           | 在转发请求之前修改原始请求体 内容                            | 修改后的请求体内容                                           |
| ModifyResponseBody          | 修改原始响应体的内容                                         | 修改后的响应体内容                                           |

<p align="right"><font size="2">注：表格转自互联网。</font></p>

#### 演示内部过滤器

演示内部过滤器时，我们为原始请求添加一个名称为IP的Header，值为localhost，并添加一个名称为name的参数，参数值为binghe。同时修改响应的结果状态，将结果状态修改为1001。

（1）在服务网关的application.yml文件中的`spring.cloud.gateway.routes`节点下的`- id: user-gateway`下面进行如下配置。

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-gateway
          uri: http://localhost:8060
          order: 1
          predicates:
            - Path=/server-user/**
          filters:
            - StripPrefix=1
            - AddRequestHeader=IP,localhost
            - AddRequestParameter=name,binghe
            - SetStatus=1001
```

（2）在用户微服务的`io.binghe.shop.user.controller.UserController`类中新增apiFilter1()方法，如下所示。

```java
@GetMapping(value = "/api/filter1")
public String apiFilter1(HttpServletRequest request, HttpServletResponse response){
    log.info("访问了apiFilter1接口");
    String ip = request.getHeader("IP");
    String name = request.getParameter("name");
    log.info("ip = " + ip + ", name = " + name);
    return "apiFilter1";
}
```

可以看到，在新增加的apiFilter1()方法中，获取到新增加的Header与参数，并将获取出来的参数与Header打印出来。并且方法返回的是字符串apiFilter1。

（3）分别启动用户微服务与网关服务，在浏览器中输入`http://localhost:10001/server-user/user/api/filter1`，如下所示。

![sa-2022-05-10-008](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-008.png)

此时，查看浏览器中的响应状态码，如下所示。

![sa-2022-05-10-009](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-009.png)

可以看到，此时的状态码已经被修改为1001。

接下来，查看下用户微服务的控制台输出的信息，发现在输出的信息中存在如下数据。

```bash
访问了apiFilter1接口
ip = localhost, name = binghe
```

说明使用SpringCloud Gateway的内置过滤器成功为原始请求添加了一个名称为IP的Header，值为localhost，并添加了一个名称为name的参数，参数值为binghe。同时修改了响应的结果状态，将结果状态修改为1001，符合预期效果。

#### 自定义局部过滤器

这里，我们基于SpringCloud Gateway自定义局部过滤器实现是否开启灰度发布的功能，整个实现过程如下所示。

（1）在服务网关的application.yml文件中的`spring.cloud.gateway.routes`节点下的`- id: user-gateway`下面进行如下配置。

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-gateway
          uri: http://localhost:8060
          order: 1
          predicates:
            - Path=/server-user/**
          filters:
            - StripPrefix=1
            - Grayscale=true
```

（2）在网关服务模块shop-gateway中新建`io.binghe.shop.filter`包，在包下新建GrayscaleGatewayFilterConfig类，用于接收配置中的参数，如下所示。

```java
/**
 * @author binghe
 * @version 1.0.0
 * @description 接收配置参数
 */
@Data
public class GrayscaleGatewayFilterConfig implements Serializable {
    private static final long serialVersionUID = 983019309000445082L;
    private boolean grayscale;
}
```

（3）在`io.binghe.shop.filter`包下GrayscaleGatewayFilterFactory类，继承`org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory`类，主要是实现自定义过滤器，模拟实现灰度发布。代码如下所示。

```java
/**
 * @author binghe
 * @version 1.0.0
 * @description 自定义过滤器模拟实现灰度发布
 */
@Component
public class GrayscaleGatewayFilterFactory extends AbstractGatewayFilterFactory<GrayscaleGatewayFilterConfig> {

    public GrayscaleGatewayFilterFactory(){
        super(GrayscaleGatewayFilterConfig.class);
    }
    @Override
    public GatewayFilter apply(GrayscaleGatewayFilterConfig config) {
        return (exchange, chain) -> {
            if (config.isGrayscale()){
                System.out.println("开启了灰度发布功能...");
            }else{
                System.out.println("关闭了灰度发布功能...");
            }
            return chain.filter(exchange);
        };
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("grayscale");
    }
}
```

（4）分别启动用户微服务和服务网关，在浏览器中输入`http://localhost:10001/server-user/user/get/1001`，如下所示。

![sa-2022-05-10-010](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-010.png)

可以看到，通过服务网关正确访问到了用户微服务，并正确获取到了用户信息。

接下来，查看下服务网关的终端，发现已经成功输出了如下信息。

```java
开启了灰度发布功能...
```

说明正确实现了自定义的局部过滤器。

### 全局过滤器

全局过滤器是一系列特殊的过滤器，会根据条件应用到所有路由中。

#### 全局过滤器概述

在SpringCloud Gateway中内置了多种不同的全局过滤器，如下所示。

| 过滤器                       | 作用                                                         |
| ---------------------------- | ------------------------------------------------------------ |
| ForwardRoutingFilter         | 用于本地forward，也就是将请求在Gateway服务内进行转发，而不是转发到下游服务。 |
| LoadBalancerClientFilter     | 整合Ribbon实现负载均衡。                                     |
| NettyRoutingFilter           | 使用Netty的HttpClient 转发http、https请求。                  |
| NettyWriteResponseFilter     | 将代理响应写回网关的客户端侧。                               |
| RouteToRequestUrlFilter      | 将从request里获取的原始url转换成Gateway进行请求转发时所使用的url。 |
| WebsocketRoutingFilter       | 使用Spring Web Socket将转发 Websocket 请求。                 |
| GatewayMetricsFilter         | 整合监控相关，提供监控指标。                                 |
| ForwardPathFilter            | 解析路径，并转发路径。                                       |
| WebClientHttpRoutingFilter   | 通过WebClient客户端转发请求真实的URL。                       |
| WebClientWriteResponseFilter | 将响应信息写入到当前的请求响应中。                           |

#### 演示全局过滤器

（1）在服务网关模块shop-gateway模块下的`io.binghe.shop.config`包下新建GatewayFilterConfig类，并在类中配置几个全局过滤器，如下所示。

```java
/**
 * @author binghe
 * @version 1.0.0
 * @description 网关过滤器配置
 */
@Configuration
@Slf4j
public class GatewayFilterConfig {
    @Bean
    @Order(-1)
    public GlobalFilter globalFilter() {
        return (exchange, chain) -> {
            log.info("执行前置过滤器逻辑");
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                log.info("执行后置过滤器逻辑");
            }));
        };
    }
}
```

**注意：@Order注解中的数字越小，执行的优先级越高。**

（2）启动用户微服务与服务网关，在浏览器中访问`http://localhost:10001/server-user/user/get/1001`，如下所示。

![sa-2022-05-10-010](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-010.png)

在服务网关终端输出如下信息。

```bash
执行前置过滤器逻辑
执行后置过滤器逻辑
```

说明我们演示的全局过滤器生效了。

#### 自定义全局过滤器

SpringCloud Gateway内置了很多全局过滤器，一般情况下能够满足实际开发需要，但是对于某些特殊的业务场景，还是需要我们自己实现自定义全局过滤器。

这里，我们就模拟实现一个获取客户端访问信息，并统计访问接口时长的全局过滤器。

（1）在网关服务模块shop-order的`io.binghe.shop.filter`包下，新建GlobalGatewayLogFilter类，实现`org.springframework.cloud.gateway.filter.GlobalFilter`接口和`org.springframework.core.Ordered`接口，代码如下所示。

```java
/**
 * @author binghe
 * @version 1.0.0
 * @description 自定义全局过滤器，模拟实现获取客户端信息并统计接口访问时长
 */
@Slf4j
@Component
public class GlobalGatewayLogFilter implements GlobalFilter, Ordered {
    /**
     * 开始访问时间
     */
    private static final String BEGIN_VISIT_TIME = "begin_visit_time";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //先记录下访问接口的开始时间
        exchange.getAttributes().put(BEGIN_VISIT_TIME, System.currentTimeMillis());
        return chain.filter(exchange).then(Mono.fromRunnable(()->{
            Long beginVisitTime = exchange.getAttribute(BEGIN_VISIT_TIME);
            if (beginVisitTime != null){
                log.info("访问接口主机: " + exchange.getRequest().getURI().getHost());
                log.info("访问接口端口: " + exchange.getRequest().getURI().getPort());
                log.info("访问接口URL: " + exchange.getRequest().getURI().getPath());
                log.info("访问接口URL参数: " + exchange.getRequest().getURI().getRawQuery());
                log.info("访问接口时长: " + (System.currentTimeMillis() - beginVisitTime) + "ms");
            }
        }));
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
```

上述代码的实现逻辑还是比较简单的，这里就不再赘述了。

（2）启动用户微服务与网关服务，在浏览器中输入`http://localhost:10001/server-user/user/api/filter1?name=binghe`，如下所示。

![sa-2022-05-10-012](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-05-10-012.png)

接下来，查看服务网关的终端日志，可以发现已经输出了如下信息。

```bash
访问接口主机: localhost
访问接口端口: 10001
访问接口URL: /server-user/user/api/filter1
访问接口URL参数: name=binghe
访问接口时长: 126ms
```

说明我们自定义的全局过滤器生效了。

## 网关熔断机制

其实熔断机制在《[SA实战 ·《SpringCloud Alibaba实战》第13章-服务网关：项目整合SpringCloud Gateway网关](https://binghe.gitcode.host/md/microservices/springcloudalibaba/2022-05-08-SA%E5%AE%9E%E6%88%98-%E7%AC%AC13%E7%AB%A0-%E6%9C%8D%E5%8A%A1%E7%BD%91%E5%85%B3-%E9%A1%B9%E7%9B%AE%E6%95%B4%E5%90%88SpringCloudGateway.html)》一文中就基于SpringCloud Gateway整合Sentinel实现了。大家可以参见《[SA实战 ·《SpringCloud Alibaba实战》第13章-服务网关：项目整合SpringCloud Gateway网关](https://binghe.gitcode.host/md/microservices/springcloudalibaba/2022-05-08-SA%E5%AE%9E%E6%88%98-%E7%AC%AC13%E7%AB%A0-%E6%9C%8D%E5%8A%A1%E7%BD%91%E5%85%B3-%E9%A1%B9%E7%9B%AE%E6%95%B4%E5%90%88SpringCloudGateway.html)》一文。

**注意：整个实战案例基于SpringCloud Alibaba技术栈实现，所以，整个案例专栏也是偏向于使用SpringCloud Alibaba技术栈的。**

**好了，今天我们就到儿吧，限于篇幅，文中并未给出完整的案例源代码，想要完整源代码的小伙伴可加入【冰河技术】知识星球获取源码。也可以加我微信：hacker_binghe，一起交流技术。**

**另外，一不小心就写了14章了，小伙伴们你们再不上车就真的跟不上了！！！**

## 关于星球

最近，冰河创建了【冰河技术】知识星球，《[SpringCloud Alibaba实战](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4MjU0OTM1OA==&action=getalbum&album_id=2337104419664084992&scene=173&from_msgid=2247500214&from_itemidx=1&count=3&nolastread=1#wechat_redirect)》专栏的源码获取方式会放到知识星期中，同时在微信上会创建专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

今天，【冰河技术】知识星球再开放200张优惠券，还没上车的小伙伴赶紧啦，再不上车就跟不上啦！！

### 星球提供的服务

冰河整理了星球提供的一些服务，如下所示。

加入星球，你将获得： 

1.学习SpringCloud Alibaba实战项目—从零开发微服务项目 

2.学习高并发、大流量业务场景的解决方案，体验大厂真正的高并发、大流量的业务场景 

3.学习进大厂必备技能：性能调优、并发编程、分布式、微服务、框架源码、中间件开发、项目实战 

4.提供站点 https://binghe.gitcode.host 所有学习内容的指导、帮助 

5.GitHub：https://github.com/binghe001/BingheGuide - 非常有价值的技术资料仓库，包括冰河所有的博客开放案例代码 

6.可以发送你的简历到我的邮箱，提供简历批阅服务 

7.提供技术问题、系统架构、学习成长、晋升答辩等各项内容的回答 

8.定期的整理和分享出各类专属星球的技术小册、电子书、编程视频、PDF文件 

9.定期组织技术直播分享，传道、授业、解惑，指导阶段瓶颈突破技巧

### 星球门票价格

星球目前的门票价格50元，随着每次加入新实战项目和分享硬核技术上调入场价格。

最后，小伙伴们可以扫描或者长按下图中的二维码加入星球，也可以在 **冰河技术** 公众号回复 “ **星球** ” ，领取入场优惠券。

![sa-2022-04-21-007](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-28-008.png)

**好了，今天就到这儿吧，我是冰河，我们下期见~~**


## 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`学习加群`。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 9px;">冰河微信</div>
    <br/>
</div>




## 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>


## 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>



## 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 9px;">知识星球：冰河技术</div>
    <br/>
</div>