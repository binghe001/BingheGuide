---
title: 第87章：业务网关整合Nacos配置
pay: https://articles.zsxq.com/id_k3v3cwv7ogmd.html
---

# 《Seckill秒杀系统》第87章：业务网关整合Nacos配置

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：掌握网关整合Nacos的配置流程，重点理解Nacos简化项目的配置原理，并且掌握基础Nacos的服务注册与发现流程，并能够将其灵活应用到自身实际项目中。

**大家好，我是冰河~~**

整合业务网关之后，客服端请求微服务时，就可以通过业务网关来统一转发请求了，也就是可以通过业务网关进行路由，将请求路由到正确的微服务上。并且后续可以在业务网关中实现鉴权、流控和风控等等一系列的功能。

## 一、前言

引入业务网关后，我们的秒杀系统就有了更进一步的保证，后续我们也会在业务网管层实现流控等功能。但是，现在有个问题就是：引入网关后，在配置文件中配置了增加对应微服务的路由地址，目前这个地址还是直接写死的，如果新增了微服务，我们还需要手动加到网关中。难道引入网关就这么low吗？

事实是不可能这么low的，我们要实现服务自动注册与发现，当有新的微服务启动后，网关可以自动感知到，并且可以按照一定的负载均衡策略进行分发。这就需要将网关整合到Nacos。好了，说干就干，开始吧。

## 二、本章诉求

对网关与Nacos进行初步整合，从Nacos中获取转发的服务地址，并对其进行测试。随后，实现网关与Nacos的最简化配置，达到网关无需配置任何微服务信息，即可动态从Nacos获取转发的服务地址。重点掌握网关与Nacos的整合流程，并能够熟练应用到自身实际项目中。

## 三、网关初步整合Nacos

在前面的文章中，初步整合SpringCloud Gateway中，我们在服务网关模块的application.yml文件中硬编码配置了服务转发的地址，如下所示。

```properties
spring.cloud.gateway.routes[0].id=user-gateway
spring.cloud.gateway.routes[0].uri=http://localhost:8081
spring.cloud.gateway.routes[0].order=1
spring.cloud.gateway.routes[0].predicates[0]=Path=/seckill-user/**
spring.cloud.gateway.routes[0].filters[0]=StripPrefix=1

spring.cloud.gateway.routes[1].id=activity-gateway
spring.cloud.gateway.routes[1].uri=http://localhost:8082
spring.cloud.gateway.routes[1].order=1
spring.cloud.gateway.routes[1].predicates[0]=Path=/seckill-activity/**
spring.cloud.gateway.routes[1].filters[0]=StripPrefix=1

spring.cloud.gateway.routes[2].id=goods-gateway
spring.cloud.gateway.routes[2].uri=http://localhost:8083
spring.cloud.gateway.routes[2].order=1
spring.cloud.gateway.routes[2].predicates[0]=Path=/seckill-goods/**
spring.cloud.gateway.routes[2].filters[0]=StripPrefix=1

spring.cloud.gateway.routes[3].id=order-gateway
spring.cloud.gateway.routes[3].uri=http://localhost:8084
spring.cloud.gateway.routes[3].order=1
spring.cloud.gateway.routes[3].predicates[0]=Path=/seckill-order/**
spring.cloud.gateway.routes[3].filters[0]=StripPrefix=1

spring.cloud.gateway.routes[4].id=stock-gateway
spring.cloud.gateway.routes[4].uri=http://localhost:8085
spring.cloud.gateway.routes[4].order=1
spring.cloud.gateway.routes[4].predicates[0]=Path=/seckill-stock/**
spring.cloud.gateway.routes[4].filters[0]=StripPrefix=1

spring.cloud.gateway.routes[5].id=reservation-gateway
spring.cloud.gateway.routes[5].uri=http://localhost:8086
spring.cloud.gateway.routes[5].order=1
spring.cloud.gateway.routes[5].predicates[0]=Path=/seckill-reservation/**
spring.cloud.gateway.routes[5].filters[0]=StripPrefix=1
```

这里，我们需要将网关与Nacos进行整合，实现从Nacos注册中心获取转发的服务地址，具体实现步骤如下所示。

**（1）引入依赖**

在seckill-gateway工程下的pom.xml文件中引入loadbalancer依赖。

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-loadbalancer</artifactId>
</dependency>
```

**（2）修改配置文件**

将application.yml备份一份，命名为application-simple.yml，并修改application.yml配置文件，修改后的文件如下所示。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码