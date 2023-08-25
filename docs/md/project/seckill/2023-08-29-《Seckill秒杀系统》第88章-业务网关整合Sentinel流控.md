---
title: 第88章：业务网关整合Sentinel流控
pay: https://articles.zsxq.com/id_25vqhrif9cf4.html
---

# 《Seckill秒杀系统》第88章：业务网关整合Sentinel流控

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：秒杀系统业务网关整合Sentinel流控，掌握业务网关整合Sentinel的流程，并能够将其灵活应用到自身实际项目中。

**大家好，我是冰河~~**

整合业务网关之后，客服端请求微服务时，就可以通过业务网关来统一转发请求了，也就是可以通过业务网关进行路由，将请求路由到正确的微服务上。并且后续可以在业务网关中实现鉴权、流控和风控等等一系列的功能。那业务网关可以整合Sentinel实现流控吗？

## 一、前言

在前面的文章中，秒杀系统整合了业务网关，并且对业务网关整合了Nacos，实现了业务网关对微服务的动态感知功能，后续只要有微服务注册到Nacos，业务网关都会动态感知到，并且会根据一定的负载均衡策略正确的将请求路由到对应的微服务，那可以业务网关可以整合Sentinel实现流控吗？改如何实现呢？

## 二、本章诉求

业务网关整合Sentinel实现流控，掌握业务网关整合Sentinel的流程，重点理解业务网关与Sentinel搭配实现流控的核心原理，并能够熟练应用到自身实际项目中。

## 三、整合Sentinel

Sentinel从1.6.0版本开始，提供了SpringCloud Gateway的适配模块，并且可以提供两种资源维度的限流，一种是route维度；另一种是自定义API分组维度。

* route维度：对application.yml文件中配置的`spring.cloud.gateway.routes.id`限流，并且资源名为`spring.cloud.gateway.routes.id`对应的值。
* 自定义API分组维度：利用Sentinel提供的API接口来自定义API分组，并且对这些API分组进行限流。

### 3.1 实现route维度限流

业务网关整合Sentinel实现route维度限流的步骤如下所示。

**（1）添加Maven依赖**

在seckill-gateway工程下的pom.xml文件中添加如下Maven依赖。

```xml
<dependency>
    <groupId>com.alibaba.csp</groupId>
    <artifactId>sentinel-spring-cloud-gateway-adapter</artifactId>
</dependency>
```

**（2）修改SeckillGatewayConfig配置类**

SeckillGatewayConfig类的源码详见：seckill-gateway工程下的io.binghe.seckill.gateway.config.SeckillGatewayConfig。修改后的源码如下所示。

```java
@Configuration
@ComponentScan(value = {"io.binghe.seckill", "com.alibaba.cola"})
@ServletComponentScan(basePackages = {"io.binghe.seckill"})
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class SeckillGatewayConfig {
    private final List<ViewResolver> viewResolvers;

    private final ServerCodecConfigurer serverCodecConfigurer;

    @Value("${spring.cloud.gateway.discovery.locator.route-id-prefix}")
    private String routeIdPrefix;

    public SeckillGatewayConfig(ObjectProvider<List<ViewResolver>> viewResolversProvider,
                                ServerCodecConfigurer serverCodecConfigurer) {
        this.viewResolvers = viewResolversProvider.getIfAvailable(Collections::emptyList);
        this.serverCodecConfigurer = serverCodecConfigurer;
    }
    /**
     * 初始化一个限流的过滤器
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public GlobalFilter sentinelGatewayFilter() {
        return new SentinelGatewayFilter();
    }
    @PostConstruct
    public void init() {
        this.initGatewayRules();
        this.initBlockHandlers();
    }
    /**
     * 配置初始化的限流参数
     */
    private void initGatewayRules() {
        Set<GatewayFlowRule> rules = new HashSet<>();
        //用户微服务
        rules.add(this.getGatewayFlowRule(getResource("seckill-user")));
        //秒杀活动微服务
        rules.add(this.getGatewayFlowRule(getResource("seckill-activity")));
        //秒杀商品微服务
        rules.add(this.getGatewayFlowRule(getResource("seckill-goods")));
        //秒杀订单微服务
        rules.add(this.getGatewayFlowRule(getResource("seckill-order")));
        //库存微服务
        rules.add(this.getGatewayFlowRule(getResource("seckill-stock")));
        //预约微服务
        rules.add(this.getGatewayFlowRule(getResource("seckill-reservation")));
        //加载规则
        GatewayRuleManager.loadRules(rules);
    }

    private String getResource(String targetServiceName){
        if (routeIdPrefix == null){
            routeIdPrefix = "";
        }
        return routeIdPrefix.concat(targetServiceName);
    }

    private GatewayFlowRule getGatewayFlowRule(String resource){
        //传入资源名称生成GatewayFlowRule
        GatewayFlowRule gatewayFlowRule = new GatewayFlowRule(resource);
        //限流阈值
        gatewayFlowRule.setCount(1);
        //统计的时间窗口，单位为
        gatewayFlowRule.setIntervalSec(1);
        return gatewayFlowRule;
    }

    /**
     * 配置限流的异常处理器
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SentinelGatewayBlockExceptionHandler sentinelGatewayBlockExceptionHandler() {
        return new SentinelGatewayBlockExceptionHandler(viewResolvers, serverCodecConfigurer);
    }
    /**
     * 自定义限流异常页面
     */
    private void initBlockHandlers() {
        BlockRequestHandler blockRequestHandler = (serverWebExchange, throwable)-> {
            Map<String, Object> map = new HashMap<>();
            map.put("code", 1001);
            map.put("codeMsg", "Sentinel-接口被限流了");
            return ServerResponse.status(HttpStatus.OK).
                    contentType(MediaType.APPLICATION_JSON_UTF8).
                    body(BodyInserters.fromObject(map));
        };
        GatewayCallbackManager.setBlockHandler(blockRequestHandler);
    }
}
```

SeckillGatewayConfig类的源代码看上去比较多，但是都是一些非常简单的方法，冰河在这里就不再赘述了。

**这里有个需要特别注意的地方：**

**Sentinel1.8.4整合SpringCloud Gateway使用的API类型为Route ID类型时，也就是基于route维度时，由于Sentinel为SpringCloud Gateway网关生成的API名称规则如下：**

**生成的规则为：${spring.cloud.gateway.discovery.locator.route-id-prefix}后面直接加上目标微服务的名称，如下所示。**
**${spring.cloud.gateway.discovery.locator.route-id-prefix}目标微服务的名称。其中，${spring.cloud.gateway.discovery.locator.route-id-prefix}是在yml文件中配置的访问前缀。**

**为了让通过服务网关访问目标微服务链接后，请求链路中生成的API名称与流控规则中生成的API名称一致，以达到启动项目即可实现访问链接的限流效果，而无需登录Setinel管理界面手动配置限流规则，可以将生成GatewayFlowRule对象的resource参数设置为${spring.cloud.gateway.discovery.locator.route-id-prefix}目标微服务的名称**

**当然，如果不按照上述配置，也可以在项目启动后，通过服务网关访问目标微服务链接后，在Sentinel管理界面的请求链路中找到对应的API名称所代表的请求链路，然后手动配置限流规则。**

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码