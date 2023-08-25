---
title: 第89章：业务网关整合Guava流控
pay: https://articles.zsxq.com/id_c2dzqg1fx62u.html
---

# 《Seckill秒杀系统》第89章：业务网关整合Guava流控

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：秒杀系统业务网关整合Guava流控，掌握业务网关整合Guava的流程，并能够将其灵活应用到自身实际项目中。

**大家好，我是冰河~~**

整合业务网关之后，客服端请求微服务时，就可以通过业务网关来统一转发请求了，也就是可以通过业务网关进行路由，将请求路由到正确的微服务上。并且后续可以在业务网关中实现鉴权、流控和风控等等一系列的功能。那业务网关可以整合Guava实现流控吗？

## 一、前言

在前面的文章中，秒杀系统整合了业务网关，并且对业务网关整合了Nacos，实现了业务网关对微服务的动态感知功能，后续只要有微服务注册到Nacos，业务网关都会动态感知到，并且会根据一定的负载均衡策略正确的将请求路由到对应的微服务，同时，业务网关也整合Sentinel实现了流控。

## 二、本章诉求

对业务网关与Guava进行整合实现流控，重点掌握业务网关整合Guava实现流控的流程和原理，并且将其灵活应用到实际项目中。

**注意：本章为大家提供网关整合Guava的实现方案代码，但是不会真正整合到秒杀系统中，大家拿到代码后可自行整合到秒杀系统中。**

## 三、整合Guava

业务网关整合Guava的步骤如下所示。

**（1）创建全局限流器**

创建BHRequestRateLimitFilter类，如下所示。

```java
@Component
@Order(-1)
public class RequestRateLimitFilter implements GlobalFilter {
    private static final Cache<String, RateLimiter> RATE_LIMITER_CACHE = CacheBuilder
            .newBuilder()
            .maximumSize(1000)
            .expireAfterAccess(1, TimeUnit.HOURS)
            .build();

    private static final double DEFAULT_PERMITS_PER_SECOND = 1; // 令牌桶每秒填充速率

    @SneakyThrows
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String remoteAddr = Objects.requireNonNull(exchange.getRequest().getRemoteAddress()).getAddress().getHostAddress();
        RateLimiter rateLimiter = RATE_LIMITER_CACHE.get(remoteAddr, () -> RateLimiter.create(DEFAULT_PERMITS_PER_SECOND));
        if (rateLimiter.tryAcquire()) {
            return chain.filter(exchange);
        }
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
        ResponseMessage<String> responseMessage = ResponseMessageBuilder.build(ErrorCode.FREQUENTLY_ERROR.getCode(), ErrorCode.FREQUENTLY_ERROR.getMesaage());
        String responseStr = JSON.toJSONString(responseMessage);
        DataBuffer dataBuffer = response.bufferFactory().wrap(responseStr.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(dataBuffer));
    }
}
```

这种限流有个弊端，就是限流的粒度太大，会对所有的请求限流，不能进行针对某个微服务或者接口进行限流。所以，我们需要继续优化这种限流策略。

**（2）创建局部限流器**

创建BHRequestRateLimitGatewayFilterFactory类，如下所示。

```java
@Component
public class BHRequestRateLimitGatewayFilterFactory extends AbstractGatewayFilterFactory<CustomRequestRateLimitGatewayFilterFactory.Config> {
    public CustomRequestRateLimitGatewayFilterFactory() {
        super(Config.class);
    }

    private static final Cache<String, RateLimiter> RATE_LIMITER_CACHE = CacheBuilder
            .newBuilder()
            .maximumSize(1000)
            .expireAfterAccess(1, TimeUnit.HOURS)
            .build();

    @Override
    public GatewayFilter apply(Config config) {
        return new GatewayFilter() {
            @SneakyThrows
            @Override
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
                String remoteAddr = Objects.requireNonNull(exchange.getRequest().getRemoteAddress()).getAddress().getHostAddress();
                RateLimiter rateLimiter = RATE_LIMITER_CACHE.get(remoteAddr, () ->
                        RateLimiter.create(Double.parseDouble(config.getPermitsPerSecond())));
                if (rateLimiter.tryAcquire()) {
                    return chain.filter(exchange);
                }
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
                response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
                ResponseMessage<String> responseMessage = ResponseMessageBuilder.build(ErrorCode.FREQUENTLY_ERROR.getCode(), ErrorCode.FREQUENTLY_ERROR.getMesaage());
                String responseStr = JSON.toJSONString(responseMessage);
                DataBuffer dataBuffer = response.bufferFactory().wrap(responseStr.getBytes(StandardCharsets.UTF_8));
                return response.writeWith(Mono.just(dataBuffer));
            }
        };
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.singletonList("permitsPerSecond");
    }

    public static class Config {
        private String permitsPerSecond; 
        
        public void setPermitsPerSecond(String permitsPerSecond){
            this.permitsPerSecond = permitsPerSecond;
        }
        
        public String getPermitsPerSecond(){
            return this.permitsPerSecond;
        }
    }
}
```

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码