---
title: 第104章：扩展Dubbo源码实现链路追踪
pay: https://articles.zsxq.com/id_njz1wp1hsjac.html
---

# 《Seckill秒杀系统》第104章：扩展Dubbo源码实现链路追踪

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：掌握扩展Dubbo源码的方式，使Sleuth能够支持Dubbo实现链路追踪，并能够灵活将实现方案应用到自身实际项目中。

**大家好，我是冰河~~**

秒杀系统已经整合了Sleuth实现链路追踪，如果是通过HTTP方式调用接口，则秒杀系统能够实现分布式链路追踪。由于秒杀系统的实现中，使用了Dubbo3，并且基于SpringCloud 2021.0.1和SpringCloud Alibaba2021.0.1实现，此版本下的Sleuth默认是不支持Dubbo3实现链路追踪的。

## 一、前言

在前面的文章中，我们在秒杀系统中整合Sleuth实现了链路追踪，在调用HTTP接口时，各个微服务会输出对应的链路追踪日志，但是，在调用Dubbo的RPC接口时，服务提供者输出的traceId和SpanId却为空。这很明显是Dubbo没有实现链路追踪啊！我们的秒杀系统中基于Dubbo实现了远程调用，如果Dubbo不能实现链接追踪，那秒杀系统就不能叫已经实现了链路追踪。

## 二、本章诉求

扩展Dubbo源码，基于Sleuth实现链路追踪，掌握扩展Dubbo源码的方式，重点理解Dubbo的扩展点机制，并能够在自身实际项目中根据具体需要扩展Dubbo源码。

另外，在我们自己手写的bhrpc框架中，也采用微内核、插件化、支持热插拔的架构模式，预留了大量的扩展点，供大家自己定制功能，《[RPC手撸专栏](https://t.zsxq.com/11JTuHLz3)》地址为：[https://t.zsxq.com/11JTuHLz3](https://t.zsxq.com/11JTuHLz3)

## 三、Dubbo实现链路追踪

Spring Cloud Sleuth默认不支持Dubbo实现链路追踪，所以我们要扩展dubbo的源码。主要的实现方案就是扩展Dubbo的过滤器，使其支持实现链路追踪的traceId和spanId，在Dubbo的Consumer与Provider之间进行传递。具体实现步骤如下所示。

**（1）新增DubboTraceFilter类**

DubboTraceFilter是自定义的Dubbo过滤器，主要实现的功能就是通过Consumer获取Sleuth放在日志MDC中的traceId和spanId，并将其放到Dubbo的上下文中，而Provider端则获取Dubbo上下文中的traceId和spanId，并将其放到日志MDC中。

DubboTraceFilter类的源码详见：seckill-dubbo-interfaces工程下的io.binghe.seckill.dubbo.interfaces.filter.DubboTraceFilter。

```java
@Activate(group = {CommonConstants.PROVIDER, CommonConstants.CONSUMER}, value = "tracing")
public class DubboTraceFilter implements Filter {
    /**
     * TraceId key
     */
    private static final String TRACE_ID = "traceId";
    /**
     * SpanId key
     */
    private static final String SPAN_ID = "spanId";

    @Override
    public Result invoke(Invoker<?> invoker, Invocation invocation) throws RpcException {
        // 获取dubbo上下文中的traceId
        String traceId = RpcContext.getContext().getAttachment(TRACE_ID);
        String spanId = RpcContext.getContext().getAttachment(SPAN_ID);
        if (StringUtils.isBlank(traceId) ) {
            // customer 设置traceId到dubbo的上下文
            RpcContext.getContext().setAttachment(TRACE_ID, MDC.get(TRACE_ID));
        } else {
            // provider 设置traceId到日志的上下文
            MDC.put(TRACE_ID, traceId);
        }
        if (StringUtils.isBlank(spanId)){
            // customer 设置spanId到dubbo的上下文
            RpcContext.getContext().setAttachment(SPAN_ID, MDC.get(SPAN_ID));
        }else{
            // provider 设置traceId到日志的上下文
            MDC.put(SPAN_ID, spanId);
        }
        return invoker.invoke(invocation);
    }
}
```

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
