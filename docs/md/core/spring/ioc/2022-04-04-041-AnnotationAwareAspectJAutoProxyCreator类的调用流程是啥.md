---
layout: post
category: binghe-spring-ioc
title: 第40章：AnnotationAwareAspectJAutoProxyCreator类详解
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 停更了很久的【Spring注解系列】专题，终于重新更新了，我们还是接着之前的文章继续往下更新。在《[【Spring注解驱动开发】二狗子让我给他讲讲@EnableAspectJAutoProxy注解](https://mp.weixin.qq.com/s?__biz=Mzg4MjU0OTM1OA==&mid=2247489210&idx=1&sn=becc26b4b2d681007bfa52ce2448eed5&chksm=cf55a1bbf82228ada0bd72aec8670bf774918b7bbaa2613baa59d77008566400a75b7d5be6a9&token=464268589&lang=zh_CN#rd)》一文中，我们通过查看`@EnableAspectJAutoProxy` 注解的源码，如下所示。
lock: need
---

# 《Spring注解驱动开发》第40章：AnnotationAwareAspectJAutoProxyCreator类详解

**大家好，我是冰河~~**

停更了很久的【Spring注解系列】专题，终于重新更新了，我们还是接着之前的文章继续往下更新。在《[【Spring注解驱动开发】二狗子让我给他讲讲@EnableAspectJAutoProxy注解](https://mp.weixin.qq.com/s?__biz=Mzg4MjU0OTM1OA==&mid=2247489210&idx=1&sn=becc26b4b2d681007bfa52ce2448eed5&chksm=cf55a1bbf82228ada0bd72aec8670bf774918b7bbaa2613baa59d77008566400a75b7d5be6a9&token=464268589&lang=zh_CN#rd)》一文中，我们通过查看`@EnableAspectJAutoProxy` 注解的源码，如下所示。

```java
package org.springframework.context.annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AspectJAutoProxyRegistrar.class)
public @interface EnableAspectJAutoProxy {
 boolean proxyTargetClass() default false;
 boolean exposeProxy() default false;
}
```

得知，`@EnableAspectJAutoProxy `注解是通过使用`@Import(AspectJAutoProxyRegistrar.class)` 给容器中注册一个名字叫做`internalAutoProxyCreator = AnnotationAwareAspectJAutoProxyCreator`的组件。

并且我们也分析了AnnotationAwareAspectJAutoProxyCreato类的核心继承关系，如下所示。

```bash
  AnnotationAwareAspectJAutoProxyCreator
       --AspectJAwareAdvisorAutoProxyCreator
         --AbstractAdvisorAutoProxyCreator
           --AbstractAutoProxyCreator
             -- ProxyProcessorSupport， SmartInstantiationAwareBeanPostProcessor, BeanFactoryAware
```

查看继承关系可以发现，此类实现了`Aware`与`BeanPostProcessor`接口，这两个接口都和Spring bean的初始化有关，由此推测此类主要处理方法都来自这两个接口的实现方法。同时该类也实现了order方法。

那今天，我们就来看看`AnnotationAwareAspectJAutoProxyCreator` 类的调用流程，具体来说，就是看看 ``AnnotationAwareAspectJAutoProxyCreator` 作为BeanPostProcessor做了哪些工作，作为BeanFactoryAware做了哪些工作。

## 分析AbstractAutoProxyCreator类

在 `AnnotationAwareAspectJAutoProxyCreator`类的继承关系上可以看出， 是在`AbstractAutoProxyCreator`类开始实现 `SmartInstantiationAwareBeanPostProcessor`接口和 `BeanFactoryAware` 接口的。

所以，我们先来看看 `AbstractAutoProxyCreator` 类进行分析。

由 `AbstractAutoProxyCreator` 类的定义我们可以看出，`AbstractAutoProxyCreator`类直接实现了`SmartInstantiationAwareBeanPostProcessor` 接口和 `BeanFactoryAware` 接口。

```java
public abstract class AbstractAutoProxyCreator extends ProxyProcessorSupport
		implements SmartInstantiationAwareBeanPostProcessor, BeanFactoryAware {
```

既然 `AbstractAutoProxyCreator` 实现了 `BeanFactoryAware` 接口， 那么 `AbstractAutoProxyCreator` 类中就一定存在setBeanFactory()方法，如下所示。

```java
@Override
public void setBeanFactory(BeanFactory beanFactory) {
    this.beanFactory = beanFactory;
}

@Nullable
protected BeanFactory getBeanFactory() {
    return this.beanFactory;
}
```

果然，我们在 `AbstractAutoProxyCreator` 类中找到了setBeanFactory()方法和getBeanFactory()方法。

另外，在 `AbstractAutoProxyCreator` 类中还存在与BeanPostProcessor后置处理器有关的方法，分别为：postProcessBeforeInstantiation()、postProcessAfterInstantiation()、postProcessProperties()、postProcessBeforeInitialization()、postProcessAfterInitialization()。整体源代码如下所示。

```java
@Override
public Object postProcessBeforeInstantiation(Class<?> beanClass, String beanName) {
    Object cacheKey = getCacheKey(beanClass, beanName);
    if (!StringUtils.hasLength(beanName) || !this.targetSourcedBeans.contains(beanName)){
        if (this.advisedBeans.containsKey(cacheKey)) {
            return null;
        }
        if (isInfrastructureClass(beanClass) || shouldSkip(beanClass, beanName)) {
            this.advisedBeans.put(cacheKey, Boolean.FALSE);
            return null;
        }
    }
    TargetSource targetSource = getCustomTargetSource(beanClass, beanName);
    if (targetSource != null) {
        if (StringUtils.hasLength(beanName)) {
            this.targetSourcedBeans.add(beanName);
        }
        Object[] specificInterceptors = getAdvicesAndAdvisorsForBean(beanClass, beanName, targetSource);
        Object proxy = createProxy(beanClass, beanName, specificInterceptors, targetSource);
        this.proxyTypes.put(cacheKey, proxy.getClass());
        return proxy;
    }
    return null;
}

@Override
public boolean postProcessAfterInstantiation(Object bean, String beanName) {
    return true;
}

@Override
public PropertyValues postProcessProperties(PropertyValues pvs, Object bean, String beanName) {
    return pvs;
}

@Override
public Object postProcessBeforeInitialization(Object bean, String beanName) {
    return bean;
}

@Override
public Object postProcessAfterInitialization(@Nullable Object bean, String beanName) {
    if (bean != null) {
        Object cacheKey = getCacheKey(bean.getClass(), beanName);
        if (this.earlyProxyReferences.remove(cacheKey) != bean) {
            return wrapIfNecessary(bean, beanName, cacheKey);
        }
    }
    return bean;
}
```

也就是说，在`AbstractAutoProxyCreator` 类中，存在后置处理器的逻辑。

到这，我们就在`AbstractAutoProxyCreator` 类中看到了`BeanFactoryAware` 的实现和后置处理器的实现。

接下来，我们再来看看`AbstractAutoProxyCreator` 的子类 `AbstractAdvisorAutoProxyCreator`类。

## 分析AbstractAdvisorAutoProxyCreator类

在 `AbstractAdvisorAutoProxyCreator`类中，我们会看到如下代码。

```java
@Override
public void setBeanFactory(BeanFactory beanFactory) {
    super.setBeanFactory(beanFactory);
    if (!(beanFactory instanceof ConfigurableListableBeanFactory)) {
        throw new IllegalArgumentException(
            "AdvisorAutoProxyCreator requires a ConfigurableListableBeanFactory: " + beanFactory);
    }
    initBeanFactory((ConfigurableListableBeanFactory) beanFactory);
}
```

说明在`AbstractAdvisorAutoProxyCreator`类中重写了setBeanFactory()方法。并且在`AbstractAdvisorAutoProxyCreator`类的setBeanFactory()方法中，首先会调用`AbstractAutoProxyCreator` 类中的setBeanFactory()方法。

在setBeanFactory()方法中会调用initBeanFactory()方法，initBeanFactory()方法的实现如下所示。

```java
protected void initBeanFactory(ConfigurableListableBeanFactory beanFactory) {
    this.advisorRetrievalHelper = new BeanFactoryAdvisorRetrievalHelperAdapter(beanFactory);
}
```

initBeanFactory()方法的实现比较简单，这里，我就不多说了。

另外，我们并没有在`AbstractAdvisorAutoProxyCreator`类中找到与后置处理器相关的方法。

接下来，我们继续分析`AbstractAdvisorAutoProxyCreator`类的子类AspectJAwareAdvisorAutoProxyCreator类。

## 分析AspectJAwareAdvisorAutoProxyCreator类

通过查看`AspectJAwareAdvisorAutoProxyCreator`类的源码，我们得知，在 `AspectJAwareAdvisorAutoProxyCreator`类中没有与后置处理器相关的代码。所以，我们继续向上分析 `AspectJAwareAdvisorAutoProxyCreator`类的子类 `AnnotationAwareAspectJAutoProxyCreator`。

## 分析AnnotationAwareAspectJAutoProxyCreator类

在 `AnnotationAwareAspectJAutoProxyCreator`类中，我们可以找到一个initBeanFactory()方法，如下所示。

```java
@Override
protected void initBeanFactory(ConfigurableListableBeanFactory beanFactory) {
    super.initBeanFactory(beanFactory);
    if (this.aspectJAdvisorFactory == null) {
        this.aspectJAdvisorFactory = new ReflectiveAspectJAdvisorFactory(beanFactory);
    }
    this.aspectJAdvisorsBuilder =
        new BeanFactoryAspectJAdvisorsBuilderAdapter(beanFactory, this.aspectJAdvisorFactory);
}
```

看到这里，小伙伴们对于setBeanFactory的调用流程有点清晰了吧？其实setBeanFactory()的调用流程为：首先会执行 `AbstractAdvisorAutoProxyCreator`类中的setBeanFactory()方法，在`AbstractAdvisorAutoProxyCreator`类中的setBeanFactory()方法中会调用其父类`AbstractAutoProxyCreator` 中的setBeanFactory()方法，然后在`AbstractAdvisorAutoProxyCreator`类中的setBeanFactory()方法中调用initBeanFactory()方法。由于在子类`AnnotationAwareAspectJAutoProxyCreator`中重写了initBeanFactory()方法，最终调用的就是`AnnotationAwareAspectJAutoProxyCreator`类中的initBeanFactory()方法。这么说有点绕，我们来看一张图吧。

![](https://img-blog.csdnimg.cn/20210311000758821.png)




注意，上图中的`AbstractAdvisorAutoProxyCreator`类中的setBeanFactory()方法作为程序调用的入口，它会依次调用`AbstractAutoProxyCreator#setBeanFactory()` 和 `AnnotationAwareAspectJAutoProxyCreator#initBeanFactory()` ，然后，再由 `AnnotationAwareAspectJAutoProxyCreator#initBeanFactory()` 调用 `AbstractAdvisorAutoProxyCreator#initBeanFactory()`。

除此之外，我们在`AnnotationAwareAspectJAutoProxyCreator`类中，并没有发现与后置处理器相关的代码了。

好了，以上就是我们分析的有关`AnnotationAwareAspectJAutoProxyCreator`类的源码。在下一篇文章中，我们开始debug调试这些源代码的具体执行流程。

**好了，今天就到这儿吧，我是冰河，大家有啥问题可以在下方留言，也可以加我微信：sun_shine_lyz，我拉你进群，一起交流技术，一起进阶，一起牛逼~~**

![](https://img-blog.csdnimg.cn/20210102235308513.jpg)

## 冰河原创PDF

关注 **冰河技术** 微信公众号：

回复 “**并发编程**” 领取《深入理解高并发编程（第1版）》PDF文档。

回复 “**并发源码**” 领取《并发编程核心知识（源码分析篇 第1版）》PDF文档。

回复 “**我要进大厂**” 领取《我要进大厂系列之面试圣经（第1版）》PDF文档。

回复 ”**限流**“ 领取《亿级流量下的分布式解决方案》PDF文档。

回复 “**设计模式**” 领取《深入浅出Java23种设计模式》PDF文档。

回复 “**Java8新特性**” 领取 《Java8新特性教程》PDF文档。

回复 “**分布式存储**” 领取《跟冰河学习分布式存储技术》 PDF文档。

回复 “**Nginx**” 领取《跟冰河学习Nginx技术》PDF文档。

回复 “**互联网工程**” 领取《跟冰河学习互联网工程技术》PDF文档。


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
