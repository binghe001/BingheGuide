---
layout: post
category: binghe-spring-ioc
title: 第32章：@EnableAspectJAutoProxy注解原理
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 最近，二狗子入职了新公司，新入职的那几天确实有点飘。不过慢慢的，他发现他身边的人各个身怀绝技啊，有Spring源码的贡献者，有Dubbo源码的贡献者，有MyBatis源码的贡献者，还有研究AI的大佬，个个都是大神级别的人物。二狗子有点慌，想起自己虽然入职了，但是比起其他人确实差点远啊。怎么办呢？先从基础补起呗，他发现自己对于Spring的理解还不算太深。于是乎，他让我给他讲讲Spring的@EnableAspectJAutoProxy注解。
lock: need
---

# 《Spring注解驱动开发》第32章：@EnableAspectJAutoProxy注解原理

## 写在前面

> 最近，二狗子入职了新公司，新入职的那几天确实有点飘。不过慢慢的，他发现他身边的人各个身怀绝技啊，有Spring源码的贡献者，有Dubbo源码的贡献者，有MyBatis源码的贡献者，还有研究AI的大佬，个个都是大神级别的人物。二狗子有点慌，想起自己虽然入职了，但是比起其他人确实差点远啊。怎么办呢？先从基础补起呗，他发现自己对于Spring的理解还不算太深。于是乎，他让我给他讲讲Spring的@EnableAspectJAutoProxy注解。
>
> 好吧，二狗子要请我吃饭啊！关注 **冰河技术** 微信公众号，后台回复“Spring注解”领取工程源码。
>
> 如果文章对你有点帮助，请点个赞，给个在看和转发，大家的三连是我持续创作的最大动力！

## @EnableAspectJAutoProxy注解

在配置类上添加@EnableAspectJAutoProxy注解，能够开启注解版的AOP功能。也就是说，AOP中如果要使注解版的AOP功能起作用，就需要在配置类上添加@EnableAspectJAutoProxy注解。  我们先来看下@EnableAspectJAutoProxy注解的源码，如下所示。

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

从源码可以看出，@EnableAspectJAutoProxy使用@Import注解引入了AspectJAutoProxyRegister.class对象 。那么，AspectJAutoProxyRegistrar又是什么呢？我们继续点击到AspectJAutoProxyRegistrar类的源码中，如下所示。

```java
package org.springframework.context.annotation;
import org.springframework.aop.config.AopConfigUtils;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
class AspectJAutoProxyRegistrar implements ImportBeanDefinitionRegistrar {
	@Override
	public void registerBeanDefinitions(
			AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {

		AopConfigUtils.registerAspectJAnnotationAutoProxyCreatorIfNecessary(registry);

		AnnotationAttributes enableAspectJAutoProxy =
				AnnotationConfigUtils.attributesFor(importingClassMetadata, EnableAspectJAutoProxy.class);
		if (enableAspectJAutoProxy != null) {
			if (enableAspectJAutoProxy.getBoolean("proxyTargetClass")) {
				AopConfigUtils.forceAutoProxyCreatorToUseClassProxying(registry);
			}
			if (enableAspectJAutoProxy.getBoolean("exposeProxy")) {
				AopConfigUtils.forceAutoProxyCreatorToExposeProxy(registry);
			}
		}
	}
}
```

可以看到AspectJAutoProxyRegistrar类实现了ImportBeanDefinitionRegistrar接口。看下ImportBeanDefinitionRegistrar接口的定义，如下所示。

```java
package org.springframework.context.annotation;

import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.BeanNameGenerator;
import org.springframework.core.type.AnnotationMetadata;
public interface ImportBeanDefinitionRegistrar {

	default void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry,
			BeanNameGenerator importBeanNameGenerator) {

		registerBeanDefinitions(importingClassMetadata, registry);
	}

	default void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
	}

```

看到ImportBeanDefinitionRegistrar接口，小伙伴们是不是觉得很熟悉呢。没错，我们在【Spring注解驱动开发】专题前面的文章中介绍过。可以通过ImportBeanDefinitionRegistrar接口实现将自定义的组件添加到IOC容器中。

也就说，**@EnableAspectJAutoProxy注解使用AspectJAutoProxyRegistrar对象自定义组件，并将相应的组件添加到IOC容器中。**

## 调试Spring源码

我们在AspectJAutoProxyRegistrar类的registerBeanDefinitions()方法中设置断点，如下所示。

![001](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-001.png)

接下来，我们以debug的方法来运行AopTest类的testAop01()方法。运行后程序进入到断点位置，如下所示。

![002](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-002.png)

可以看到，程序已经暂停在断点位置，而且在IDEA的左下角显示了方法的调用栈。

在AspectJAutoProxyRegistrar类的registerBeanDefinitions()方法，首先调用AopConfigUtils类的registerAspectJAnnotationAutoProxyCreatorIfNecessary()方法来注册registry。单看registerAspectJAnnotationAutoProxyCreatorIfNecessary()方法也不难理解，字面含义就是：如果需要的话注册一个AspectJAnnotationAutoProxyCreator。

接下来，我们进入到AopConfigUtils类的registerAspectJAnnotationAutoProxyCreatorIfNecessary()方法中，如下所示。

![003](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-003.png)

在AopConfigUtils类的registerAspectJAnnotationAutoProxyCreatorIfNecessary()方法中，直接调用了重载的registerAspectJAnnotationAutoProxyCreatorIfNecessary()方法，我们继续跟代码，如下所示。

![004](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-004.png)

可以看到在重载的registerAspectJAnnotationAutoProxyCreatorIfNecessary()方法中直接调用了registerOrEscalateApcAsRequired()方法。在registerOrEscalateApcAsRequired()方法中，传入了AnnotationAwareAspectJAutoProxyCreator.class对象。

我们继续跟进代码，如下所示。

![005](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-005.png)

![006](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-006.png)

我们可以看到，在registerOrEscalateApcAsRequired()方法中，接收到的Class对象的类型为：org.springframework.aop.aspectj.annotation.AnnotationAwareAspectJAutoProxyCreator。

在registerOrEscalateApcAsRequired()方法中方法中，首先判断registry是否包含org.springframework.aop.config.internalAutoProxyCreator类型的bean。如下所示。

![007](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-007.png)

如果registry中包含org.springframework.aop.config.internalAutoProxyCreator类型的bean，则进行相应的处理，从Spring的源码来看，就是将org.springframework.aop.config.internalAutoProxyCreator类型的bean从registry中取出，并且判断cls对象的name值和apcDefinition的beanClassName值是否相等，如果不相等。则获取apcDefinition和cls的优先级，如果apcDefinition的优先级小于cls的优先级，则将apcDefinition的beanClassName设置为cls的name值。相对来说，理解起来还是比较简单的。

我们这里是第一次运行程序，不会进入到 if 条件中，我们继续看代码，如下所示。

![008](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-008.png)

这里，使用RootBeanDefinition来创建一个beanDefinition，并且将org.springframework.aop.aspectj.annotation.AnnotationAwareAspectJAutoProxyCreator的Class对象作为参数传递进来。

![009](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-009.png)

我们继续往下看代码，最终AopConfigUtils类的registerOrEscalateApcAsRequired()方法中，会通过registry调用registerBeanDefinition()方法注册组件，如下所示。

![010](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-010.png)

并且注册的bean的名称为org.springframework.aop.config.internalAutoProxyCreator。

接下来，我们继续看AspectJAutoProxyRegistrar类的registerBeanDefinitions()源码，如下所示。

![012](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-012.png)

通过AnnotationConfigUtils类的attributesFor方法来获取@EnableAspectJAutoProxy注解的信息。接下来，就是判断proxyTargetClass属性的值是否为true，如果为true则调用AopConfigUtils类的forceAutoProxyCreatorToUseClassProxying()方法；继续判断exposeProxy属性的值是否为true，如果为true则调用AopConfigUtils类的forceAutoProxyCreatorToExposeProxy()方法。

**综上，向Spring的配置类上添加@EnableAspectJAutoProxy注解后，会向IOC容器中注册AnnotationAwareAspectJAutoProxyCreator。**

接下来，我们来看下AnnotationAwareAspectJAutoProxyCreator类的结构图。

![013](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-033-013.png)

我们简单梳理下AnnotationAwareAspectJAutoProxyCreato类的核心继承关系，如下所示。

```bash
  AnnotationAwareAspectJAutoProxyCreator
       --AspectJAwareAdvisorAutoProxyCreator
         --AbstractAdvisorAutoProxyCreator
           --AbstractAutoProxyCreator
             -- ProxyProcessorSupport， SmartInstantiationAwareBeanPostProcessor
```

查看继承关系可以发现，此类实现了Aware与BeanPostProcessor接口，这两个接口都和Spring bean的初始化有关，由此推测此类主要处理方法都来自这两个接口的实现方法。同时该类也实现了order方法。

好了，二狗子说：有关AnnotationAwareAspectJAutoProxyCreator类的详细代码和执行流程我们后面再讲，他有点消化不了了。

## 重磅福利

关注「 **冰河技术** 」微信公众号，后台回复 “**设计模式**” 关键字领取《**深入浅出Java 23种设计模式**》PDF文档。回复“**Java8**”关键字领取《**Java8新特性教程**》PDF文档。回复“**限流**”关键字获取《**亿级流量下的分布式限流解决方案**》PDF文档，三本PDF均是由冰河原创并整理的超硬核教程，面试必备！！

<font color="#FF0000">**好了，今天就聊到这儿吧！别忘了点个赞，给个在看和转发，让更多的人看到，一起学习，一起进步！！**</font>

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