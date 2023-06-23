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

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)