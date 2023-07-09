---
layout: post
category: binghe-spring-ioc
title: 第20章：BeanPostProcessor在Spring底层是如何使用的
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在《[【String注解驱动开发】面试官再问你BeanPostProcessor的执行流程，就把这篇文章甩给他！](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247485089&idx=1&sn=466c246a28440329d4bf3d82a2214229&chksm=cee5196cf992907a3aaa9e7bfef971328a16ceb525c8c80a34822e04955de3f423e1b8f90540&token=2101168258&lang=zh_CN#rd)》一文中，我们详细的介绍了BeanPostProcessor的执行流程。那么，BeanPostProcessor在Spring底层是如何使用的？今天，我们就一起来探讨下Spring的源码，一探BeanPostProcessor在Spring底层的使用情况。
lock: need
---

# 《Spring注解驱动开发》第20章：BeanPostProcessor在Spring底层是如何使用的

## 写在前面

> 在《[【String注解驱动开发】面试官再问你BeanPostProcessor的执行流程，就把这篇文章甩给他！](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247485089&idx=1&sn=466c246a28440329d4bf3d82a2214229&chksm=cee5196cf992907a3aaa9e7bfef971328a16ceb525c8c80a34822e04955de3f423e1b8f90540&token=2101168258&lang=zh_CN#rd)》一文中，我们详细的介绍了BeanPostProcessor的执行流程。那么，BeanPostProcessor在Spring底层是如何使用的？今天，我们就一起来探讨下Spring的源码，一探BeanPostProcessor在Spring底层的使用情况。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## BeanPostProcessor接口

我们先来看下BeanPostProcessor接口的源码，如下所示。

```java
package org.springframework.beans.factory.config;
import org.springframework.beans.BeansException;
import org.springframework.lang.Nullable;

public interface BeanPostProcessor {
    
	@Nullable
	default Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	@Nullable
	default Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}
}
```

可以看到，在BeanPostProcessor接口中，提供了两个方法：postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法。postProcessBeforeInitialization()方法会在bean初始化之前调用，postProcessAfterInitialization()方法会在bean初始化之后调用。接下来，我们就分析下BeanPostProcessor接口在Spring中的实现。

**注意：这里，我列举几个BeanPostProcessor接口在Spring中的实现类，来让大家更加清晰的理解BeanPostProcessor接口在Spring底层的应用。**

## ApplicationContextAwareProcessor类

org.springframework.context.support.ApplicationContextAwareProcessor是BeanPostProcessor接口的实现类，这个类的作用是可以向组件中注入IOC容器，大致的源码如下所示。

```java
package org.springframework.context.support;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.EmbeddedValueResolver;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.EmbeddedValueResolverAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.lang.Nullable;
import org.springframework.util.StringValueResolver;
class ApplicationContextAwareProcessor implements BeanPostProcessor {
    /****************************省略N多行代码************************/
}
```

这里，省略了源码的细节，只给出了类结构，感兴趣的小伙伴们可自行翻阅Spring源码进行查看，我这里的Spring版本为5.2.6.RELEASE。

那具体如何使用ApplicationContextAwareProcessor类向组件中注入IOC容器呢？别急，我用一个例子来说明下，相信小伙伴们看完后会有一种豁然开朗的感觉——哦，原来是它啊，我之前在项目中使用过的！

要想使用ApplicationContextAwareProcessor类向组件中注入IOC容器，我们就不得不提Spring中的另一个接口：ApplicationContextAware，如果需要向组件中注入IOC容器，可以使组件实现ApplicationContextAware接口。

例如，我们创建一个Employee类，使其实现ApplicationContextAware接口，此时，我们需要实现ApplicationContextAware接口的setApplicationContext()方法，在setApplicationContext()方法中有一个ApplicationContext类型的参数，这个就是IOC容器对象，我们可以在Employee类中定义一个ApplicationContext类型的成员变量，然后在setApplicationContext()方法中为这个成员变量赋值，此时就可以在Employee中的其他方法中使用ApplicationContext对象了，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试ApplicationContextAware
 */
@Component
public class Employee implements ApplicationContextAware {
    private ApplicationContext applicationContext;
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
```

看到这里，相信不少小伙伴们都有一种很熟悉的感觉：没错，我之前也在项目中使用过！是的，这就是BeanPostProcessor在Spring底层的一种使用场景。至于上面的案例代码为何会在setApplicationContext()方法中获取到ApplicationContext对象，这就是ApplicationContextAwareProcessor类的功劳了！

接下来，我们就深入分析下ApplicationContextAwareProcessor类。

我们先来看下ApplicationContextAwareProcessor类中对于postProcessBeforeInitialization()方法的实现，如下所示。

```java
@Override
@Nullable
public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
    if (!(bean instanceof EnvironmentAware || bean instanceof EmbeddedValueResolverAware ||
          bean instanceof ResourceLoaderAware || bean instanceof ApplicationEventPublisherAware ||
          bean instanceof MessageSourceAware || bean instanceof ApplicationContextAware)){
        return bean;
    }

    AccessControlContext acc = null;

    if (System.getSecurityManager() != null) {
        acc = this.applicationContext.getBeanFactory().getAccessControlContext();
    }

    if (acc != null) {
        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            invokeAwareInterfaces(bean);
            return null;
        }, acc);
    }
    else {
        invokeAwareInterfaces(bean);
    }

    return bean;
}
```

在bean初始化之前，首先对当前bean的类型进行判断，如果当前bean的类型不是EnvironmentAware，不是EmbeddedValueResolverAware，不是ResourceLoaderAware，不是ApplicationEventPublisherAware，不是MessageSourceAware，也不是ApplicationContextAware，则直接返回bean。如果是上面类型中的一种类型，则最终会调用invokeAwareInterfaces()方法，并将bean传递给invokeAwareInterfaces()方法。invokeAwareInterfaces()方法又是个什么鬼呢？我们继续看invokeAwareInterfaces()方法的源码，如下所示。

```java
private void invokeAwareInterfaces(Object bean) {
    if (bean instanceof EnvironmentAware) {
        ((EnvironmentAware) bean).setEnvironment(this.applicationContext.getEnvironment());
    }
    if (bean instanceof EmbeddedValueResolverAware) {
        ((EmbeddedValueResolverAware) bean).setEmbeddedValueResolver(this.embeddedValueResolver);
    }
    if (bean instanceof ResourceLoaderAware) {
        ((ResourceLoaderAware) bean).setResourceLoader(this.applicationContext);
    }
    if (bean instanceof ApplicationEventPublisherAware) {
        ((ApplicationEventPublisherAware) bean).setApplicationEventPublisher(this.applicationContext);
    }
    if (bean instanceof MessageSourceAware) {
        ((MessageSourceAware) bean).setMessageSource(this.applicationContext);
    }
    if (bean instanceof ApplicationContextAware) {
        ((ApplicationContextAware) bean).setApplicationContext(this.applicationContext);
    }
}
```

可以看到invokeAwareInterfaces()方法的源码比较简单，就是判断当前bean属于哪种接口类型，则将bean强转为哪种接口类型的对象，然后调用接口的方法，将相应的参数传递到接口的方法中。这里，我们在创建Employee类时，实现的是ApplicationContextAware接口，所以，在invokeAwareInterfaces()方法中，会执行如下的逻辑代码。

```java
if (bean instanceof ApplicationContextAware) {
    ((ApplicationContextAware) bean).setApplicationContext(this.applicationContext);
}
```

我们可以看到，此时会将this.applicationContext传递到ApplicationContextAware接口的setApplicationContext()方法中。所以，我们在Employee类中的setApplicationContext()方法中就可以直接接收到ApplicationContext对象了。

我们也可以在IDEA中通过Debug的形式来看一下程序的执行过程，此时我们在Employee类的setApplicationContext()方法上设置断点，如下所示。

![001](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-021-001.png)

接下来，我们以Debug的方式来运行SpringBeanTest类的testAnnotationConfig2()方法，运行后的效果如下图所示。

![002](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-021-002.png)

在IDEA的左下角可以看到方法的调用堆栈，通过对方法调用栈的分析，我们看到在执行Employee类中的setApplicationContext()方法之前，执行了ApplicationContextAwareProcessor类的invokeAwareInterfaces方法，如下所示。

![003](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-021-003.png)

当我们点击方法调用栈中的invokeAwareInterfaces()方法时，代码的执行定位到如下一行代码。

```java
((ApplicationContextAware) bean).setApplicationContext(this.applicationContext);
```

和我们之前分析的逻辑一致。

## BeanValidationPostProcessor类

org.springframework.validation.beanvalidation.BeanValidationPostProcessor类主要是用来为bean进行校验操作，当我们创建bean，并为bean赋值后，我们可以通过BeanValidationPostProcessor类为bean进行校验操作。BeanValidationPostProcessor类的结构如下所示。

```java
package org.springframework.validation.beanvalidation;

import java.util.Iterator;
import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

public class BeanValidationPostProcessor implements BeanPostProcessor, InitializingBean {
    /*******************************省略N行代码**********************************/
}
```

这里，我们也来看看postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法的实现，如下所示。

```java
@Override
public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
    if (!this.afterInitialization) {
        doValidate(bean);
    }
    return bean;
}

@Override
public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
    if (this.afterInitialization) {
        doValidate(bean);
    }
    return bean;
}
```

可以看到，在postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法中的主要逻辑都是调用doValidate()方法对bean进行校验，只不过在两个方法中都会对afterInitialization这个boolean类型的成员变量进行判断，如果afterInitialization的值为false，则在postProcessBeforeInitialization()方法中调用doValidate()方法对bean进行校验；如果afterInitialization的值为true，则在postProcessAfterInitialization()方法中调用doValidate()方法对bean进行校验。

## InitDestroyAnnotationBeanPostProcessor类

org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor类主要用来处理@PostConstruct注解和@PreDestroy注解。

例如，我们之前创建的Cat类中就使用了@PostConstruct注解和@PreDestroy注解，如下所示。

```java
package io.mykit.spring.plugins.register.bean;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试@PostConstruct注解和@PreDestroy注解
 */
public class Cat {

    public Cat(){
        System.out.println("Cat类的构造方法...");
    }

    public void init(){
        System.out.println("Cat的init()方法...");
    }

    @PostConstruct
    public void postConstruct(){
        System.out.println("Cat的postConstruct()方法...");
    }

    @PreDestroy
    public void preDestroy(){
        System.out.println("Cat的preDestroy()方法...");
    }

    public void destroy(){
        System.out.println("Cat的destroy()方法...");
    }
}
```

那么，在Cat类中使用了 @PostConstruct注解和@PreDestroy注解来标注方法，Spring怎么就知道什么时候执行 @PostConstruct注解标注的方法，什么时候执行@PreDestroy标注的方法呢？这就要归功于InitDestroyAnnotationBeanPostProcessor类的实现了。

接下来，我们也通过Debug的方式来跟进下代码的执行流程。首先，在Cat类的postConstruct()方法上打上断点，如下所示。

![004](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-021-004.png)

接下来，我们以Debug的方式运行BeanLifeCircleTest类的testBeanLifeCircle04()方法，效果如下所示。

![005](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-021-005.png)

我们还是带着问题来分析，Spring怎么就能定位到使用@PostConstruct注解标注的方法呢？通过分析方法的调用栈我们发现了在进入使用@PostConstruct注解标注的方法之前，Spring调用了InitDestroyAnnotationBeanPostProcessor类的postProcessBeforeInitialization()方法，如下所示。

![006](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-021-006.png)

在InitDestroyAnnotationBeanPostProcessor类的postProcessBeforeInitialization()方法中，首先会找到bean中有关生命周期的注解，比如@PostConstruct注解等，找到这些注解之后，则将这些信息赋值给LifecycleMetadata类型的变量metadata，之后调用metadata的invokeInitMethods()方法，通过反射来调用标注了@PostConstruct注解的方法。这就是为什么标注了@PostConstruct注解的方法被Spring执行。

## AutowiredAnnotationBeanPostProcessor类

org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor类主要是用于处理标注了@Autowired注解的变量或方法。

Spring为何能够自动处理标注了@Autowired注解的变量或方法，就交给小伙伴们自行分析了。大家可以写一个测试方法并通过方法调用堆栈来分析AutowiredAnnotationBeanPostProcessor类的源码，从而找到自己想要的答案。

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

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