---
layout: post
category: binghe-spring-ioc
title: 第21章：BeanPostProcessor后置处理器浅析
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 有些小伙伴问我，学习Spring是不是不用学习到这么细节的程度啊？感觉这些细节的部分在实际工作中使用不到啊，我到底需不需要学习到这么细节的程度呢？我的答案是：有必要学习到这么细节的程度，而且是有机会、有条件一定要学！吃透Spring的原理和源码！往往拉开人与人之间差距的就是这些细节的部分，当前只要是使用Java技术栈开发的Web项目，几乎都会使用Spring框架。而且目前各招聘网站上对于Java开发的要求几乎清一色的都是熟悉或者精通Spring。所以，你，很有必要学习Spring的细节知识点。
lock: need
---

# 《Spring注解驱动开发》第21章：BeanPostProcessor后置处理器浅析

## 写在前面

> 有些小伙伴问我，学习Spring是不是不用学习到这么细节的程度啊？感觉这些细节的部分在实际工作中使用不到啊，我到底需不需要学习到这么细节的程度呢？我的答案是：有必要学习到这么细节的程度，而且是有机会、有条件一定要学！吃透Spring的原理和源码！往往拉开人与人之间差距的就是这些细节的部分，当前只要是使用Java技术栈开发的Web项目，几乎都会使用Spring框架。而且目前各招聘网站上对于Java开发的要求几乎清一色的都是熟悉或者精通Spring。所以，你，很有必要学习Spring的细节知识点。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## BeanPostProcessor后置处理器概述

首先，我们来看下BeanPostProcessor的源码，看下它到底是个什么鬼，如下所示。

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

从源码可以看出：BeanPostProcessor是一个接口，其中有两个方法，postProcessBeforeInitialization和postProcessAfterInitialization两个方法，这两个方法分别是在spring容器中的bean初始化前后执行，所以spring容器中的每一个bean对象初始化前后，都会执行BeanPostProcessor接口的实现类的这两个方法。

也就是说，**postProcessBeforeInitialization方法会在bean实例化和属性设置之后，自定义初始化方法之前被调用，而postProcessAfterInitialization方法会在自定义初始化方法之后被调用。当容器中存在多个BeanPostProcessor的实现类时，会按照它们在容器中注册的顺序执行。对于自定义BeanPostProcessor实现类，还可以让其实现Ordered接口自定义排序。**

因此我们可以在每个bean对象初始化前后，加上自己的逻辑。实现方式：自定义一个BeanPostProcessor接口的实现类MyBeanPostProcessor，然后在类MyBeanPostProcessor的postProcessBeforeInitialization和postProcessAfterInitialization方法里面写上自己的逻辑。

## BeanPostProcessor后置处理器实例

我们创建一个MyBeanPostProcessor类，实现BeanPostProcessor接口，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试BeanPostProcessor
 */
@Component
public class MyBeanPostProcessor implements BeanPostProcessor {

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("调用了postProcessBeforeInitialization方法，beanName = " + beanName + ", bean = " + bean);
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("调用了postProcessAfterInitialization，beanName = " + beanName + ", bean = " + bean);
        return bean;
    }
}
```

接下来，我们运行BeanLifeCircleTest类的testBeanLifeCircle04()方法，输出的结果信息如下所示。

```bash
调用了postProcessBeforeInitialization方法，beanName = animalConfig, bean = io.mykit.spring.plugins.register.config.AnimalConfig$$EnhancerBySpringCGLIB$$e8ab4f2e@56528192
调用了postProcessAfterInitialization，beanName = animalConfig, bean = io.mykit.spring.plugins.register.config.AnimalConfig$$EnhancerBySpringCGLIB$$e8ab4f2e@56528192
Cat类的构造方法...
调用了postProcessBeforeInitialization方法，beanName = cat, bean = io.mykit.spring.plugins.register.bean.Cat@1b1473ab
Cat的postConstruct()方法...
Cat的init()方法...
调用了postProcessAfterInitialization，beanName = cat, bean = io.mykit.spring.plugins.register.bean.Cat@1b1473ab
Cat的preDestroy()方法...
Cat的destroy()方法...
```

可以看到，postProcessBeforeInitialization方法会在bean实例化和属性设置之后，自定义初始化方法之前被调用，而postProcessAfterInitialization方法会在自定义初始化方法之后被调用。

也可以让实现Ordered接口自定义排序，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试BeanPostProcessor
 */
@Component
public class MyBeanPostProcessor implements BeanPostProcessor, Ordered {

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("调用了postProcessBeforeInitialization方法，beanName = " + beanName + ", bean = " + bean);
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("调用了postProcessAfterInitialization，beanName = " + beanName + ", bean = " + bean);
        return bean;
    }

    @Override
    public int getOrder() {
        return 3;
    }
}
```

再次运行BeanLifeCircleTest类的testBeanLifeCircle04()方法，输出的结果信息如下所示。

```bash
调用了postProcessBeforeInitialization方法，beanName = animalConfig, bean = io.mykit.spring.plugins.register.config.AnimalConfig$$EnhancerBySpringCGLIB$$b045438a@1ed1993a
调用了postProcessAfterInitialization，beanName = animalConfig, bean = io.mykit.spring.plugins.register.config.AnimalConfig$$EnhancerBySpringCGLIB$$b045438a@1ed1993a
Cat类的构造方法...
调用了postProcessBeforeInitialization方法，beanName = cat, bean = io.mykit.spring.plugins.register.bean.Cat@36c88a32
Cat的postConstruct()方法...
Cat的init()方法...
调用了postProcessAfterInitialization，beanName = cat, bean = io.mykit.spring.plugins.register.bean.Cat@36c88a32
Cat的preDestroy()方法...
Cat的destroy()方法...
```

## BeanPostProcessor后置处理器作用

后置处理器用于bean对象初始化前后进行逻辑增强。spring提供了BeanPostProcessor的很多实现类，例如AutowiredAnnotationBeanPostProcessor用于@Autowired注解的实现，AnnotationAwareAspectJAutoProxyCreator用于SpringAOP的动态代理等等。

除此之外，我们还可以自定义BeanPostProcessor的实现类，在其中写入需要的逻辑。下面以AnnotationAwareAspectJAutoProxyCreator为例，说明后置处理器是怎样工作的。我们都知道springAOP的实现原理是动态代理，最终放入容器的是代理类的对象，而不是bean本身的对象，那么spring是什么时候做到这一步的？就是在AnnotationAwareAspectJAutoProxyCreator后置处理器的postProcessAfterInitialization方法，即bean对象初始化完成之后，后置处理器会判断该bean是否注册了切面，如果是，则生成代理对象注入容器。Spring中的关键代码如下所示。

```java
/**
  * Create a proxy with the configured interceptors if the bean is
  * identified as one to proxy by the subclass.
  * @see #getAdvicesAndAdvisorsForBean
  */
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