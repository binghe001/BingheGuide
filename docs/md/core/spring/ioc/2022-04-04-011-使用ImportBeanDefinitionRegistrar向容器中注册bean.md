---
layout: post
category: binghe-spring-ioc
title: 第10章：在@Import注解中使用ImportBeanDefinitionRegistrar向容器中注册bean
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在前面的文章中，我们学习了如何使用@Import注解向Spring容器中导入bean，可以使用@Import注解快速向容器中导入bean，小伙伴们可以参见《[【Spring注解驱动开发】使用@Import注解给容器中快速导入一个组件](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484863&idx=1&sn=faca9edb10665d357089a290220ede2f&chksm=cee51a72f992936430364b018e07f062c2cb4bbe7111d0b615a1937215170976e5caf23a227b&token=1611686244&lang=zh_CN#rd)》。可以在@Import注解中使用ImportSelector接口导入bean，小伙伴们可以参见《[【Spring注解驱动开发】在@Import注解中使用ImportSelector接口导入bean](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484870&idx=1&sn=a371224a8c2b9f70a41ff88976d6b0e6&chksm=cee51a0bf992931d3e39ddf70061ac8de713c817ec6561075a740eb18c7269ce66d50459dd58&token=1611686244&lang=zh_CN#rd)》一文。今天，我们就来说说，如何在@Import注解中使用ImportBeanDefinitionRegistrar向容器中注册bean。
lock: need
---

# 《Spring注解驱动开发》第10章：在@Import注解中使用ImportBeanDefinitionRegistrar向容器中注册bean

## 写在前面

> 在前面的文章中，我们学习了如何使用@Import注解向Spring容器中导入bean，可以使用@Import注解快速向容器中导入bean，小伙伴们可以参见《[【Spring注解驱动开发】使用@Import注解给容器中快速导入一个组件](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484863&idx=1&sn=faca9edb10665d357089a290220ede2f&chksm=cee51a72f992936430364b018e07f062c2cb4bbe7111d0b615a1937215170976e5caf23a227b&token=1611686244&lang=zh_CN#rd)》。可以在@Import注解中使用ImportSelector接口导入bean，小伙伴们可以参见《[【Spring注解驱动开发】在@Import注解中使用ImportSelector接口导入bean](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484870&idx=1&sn=a371224a8c2b9f70a41ff88976d6b0e6&chksm=cee51a0bf992931d3e39ddf70061ac8de713c817ec6561075a740eb18c7269ce66d50459dd58&token=1611686244&lang=zh_CN#rd)》一文。今天，我们就来说说，如何在@Import注解中使用ImportBeanDefinitionRegistrar向容器中注册bean。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## ImportBeanDefinitionRegistrar概述

### 概述

我们先来看看ImportBeanDefinitionRegistrar是个什么鬼，点击进入ImportBeanDefinitionRegistrar源码，如下所示。

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

}
```

由源码可以看出，ImportBeanDefinitionRegistrar本质上是一个接口。在ImportBeanDefinitionRegistrar接口中，有一个registerBeanDefinitions()方法，通过registerBeanDefinitions()方法，我们可以向Spring容器中注册bean实例。

Spring官方在动态注册bean时，大部分套路其实是使用ImportBeanDefinitionRegistrar接口。

所有实现了该接口的类都会被ConfigurationClassPostProcessor处理，ConfigurationClassPostProcessor实现了BeanFactoryPostProcessor接口，所以ImportBeanDefinitionRegistrar中动态注册的bean是优先于依赖其的bean初始化的，也能被aop、validator等机制处理。

### 使用方法

ImportBeanDefinitionRegistrar需要配合@Configuration和@Import注解，@Configuration定义Java格式的Spring配置文件，@Import注解导入实现了ImportBeanDefinitionRegistrar接口的类。

## ImportBeanDefinitionRegistrar实例

既然ImportBeanDefinitionRegistrar是一个接口，那我们就创建一个MyImportBeanDefinitionRegistrar类，实现ImportBeanDefinitionRegistrar接口，如下所示。

```java
package io.mykit.spring.plugins.register.condition;

import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;

/**
 * @author binghe
 * @version 1.0.0
 * @description ImportBeanDefinitionRegistrar的实现类
 */
public class MyImportBeanDefinitionRegistrar implements ImportBeanDefinitionRegistrar {

    /**
     * AnnotationMetadata: 当前类的注解信息
     * BeanDefinitionRegistry：BeanDefinition注册类
     * 通过调用BeanDefinitionRegistry接口的registerBeanDefinition()方法，可以将所有需要添加到容器中的bean注入到容器中。
     */
    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry){

    }
}
```

可以看到，这里，我们先创建了MyImportBeanDefinitionRegistrar类的大体框架。接下来，我们在PersonConfig2类上的@Import注解中，添加MyImportBeanDefinitionRegistrar类，如下所示。

```java
@Configuration
@Import({Department.class, Employee.class, MyImportSelector.class, MyImportBeanDefinitionRegistrar.class})
public class PersonConfig2 {
```

接下来，创建一个Company类，作为测试测试ImportBeanDefinitionRegistrar接口的bean，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试ImportBeanDefinitionRegistrar接口的使用
 */
public class Company {
}
```

接下来，就要实现MyImportBeanDefinitionRegistrar类中的registerBeanDefinitions()方法的逻辑了，添加逻辑后的registerBeanDefinitions()方法如下所示。

```java
    /**
     * AnnotationMetadata: 当前类的注解信息
     * BeanDefinitionRegistry：BeanDefinition注册类
     * 通过调用BeanDefinitionRegistry接口的registerBeanDefinition()方法，可以将所有需要添加到容器中的bean注入到容器中。
     */
    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry){
        boolean employee = registry.containsBeanDefinition("employee");
        boolean department = registry.containsBeanDefinition("department");
        if (employee && department){
            BeanDefinition beanDefinition = new RootBeanDefinition(Company.class);
            registry.registerBeanDefinition("company", beanDefinition);
        }
    }
```

registerBeanDefinitions()方法的实现逻辑很简单，就是判断Spring容器中是否同时存在以employee命名的bean和以department命名的bean，如果同时存在以employee命名的bean和以department命名的bean，则向Spring容器中注入一个以company命名的bean。

接下来，我们就运行SpringBeanTest类中的testAnnotationConfig7()方法来进行测试，输出结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig2
io.mykit.spring.plugins.register.bean.Department
io.mykit.spring.plugins.register.bean.Employee
io.mykit.spring.plugins.register.bean.User
io.mykit.spring.plugins.register.bean.Role
person
binghe001
```

可以看到，在输出结果中，并没有看到“company”，这是因为输出结果中存在io.mykit.spring.plugins.register.bean.Department和io.mykit.spring.plugins.register.bean.Employee，并不存在我们代码逻辑中的department和employee。所以，我们将registerBeanDefinitions()方法的逻辑稍微修改下，修改后的代码如下所示。

```java
/**
  * AnnotationMetadata: 当前类的注解信息
  * BeanDefinitionRegistry：BeanDefinition注册类
  * 通过调用BeanDefinitionRegistry接口的registerBeanDefinition()方法，可以将所有需要添加到容器中的bean注入到容器中。
  */
@Override
public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry){
    boolean employee = registry.containsBeanDefinition(Employee.class.getName());
    boolean department = registry.containsBeanDefinition(Department.class.getName());
    if (employee && department){
        BeanDefinition beanDefinition = new RootBeanDefinition(Company.class);
        registry.registerBeanDefinition("company", beanDefinition);
    }
}
```

接下来，我们再次运行SpringBeanTest类中的testAnnotationConfig7()方法来进行测试，输出结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig2
io.mykit.spring.plugins.register.bean.Department
io.mykit.spring.plugins.register.bean.Employee
io.mykit.spring.plugins.register.bean.User
io.mykit.spring.plugins.register.bean.Role
person
binghe001
company
```

可以看到，此时输出了company，说明Spring容器中已经成功注册了以company命名的bean。

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