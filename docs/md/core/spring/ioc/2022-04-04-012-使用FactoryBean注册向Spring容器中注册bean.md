---
layout: post
category: binghe-spring-ioc
title: 第11章：使用FactoryBean向Spring容器中注册bean
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在前面的文章中，我们知道可以通过多种方式向Spring容器中注册bean。可以使用@Configuration结合@Bean向Spring容器中注册bean；可以按照条件向Spring容器中注册bean；可以使用@Import向容器中快速导入bean对象；可以在@Import中使用ImportBeanDefinitionRegistrar向容器中注册bean。
lock: need
---

# 《Spring注解驱动开发》第11章：使用FactoryBean向Spring容器中注册bean

## 写在前面

> 在前面的文章中，我们知道可以通过多种方式向Spring容器中注册bean。可以使用@Configuration结合@Bean向Spring容器中注册bean；可以按照条件向Spring容器中注册bean；可以使用@Import向容器中快速导入bean对象；可以在@Import中使用ImportBeanDefinitionRegistrar向容器中注册bean。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## FactoryBean概述

一般情况下，Spring通过反射机制利用bean的class属性指定实现类来实例化bean 。在某些情况下，实例化bean过程比较复杂，如果按照传统的方式，则需要在<bean>标签中提供大量的配置信息，配置方式的灵活性是受限的，这时采用编码的方式可以得到一个更加简单的方案。Spring为此提供了一个org.springframework.bean.factory.FactoryBean的工厂类接口，用户可以通过实现该接口定制实例化bean的逻辑。

FactoryBean接口对于Spring框架来说占有重要的地位，Spring 自身就提供了70多个FactoryBean的实现。它们隐藏了实例化一些复杂bean的细节，给上层应用带来了便利。从Spring 3.0 开始， FactoryBean开始支持泛型，即接口声明改为FactoryBean<T> 的形式：

在Spring 5.2.6版本中，FactoryBean接口的定义如下所示。

```java
package org.springframework.beans.factory;
import org.springframework.lang.Nullable;

public interface FactoryBean<T> {

	String OBJECT_TYPE_ATTRIBUTE = "factoryBeanObjectType";

	@Nullable
	T getObject() throws Exception;

	@Nullable
	Class<?> getObjectType();

	default boolean isSingleton() {
		return true;
	}
}
```

* T getObject()：返回由FactoryBean创建的bean实例，如果isSingleton()返回true，则该实例会放到Spring容器中单实例缓存池中。

* boolean isSingleton()：返回由FactoryBean创建的bean实例的作用域是singleton还是prototype。

* Class<T> getObjectType()：返回FactoryBean创建的bean类型。

**这里，需要注意的是：当配置文件中<bean>标签的class属性配置的实现类是FactoryBean时，通过 getBean()方法返回的不是FactoryBean本身，而是FactoryBean#getObject()方法所返回的对象，相当于FactoryBean#getObject()代理了getBean()方法。**

## FactoryBean实例

首先，创建一个PersonFactoryBean，实现FactoryBean接口，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.factory.FactoryBean;
/**
 * @author binghe
 * @version 1.0.0
 * @description 商品的FactoryBean，测试FactoryBean
 */
public class PersonFactoryBean implements FactoryBean<Person> {

    //返回一个Person对象，这个对象会被注册到Spring容器中
    @Override
    public Person getObject() throws Exception {
        return new Person();
    }

    @Override
    public Class<?> getObjectType() {
        return Person.class;
    }

    //bean是否为单例;true:是；false:否
    @Override
    public boolean isSingleton() {
        return true;
    }
}
```

接下来，我们在PersonConfig2类中加入PersonFactoryBean的声明，如下所示。

```java
@Bean
public PersonFactoryBean personFactoryBean(){
    return new PersonFactoryBean();
}
```

这里需要小伙伴们注意的是：我在这里使用@Bean注解向Spring容器中添加的是PersonFactory对象。那我们就来看看Spring容器中有哪些bean。接下来，运行SpringBeanTest类中的testAnnotationConfig7()方法，输出的结果信息如下所示。

```java
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
personFactoryBean
company
```

可以看到，结果信息中输出了一个personFactoryBean，我们看下这个personFactoryBean到底是个什么鬼！此时，我们对SpringBeanTest类中的testAnnotationConfig7()方法稍加改动，添加获取personFactoryBean的代码，并输出personFactoryBean实例的类型，如下所示。

```java
@Test
public void testAnnotationConfig7(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig2.class);
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);

    Object personFactoryBean = context.getBean("personFactoryBean");
    System.out.println("personFactoryBean实例的类型为：" + personFactoryBean.getClass());
}
```

再次运行SpringBeanTest类中的testAnnotationConfig7()方法，输出的结果信息如下所示。

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
personFactoryBean
company
personFactoryBean实例的类型为：class io.mykit.spring.plugins.register.bean.Person
```

可以看到，虽然我在代码中使用@Bean注解注入的PersonFactoryBean对象，但是，实际上从Spring容器中获取到的bean对象却是调用PersonFactoryBean类中的getObject()获取到的Person对象。

**看到这里，是不是有种豁然开朗的感觉！！！**

在PersonFactoryBean类中，我们将Person对象设置为单实例bean，接下来，我们在SpringBeanTest类中的testAnnotationConfig7()方法多次获取Person对象，并输出多次获取的对象是否为同一对象，如下所示。

```java
@Test
public void testAnnotationConfig7(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig2.class);
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);

    Object personFactoryBean1 = context.getBean("personFactoryBean");
    Object personFactoryBean2 = context.getBean("personFactoryBean");
    System.out.println(personFactoryBean1 == personFactoryBean2);
}
```

运行testAnnotationConfig7()方法输出的结果信息如下所示。

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
personFactoryBean
company
true
```

可以看到，在PersonFactoryBean类的isSingleton()方法中返回true时，每次获取到的Person对象都是同一个对象，说明Person对象是单实例bean。

这里，可能就会有小伙伴要问了，如果将Person对象修改成多实例bean呢？别急，这里我们只需要在PersonFactoryBean类的isSingleton()方法中返回false，即可将Person对象设置为多实例bean，如下所示。

```java
//bean是否为单例;true:是；false:否
@Override
public boolean isSingleton() {
    return false;
}
```

再次运行SpringBeanTest类中的testAnnotationConfig7()方法，输出的结果信息如下所示。

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
personFactoryBean
company
false
```

可以看到，最终结果返回了false，说明此时Person对象是多实例bean。

## 如何在Spring容器中获取到FactoryBean对象？

之前，我们使用@Bean注解向Spring容器中注册的PersonFactoryBean，获取出来的确实Person对象。那么，小伙伴们可能会问：我就想获取PersonFactoryBean实例，该怎么办呢？

其实，这也很简单， **只需要在获取bean对象时，在id前面加上&符号即可**。

打开我们的测试类SpringBeanTest，在testAnnotationConfig7()方法中添加获取PersonFactoryBean实例的代码，如下所示。

```java
@Test
public void testAnnotationConfig7(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig2.class);
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);

    Object personFactoryBean1 = context.getBean("personFactoryBean");
    Object personFactoryBean2 = context.getBean("personFactoryBean");
    System.out.println("personFactoryBean1类型：" + personFactoryBean1.getClass());
    System.out.println("personFactoryBean2类型：" + personFactoryBean2.getClass());
    System.out.println(personFactoryBean1 == personFactoryBean2);

    Object personFactoryBean3 = context.getBean("&personFactoryBean");
    System.out.println("personFactoryBean3类型：" + personFactoryBean3.getClass());
}
```

运行SpringBeanTest类中的testAnnotationConfig7()方法，输出的结果信息如下所示。

```java
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
personFactoryBean
company
personFactoryBean1类型：class io.mykit.spring.plugins.register.bean.Person
personFactoryBean2类型：class io.mykit.spring.plugins.register.bean.Person
false
personFactoryBean3类型：class io.mykit.spring.plugins.register.bean.PersonFactoryBean
```

可以看到，在获取bean时，在id前面加上&符号就会获取到PersonFactoryBean实例对象。

那问题又来了！！**为什么在id前面加上&符号就会获取到PersonFactoryBean实例对象呢？**

接下来，我们就揭开这个神秘的面纱，打开BeanFactory接口，

```java
package org.springframework.beans.factory;
import org.springframework.beans.BeansException;
import org.springframework.core.ResolvableType;
import org.springframework.lang.Nullable;

public interface BeanFactory {
	String FACTORY_BEAN_PREFIX = "&";
    /**************以下省略n行代码***************/
}
```

看到这里，是不是明白了呢？没错，在BeanFactory接口中定义了一个&前缀，只要我们使用bean的id来从Spring容器中获取bean时，Spring就会知道我们是在获取FactoryBean本身。

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