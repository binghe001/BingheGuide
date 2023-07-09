---
layout: post
category: binghe-spring-ioc
title: 第23章：使用@PropertySource加载配置文件
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 很多小伙伴都在问：冰河，你的Spring专题更新完了吗？怎么感觉像是写了一半啊？我：没有更新完呀，整个专题预计会有70多篇。那怎么更新了一半就去写别的了呢？那是因为有很多其他的小伙伴在后台留言说：急需学习一些其他的技术，所以，临时调整的。放心，Spring专题会持续更新的！这不，今天，我们就继续更新Spring专题。不出意外的话，会一直持续更新完！！
lock: need
---

# 《Spring注解驱动开发》第23章：使用@PropertySource加载配置文件

## 写在前面

> 很多小伙伴都在问：冰河，你的Spring专题更新完了吗？怎么感觉像是写了一半啊？我：没有更新完呀，整个专题预计会有70多篇。那怎么更新了一半就去写别的了呢？那是因为有很多其他的小伙伴在后台留言说：急需学习一些其他的技术，所以，临时调整的。放心，Spring专题会持续更新的！这不，今天，我们就继续更新Spring专题。不出意外的话，会一直持续更新完！！
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## @PropertySource注解概述

@PropertySource注解是Spring 3.1开始引入的配置类注解。通过@PropertySource注解将properties配置文件中的值存储到Spring的 Environment中，Environment接口提供方法去读取配置文件中的值，参数是properties文件中定义的key值。也可以使用@Value 注解用${}占位符注入属性。

@PropertySource注解的源代码如下所示。

```java
package org.springframework.context.annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.core.io.support.PropertySourceFactory;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Repeatable(PropertySources.class)
public @interface PropertySource {
	String name() default "";
	String[] value();
	boolean ignoreResourceNotFound() default false;
	String encoding() default "";
	Class<? extends PropertySourceFactory> factory() default PropertySourceFactory.class;
}

```

从@PropertySource的源码可以看出，我们可以通过@PropertySource注解指定多个properties文件，可以使用如下形式进行指定。

```java
@PropertySource(value={"classpath:xxx.properties", "classpath:yyy.properties"})
```

细心的读者可以看到，在@PropertySource注解类的上面标注了如下的注解信息。

```java
@Repeatable(PropertySources.class)
```

看到这里，小伙伴们是不是有种恍然大悟的感觉呢？没错，我们也可以使用@PropertySources注解来指定properties配置文件。

## @PropertySources注解

首先，我们也是看下@PropertySources注解的源码，如下所示。

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
public @interface PropertySources {
	PropertySource[] value();
}
```

@PropertySources注解的源码比较简单，只有一个PropertySource[]数组类型的属性value，那我们如何使用@PropertySources注解指定配置文件呢？其实也很简单，就是使用如下所示的方式就可以了。

```java
@PropertySources(value={
    @PropertySource(value={"classpath:xxx.properties"}),
    @PropertySource(value={"classpath:yyy.properties"}),
})
```

是不是很简单呢？接下来，我们就以一个小案例来说明@PropertySource注解的用法。

## 案例准备

首先，我们在工程的src/main/resources目录下创建一个配置文件person.properties文件，文件的内容如下所示。

```bash
person.nickName=zhangsan
```

接下来，我们在Person类中新增一个字段nickName，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.beans.factory.annotation.Value;
import java.io.Serializable;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试实体类
 */
@Data
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Person implements Serializable {
    private static final long serialVersionUID = 7387479910468805194L;
    @Value("binghe")
    private String name;
    @Value("#{20-2}")
    private Integer age;
    private String nickName;
}
```

目前，我们并没有为Person类的nickName字段赋值，所以，此时Person类的nickName字段的值为空。我们运行下PropertyValueTest类的testPropertyValue01()方法来看下输出结果，如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
propertyValueConfig
person
================================
Person(name=binghe, age=18, nickName=null)
Process finished with exit code 0
```

可以看出，Person类的nickName字段的值确实输出了null。

## 使用xml文件方式获取值

如果我们需要在xml文件中获取person.properties文件中的值，则我们首先需要在Spring的xml文件中引入context名称空间，并且使用context命名空间导入person.properties文件，之后在bean的属性字段中使用如下方式将person.properties文件中的值注入到Person类的nickName字段上。

```xml
<context:property-placeholder location="classpath:person.properties" />
<bean id = "person" class="io.mykit.spring.plugins.register.bean.Person">
    <property name="name" value="binghe"></property>
    <property name="age" value="18"></property>
    <property name="nickName" value="${person.nickName}"></property>
</bean>
```

整个bean.xml文件的内容如下所示。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/context
                           http://www.springframework.org/context/spring-context.xsd ">
    
    <context:property-placeholder location="classpath:person.properties"/>
    <bean id = "person" class="io.mykit.spring.plugins.register.bean.Person">
        <property name="name" value="binghe"></property>
        <property name="age" value="18"></property>
        <property name="nickName" value="${person.nickName}"></property>
    </bean>
</beans>
```

这样就可以将person.properties文件中的值注入到Person的nickName字段上。接下来，我们在PropertyValueTest类中创建testPropertyValue02()测试方法，如下所示。

```java
@Test
public void testPropertyValue02(){
    ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext("classpath:beans.xml");
    Person person = (Person) context.getBean("person");
    System.out.println(person);
}
```

我们运行PropertyValueTest类中创建的testPropertyValue02()方法，输出的结果信息如下所示。

```bash
Person(name=binghe, age=18, nickName=zhangsan)
```

## 使用注解方式获取值

如果我们使用注解的方式该如何做呢？首先，我们需要在PropertyValueConfig配置类上添加@PropertySource注解，如下所示。

```java
package io.mykit.spring.plugins.register.config;
import io.mykit.spring.plugins.register.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试属性赋值
 */
@PropertySource(value = {"classpath:person.properties"})
@Configuration
public class PropertyValueConfig {
    @Bean
    public Person person(){
        return new Person();
    }
}
```

这里使用的`@PropertySource(value = {"classpath:person.properties"})`就相当于xml文件中使用的`<context:property-placeholder location="classpath:person.properties"/>`。

接下来，我们就可以在Person类的nickName字段上使用@Value注解来获取person.properties文件中的值了，如下所示。

```java
@Value("${person.nickName}")
private String nickName;
```

配置完成后，我们再次运行PropertyValueTest类的testPropertyValue01()方法来看下输出结果，如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
propertyValueConfig
person
================================
Person(name=binghe, age=18, nickName=zhangsan)
```

可以看到，此时Person类的nickName字段已经注入了“zhangsan”这个值。

## 使用Environment获取值

这里，我们在PropertyValueTest类中创建testPropertyValue03()方法，来使用Environment获取person.properties中的值，如下所示。

```java
@Test
public void testPropertyValue03(){
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(PropertyValueConfig.class);
    Environment environment = context.getEnvironment();
    String nickName = environment.getProperty("person.nickName");
    System.out.println(nickName);
}
```

运行PropertyValueTest类中的testPropertyValue03()方法，输出的结果信息如下所示。

```bash
zhangsan
```

可以看到，使用Environment确实能够获取到person.properties中的值。

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