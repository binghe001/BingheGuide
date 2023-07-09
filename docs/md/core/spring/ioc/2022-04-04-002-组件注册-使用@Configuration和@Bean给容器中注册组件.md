---
layout: post
category: binghe-spring-ioc
title: 第01章：组件注册-使用@Configuration和@Bean给容器中注册组件
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在之前的Spring版本中，我们只能通过写XML配置文件来定义我们的Bean，XML配置不仅繁琐，而且很容易出错，稍有不慎就会导致编写的应用程序各种报错，排查半天，发现是XML文件配置不对！另外，每个项目编写大量的XML文件来配置Spring，也大大增加了项目维护的复杂度，往往很多个项目的Spring XML文件的配置大部分是相同的，只有很少量的配置不同，这也造成了配置文件上的冗余。
lock: need
---

# 《Spring注解驱动开发》第01章：组件注册-使用@Configuration和@Bean给容器中注册组件

## 写在前面

> 在之前的Spring版本中，我们只能通过写XML配置文件来定义我们的Bean，XML配置不仅繁琐，而且很容易出错，稍有不慎就会导致编写的应用程序各种报错，排查半天，发现是XML文件配置不对！另外，每个项目编写大量的XML文件来配置Spring，也大大增加了项目维护的复杂度，往往很多个项目的Spring XML文件的配置大部分是相同的，只有很少量的配置不同，这也造成了配置文件上的冗余。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## Spring IOC和DI

在Spring容器的底层，最重要的功能就是IOC和DI，也就是控制反转和依赖注入。

> IOC：控制反转,将类的对象的创建交给Spring类管理创建。
> DI：依赖注入,将类里面的属性在创建类的过程中给属性赋值。
> DI和IOC的关系：DI不能单独存在,DI需要在IOC的基础上来完成。

在Spring内部，所有的组件都会放到IOC容器中，组件之间的关系通过IOC容器来自动装配，也就是我们所说的依赖注入。接下来，我们就使用注解的方式来完成容器组件的注册、管理及依赖、注入等功能。

在介绍使用注解完成容器组件的注册、管理及依赖、注入等功能之前，我们先来看看使用XML文件是如何注入Bean的。

## 通过XML文件注入JavaBean

首先，我们在工程的io.mykit.spring.bean包下创建Person类，作为测试的JavaBean，代码如下所示。

```java
package io.mykit.spring.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
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
    private String name;
    private Integer age;
}
```

接下来，我们在工程的resources目录下创建Spring的配置文件beans.xml，通过beans.xml文件将Person类注入到Spring的IOC容器中，配置如下所示。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <bean id = "person" class="io.mykit.spring.bean.Person">
        <property name="name" value="binghe"></property>
        <property name="age" value="18"></property>
    </bean>
</beans>
```

到此，我们使用XML方式注入JavaBean就配置完成了。接下来，我们创建一个SpringBeanTest类来进行测试，这里，我使用的是Junit进行测试，测试方法如下所示。

```java
@Test
public void testXmlConfig(){
    ApplicationContext context = new ClassPathXmlApplicationContext("beans.xml");
    Person person = (Person) context.getBean("person");
    System.out.println(person);
}
```

运行testXmlConfig()方法，输出的结果信息如下。

```bash
Person(name=binghe, age=18)
```

从输出结果中，我们可以看出，Person类通过beans.xml文件的配置，已经注入到Spring的IOC容器中了。

## 通过注解注入JavaBean

通过XML文件，我们可以将JavaBean注入到Spring的IOC容器中。那使用注解又该如何实现呢？别急，其实使用注解比使用XML文件要简单的多，我们在项目的io.mykit.spring.plugins.register.config包下创建PersonConfig类，并在PersonConfig类上添加@Configuration注解来标注PersonConfig类是一个Spring的配置类，通过@Bean注解将Person类注入到Spring的IOC容器中。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 以注解的形式来配置Person
 */
@Configuration
public class PersonConfig {
     @Bean
    public Person person(){
        return new Person("binghe001", 18);
    }
}
```

没错，通过PersonConfig类我们就能够将Person类注入到Spring的IOC容器中，是不是很Nice！！主要我们在类上加上@Configuration注解，并在方法上加上@Bean注解，就能够将方法中创建的JavaBean注入到Spring的IOC容器中。

接下来，我们在SpringBeanTest类中创建一个testAnnotationConfig()方法来测试通过注解注入的Person类，如下所示。

```java
@Test
public void testAnnotationConfig(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig.class);
    Person person = context.getBean(Person.class);
    System.out.println(person);
}
```

运行testAnnotationConfig()方法，输出的结果信息如下所示。

```bash
Person(name=binghe001, age=18)
```

可以看出，通过注解将Person类注入到了Spring的IOC容器中。

到这里，我们已经明确，通过XML文件和注解两种方式都可以将JavaBean注入到Spring的IOC容器中。那么，使用注解将JavaBean注入到IOC容器中时，使用的bean的名称是什么呢？ 我们可以在testAnnotationConfig()方法中添加如下代码来获取Person类型下的注解名称。

```java
//按照类型找到对应的bean名称数组
String[] names = context.getBeanNamesForType(Person.class);
Arrays.stream(names).forEach(System.out::println);
```

完整的testAnnotationConfig()方法的代码如下所示。

```java
@Test
public void testAnnotationConfig(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig.class);
    Person person = context.getBean(Person.class);
    System.out.println(person);

    //按照类型找到对应的bean名称数组
    String[] names = context.getBeanNamesForType(Person.class);
    Arrays.stream(names).forEach(System.out::println);
}
```

运行testAnnotationConfig()方法输出的结果信息如下所示。

```bash
Person(name=binghe001, age=18)
person
```

那这里的person是啥？我们修改下PersonConfig类中的person()方法，将person()方法修改成person01()方法，如下所示。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 以注解的形式来配置Person
 */
@Configuration
public class PersonConfig {

    @Bean
    public Person person01(){
        return new Person("binghe001", 18);
    }
}
```

此时，我们再次运行testAnnotationConfig()方法，输出的结果信息如下所示。

```bash
Person(name=binghe001, age=18)
person01
```

看到这里，大家应该有种豁然开朗的感觉了，没错！！使用注解注入Javabean时，bean在IOC中的名称就是使用@Bean注解标注的方法名称。我们可不可以为bean单独指定名称呢？那必须可以啊！只要在@Bean注解中明确指定名称就可以了。比如下面的PersonConfig类的代码，我们将person01()方法上的@Bean注解修改成@Bean("person")注解，如下所示。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 以注解的形式来配置Person
 */
@Configuration
public class PersonConfig {

    @Bean("person")
    public Person person01(){
        return new Person("binghe001", 18);
    }
}
```

此时，我们再次运行testAnnotationConfig()方法，输出的结果信息如下所示。

```bash
Person(name=binghe001, age=18)
person
```

可以看到，此时，输出的JavaBean的名称为person。

**结论：我们在使用注解方式向Spring的IOC容器中注入JavaBean时，如果没有在@Bean注解中明确指定bean的名称，就使用当前方法的名称来作为bean的名称；如果在@Bean注解中明确指定了bean的名称，则使用@Bean注解中指定的名称来作为bean的名称。**

好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！

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