---
layout: post
category: binghe-spring-ioc
title: 第02章：使用@ComponentScan自动扫描组件并指定扫描规则
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在实际项目中，我们更多的是使用Spring的包扫描功能对项目中的包进行扫描，凡是在指定的包或子包中的类上标注了@Repository、@Service、@Controller、@Component注解的类都会被扫描到，并将这个类注入到Spring容器中。Spring包扫描功能可以使用XML文件进行配置，也可以直接使用@ComponentScan注解进行设置，使用@ComponentScan注解进行设置比使用XML文件配置要简单的多。
lock: need
---

# 《Spring注解驱动开发》第02章：使用@ComponentScan自动扫描组件并指定扫描规则

## 写在前面

> 在实际项目中，我们更多的是使用Spring的包扫描功能对项目中的包进行扫描，凡是在指定的包或子包中的类上标注了@Repository、@Service、@Controller、@Component注解的类都会被扫描到，并将这个类注入到Spring容器中。Spring包扫描功能可以使用XML文件进行配置，也可以直接使用@ComponentScan注解进行设置，使用@ComponentScan注解进行设置比使用XML文件配置要简单的多。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## 使用XML文件配置包扫描

我们可以在Spring的XML配置文件中配置包的扫描，在配置包扫描时，需要在Spring的XML文件中的beans节点中引入context标签，如下所示。

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/context
                           http://www.springframework.org/context/spring-context.xsd ">
```

接下来，我们就可以在XML文件中定义要扫描的包了，如下所示。

```xml
<context:component-scan base-package="io.mykit.spring"/>
```

整个beans.xml文件如下所示。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd
       http://www.springframework.org/schema/context
       http://www.springframework.org/schema/context.xsd">

    <context:component-scan base-package="io.mykit.spring"/>

    <bean id = "person" class="io.mykit.spring.bean.Person">
        <property name="name" value="binghe"></property>
        <property name="age" value="18"></property>
    </bean>
</beans>
```

此时，只要在io.mykit.spring包下，或者io.mykit.spring的子包下标注了@Repository、@Service、@Controller、@Component注解的类都会被扫描到，并自动注入到Spring容器中。

此时，我们分别创建PersonDao、PersonService、和PersonController类，并在这三个类中分别添加@Repository、@Service、@Controller注解，如下所示。

* PersonDao

```java
package io.mykit.spring.plugins.register.dao;

import org.springframework.stereotype.Repository;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的dao
 */
@Repository
public class PersonDao {
}
```



* PersonService

```java
package io.mykit.spring.plugins.register.service;

import org.springframework.stereotype.Service;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的Service
 */
@Service
public class PersonService {
}
```



* PersonController

```java
package io.mykit.spring.plugins.register.controller;

import org.springframework.stereotype.Controller;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的controller
 */
@Controller
public class PersonController {
}
```

接下来，我们在SpringBeanTest类中新建一个测试方法testComponentScanByXml()进行测试，如下所示。

```java
@Test
public void testComponentScanByXml(){
    ApplicationContext context = new ClassPathXmlApplicationContext("beans.xml");
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);
}
```

运行测试用例，输出的结果信息如下所示。

```bash
personConfig
personController
personDao
personService
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
person
```

可以看到，除了输出我们自己创建的bean名称之外，也输出了Spring内部使用的一些重要的bean名称。

接下来，我们使用注解来完成这些功能。

## 使用注解配置包扫描

使用@ComponentScan注解之前我们先将beans.xml文件中的下述配置注释。

```xml
<context:component-scan base-package="io.mykit.spring"></context:component-scan>
```

注释后如下所示。

```xml
<!--<context:component-scan base-package="io.mykit.spring"></context:component-scan>-->
```

使用@ComponentScan注解配置包扫描就非常Easy了！在我们的PersonConfig类上添加@ComponentScan注解，并将扫描的包指定为io.mykit.spring即可，整个的PersonConfig类如下所示。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 以注解的形式来配置Person
 */
@Configuration
@ComponentScan(value = "io.mykit.spring")
public class PersonConfig {

    @Bean("person")
    public Person person01(){
        return new Person("binghe001", 18);
    }
}
```

没错，就是这么简单，只需要在类上添加@ComponentScan(value = "io.mykit.spring")注解即可。

接下来，我们在SpringBeanTest类中新增testComponentScanByAnnotation()方法，如下所示。

```java
@Test
public void testComponentScanByAnnotation(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig.class);
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);
}
```

运行testComponentScanByAnnotation()方法输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
personController
personDao
personService
person
```

可以看到使用@ComponentScan注解同样输出了bean的名称。

既然使用XML文件和注解的方式都能够将相应的类注入到Spring容器当中，那我们是使用XML文件还是使用注解呢？我更倾向于使用注解，如果你确实喜欢使用XML文件进行配置，也可以，哈哈，个人喜好嘛！好了，我们继续。

## 关于@ComponentScan注解

我们点开ComponentScan注解类，如下所示。

```java
package org.springframework.context.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.beans.factory.support.BeanNameGenerator;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.type.filter.TypeFilter;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Repeatable(ComponentScans.class)
public @interface ComponentScan {

	@AliasFor("basePackages")
	String[] value() default {};

	@AliasFor("value")
	String[] basePackages() default {};

	Class<?>[] basePackageClasses() default {};

	Class<? extends BeanNameGenerator> nameGenerator() default BeanNameGenerator.class;

	Class<? extends ScopeMetadataResolver> scopeResolver() default AnnotationScopeMetadataResolver.class;

	ScopedProxyMode scopedProxy() default ScopedProxyMode.DEFAULT;

	String resourcePattern() default ClassPathScanningCandidateComponentProvider.DEFAULT_RESOURCE_PATTERN;

	boolean useDefaultFilters() default true;

	Filter[] includeFilters() default {};

	Filter[] excludeFilters() default {};

	boolean lazyInit() default false;

	@Retention(RetentionPolicy.RUNTIME)
	@Target({})
	@interface Filter {
		FilterType type() default FilterType.ANNOTATION;
        
		@AliasFor("classes")
		Class<?>[] value() default {};
        
		@AliasFor("value")
		Class<?>[] classes() default {};
        
		String[] pattern() default {};
	}
}
```

这里，我们着重来看ComponentScan类的两个方法，如下所示。

```java
Filter[] includeFilters() default {};
Filter[] excludeFilters() default {};
```

includeFilters()方法表示Spring扫描的时候，只包含哪些注解，而excludeFilters()方法表示不包含哪些注解。两个方法的返回值都是Filter[]数组，在ComponentScan注解类的内部存在Filter注解类，大家可以看下上面的代码。

### 1.扫描时排除注解标注的类

例如，我们现在排除@Controller、@Service和@Repository注解，我们可以在PersonConfig类上通过@ComponentScan注解的excludeFilters()实现。例如，我们在PersonConfig类上添加了如下的注解。

```java
@ComponentScan(value = "io.mykit.spring", excludeFilters = {
        @Filter(type = FilterType.ANNOTATION, classes = {Controller.class, Service.class, Repository.class})
})
```

这样，我们就使得Spring在扫描包的时候排除了使用@Controller、@Service和@Repository注解标注的类。运行SpringBeanTest类中的testComponentScanByAnnotation()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
person
```

可以看到，输出的结果信息中不再输出personController、personService和personDao说明Spring在进行包扫描时，忽略了@Controller、@Service和@Repository注解标注的类。

### 2.扫描时只包含注解标注的类

我们也可以使用ComponentScan注解类的includeFilters()来指定Spring在进行包扫描时，只包含哪些注解标注的类。

**这里需要注意的是，当我们使用includeFilters()来指定只包含哪些注解标注的类时，需要禁用默认的过滤规则。**

例如，我们需要Spring在扫描时，只包含@Controller注解标注的类，可以在PersonConfig类上添加@ComponentScan注解，设置只包含@Controller注解标注的类，并禁用默认的过滤规则，如下所示。

```java
@ComponentScan(value = "io.mykit.spring", includeFilters = {
        @Filter(type = FilterType.ANNOTATION, classes = {Controller.class})
}, useDefaultFilters = false)
```

此时，我们再次运行SpringBeanTest类的testComponentScanByAnnotation()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
personController
person
```

可以看到，在输出的结果中，只包含了@Controller注解标注的组件名称，并没有输出@Service和@Repository注解标注的组件名称。

注意：在使用includeFilters()来指定只包含哪些注解标注的类时，结果信息中会一同输出Spring内部的组件名称。

### 3.重复注解

不知道小伙伴们有没有注意到ComponentScan注解类上有一个如下所示的注解。

```java
@Repeatable(ComponentScans.class)
```

我们先来看看@ComponentScans注解是个啥，如下所示。

```java
package org.springframework.context.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
public @interface ComponentScans {
	ComponentScan[] value();
}
```

可以看到，在ComponentScans注解类中只声明了一个返回ComponentScan[]数组的value()，说到这里，大家是不是就明白了，没错，这在Java8中是一个重复注解。

> 对于Java8不熟悉的小伙伴，可以到【[Java8新特性](https://mp.weixin.qq.com/mp/appmsgalbum?action=getalbum&__biz=Mzg3MzE1NTIzNA==&scene=1&album_id=1325066823947321344#wechat_redirect)】专栏查看关于Java8新特性的文章。专栏地址小伙伴们可以猛戳下面的链接地址进行查看：
>
> [https://mp.weixin.qq.com/mp/appmsgalbum?action=getalbum&__biz=Mzg3MzE1NTIzNA==&scene=1&album_id=1325066823947321344#wechat_redirect](https://mp.weixin.qq.com/mp/appmsgalbum?action=getalbum&__biz=Mzg3MzE1NTIzNA==&scene=1&album_id=1325066823947321344#wechat_redirect)

在Java8中表示@ComponentScan注解是一个重复注解，可以在一个类上重复使用这个注解，如下所示。

```java
@Configuration
@ComponentScan(value = "io.mykit.spring", includeFilters = {
        @Filter(type = FilterType.ANNOTATION, classes = {Controller.class})
}, useDefaultFilters = false)
@ComponentScan(value = "io.mykit.spring", includeFilters = {
        @Filter(type = FilterType.ANNOTATION, classes = {Service.class})
}, useDefaultFilters = false)
public class PersonConfig {

    @Bean("person")
    public Person person01(){
        return new Person("binghe001", 18);
    }
}
```

运行SpringBeanTest类的testComponentScanByAnnotation()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
personController
personService
person
```

可以看到，同时输出了@Controller注解和@Service注解标注的组件名称。

如果使用的是Java8之前的版本，我们就不能直接在类上写多个@ComponentScan注解了。此时，我们可以在PersonConfig类上使用@ComponentScans注解，如下所示。

```java
@ComponentScans(value = {
        @ComponentScan(value = "io.mykit.spring", includeFilters = {
                @Filter(type = FilterType.ANNOTATION, classes = {Controller.class})
        }, useDefaultFilters = false),
        @ComponentScan(value = "io.mykit.spring", includeFilters = {
                @Filter(type = FilterType.ANNOTATION, classes = {Service.class})
        }, useDefaultFilters = false)
})
```

再次运行SpringBeanTest类的testComponentScanByAnnotation()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
personController
personService
person
```

与使用多个@ComponentScan注解输出的结果信息相同。

**总结：我们可以使用@ComponentScan注解来指定Spring扫描哪些包，可以使用excludeFilters()指定扫描时排除哪些组件，也可以使用includeFilters()指定扫描时只包含哪些组件。当使用includeFilters()指定只包含哪些组件时，需要禁用默认的过滤规则**

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