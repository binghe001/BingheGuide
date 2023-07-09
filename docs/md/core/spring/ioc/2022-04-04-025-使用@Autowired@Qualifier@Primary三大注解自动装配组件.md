---
layout: post
category: binghe-spring-ioc
title: 第24章：使用三大注解自动装配组件
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 【Spring专题】停更一个多月，期间在更新其他专题的内容，不少小伙伴纷纷留言说：冰河，你【Spring专题】是不是停更了啊！其实并没有停更，只是中途有很多小伙伴留言说急需学习一些知识技能，以便于跳槽，哈哈，大家都懂得！所以，中途停更了一段时间，写了一些其他专题的文章。现在，继续更新【String专题】。
lock: need
---

# 《Spring注解驱动开发》第24章：使用三大注解自动装配组件

## 写在前面

> 【Spring专题】停更一个多月，期间在更新其他专题的内容，不少小伙伴纷纷留言说：冰河，你【Spring专题】是不是停更了啊！其实并没有停更，只是中途有很多小伙伴留言说急需学习一些知识技能，以便于跳槽，哈哈，大家都懂得！所以，中途停更了一段时间，写了一些其他专题的文章。现在，继续更新【String专题】。
>
> 关注 **冰河技术** 微信公众号，订阅更多技术干货！如果文章对你有所帮助，请不要吝惜你的点赞、在看、留言和转发，你的支持是我持续创作的最大动力！
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## 注解说明

### @Autowired注解

@Autowired 注解，可以对类成员变量、方法和构造函数进行标注，完成自动装配的工作。@Autowired 注解可以放在类，接口以及方法上。在使用@Autowired之前，我们对一个bean配置属性时，是用如下xml文件的形式进行配置的。

```xml
<property name="属性名" value=" 属性值"/>
```

@Autowired 注解的源码如下所示。

```java
package org.springframework.beans.factory.annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Target({ElementType.CONSTRUCTOR, ElementType.METHOD, ElementType.PARAMETER, ElementType.FIELD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Autowired {
	boolean required() default true;
}
```

**@Autowired 注解说明：**

（1）默认优先按照类型去容器中找对应的组件，找到就赋值；

（2）如果找到多个相同类型的组件，再将属性名称作为组件的id，到 IOC 容器中进行查找。

### @Qualifier注解

@Autowired是根据类型进行自动装配的，如果需要按名称进行装配，则需要配合@Qualifier 注解使用。

@Qualifier注解源码如下所示。

```java
package org.springframework.beans.factory.annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Qualifier {
	String value() default "";
}
```

### @Primary注解

在Spring 中使用注解，常使用@Autowired， 默认是根据类型Type来自动注入的。但有些特殊情况，对同一个接口，可能会有几种不同的实现类，而默认只会采取其中一种实现的情况下， 就可以使用@Primary注解来标注优先使用哪一个实现类。

@Primary注解的源码如下所示。

```java
package org.springframework.context.annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Primary {

}
```

## 自动装配

在进行项目实战之前，我们先来说说什么是Spring组件的自动装配。Spring组件的自动装配就是：**Spring利用依赖注入，也就是我们通常所说的DI，完成对IOC容器中各个组件的依赖关系赋值。**

## 项目实战

### 测试@Autowired注解

这里，我们以之前项目中创建的dao、service和controller为例进行说明。dao、service和controller的初始代码分别如下所示。

* dao

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

* service

```java
package io.mykit.spring.plugins.register.service;
import io.mykit.spring.plugins.register.dao.PersonDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的Service
 */
@Service
public class PersonService {
    @Autowired
    private PersonDao personDao;
}
```

* controller

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
    @Autowired
    private PersonService personService;
}
```

可以看到，我们在Service中使用@Autowired注解注入了Dao，在Controller中使用@Autowired注解注入了Service。为了方便测试，我们在PersonService类中生成一个toString()方法，如下所示。

```java
package io.mykit.spring.plugins.register.service;
import io.mykit.spring.plugins.register.dao.PersonDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的Service
 */
@Service
public class PersonService {
    @Autowired
    private PersonDao personDao;

    @Override
    public String toString() {
        return personDao.toString();
    }
}
```

这里，我们在PersonService类的toString()方法中直接调用personDao的toString()方法并返回。为了更好的演示效果，我们在项目的 `io.mykit.spring.plugins.register.config` 包下创建AutowiredConfig类，如下所示。

```java
package io.mykit.spring.plugins.register.config;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试自动装配组件的Config配置类
 */
@Configuration
@ComponentScan(value = {
        "io.mykit.spring.plugins.register.dao", 
        "io.mykit.spring.plugins.register.service", 
        "io.mykit.spring.plugins.register.controller"})
public class AutowiredConfig {

}
```

接下来，我们来测试一下上面的程序，我们在项目的src/test/java目录下的 `io.mykit.spring.test` 包下创建AutowiredTest类，如下所示。

```java
package io.mykit.spring.test;
import io.mykit.spring.plugins.register.config.AutowiredConfig;
import io.mykit.spring.plugins.register.service.PersonService;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试自动装配
 */
public class AutowiredTest {
    @Test
    public void testAutowired01(){
        //创建IOC容器
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AutowiredConfig.class);
        PersonService personService = context.getBean(PersonService.class);
        System.out.println(personService);
        context.close();
    }
}
```

测试方法比较简单，这里，我就不做过多说明了。接下来，我们运行AutowiredTest类的testAutowired01()方法，得出的输出结果信息如下所示。

```bash
io.mykit.spring.plugins.register.dao.PersonDao@10e92f8f
```

可以看到，输出了PersonDao信息。

**那么问题来了：我们在PersonService类中输出的PersonDao，和我们直接在Spring IOC容器中获取的PersonDao是不是同一个对象呢？**

我们可以在AutowiredTest类的testAutowired01()方法中添加获取PersonDao对象的方法，并输出获取到的PersonDao对象，如下所示。

```java
@Test
public void testAutowired01(){
    //创建IOC容器
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AutowiredConfig.class);
    PersonService personService = context.getBean(PersonService.class);
    System.out.println(personService);
    PersonDao personDao = context.getBean(PersonDao.class);
    System.out.println(personDao);
    context.close();
}
```

我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
io.mykit.spring.plugins.register.dao.PersonDao@10e92f8f
io.mykit.spring.plugins.register.dao.PersonDao@10e92f8f
```

可以看到，我们在PersonService类中输出的PersonDao对象和直接从IOC容器中获取的PersonDao对象是同一个对象。

**如果在Spring容器中存在对多个PersonDao对象该如何处理呢？**

首先，为了更加直观的看到我们使用@Autowired注解装配的是哪个PersonDao对象，我们对PersonDao类进行改造，为其加上一个remark字段，为其赋一个默认值，如下所示。

```java
package io.mykit.spring.plugins.register.dao;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Repository;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的dao
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Repository
public class PersonDao {
    private String remark = "1";
}
```

接下来，我们就在AutowiredConfig类中注入一个PersonDao对象，并且显示指定PersonDao对象在IOC容器中的bean的名称为personDao2，并为PersonDao对象的remark字段赋值为2，如下所示。

```java
  @Bean("personDao2")
  public PersonDao personDao(){
      return new PersonDao("2");
  }
```

目前，在我们的IOC容器中就会注入两个PersonDao对象。那此时，**@Autowired注解装配的是哪个PersonDao对象呢？**

接下来，我们运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonDao{remark='1'}
```

可以看到，结果信息输出了1，说明：**@Autowired注解默认优先按照类型去容器中找对应的组件，找到就赋值；如果找到多个相同类型的组件，再将属性名称作为组件的id，到 IOC 容器中进行查找。**

**那我们如何让@Autowired装配personDao2呢？** 这个问题问的好，其实很简单，我们将PersonService类中的personDao全部修改为personDao2，如下所示。

```java
package io.mykit.spring.plugins.register.service;
import io.mykit.spring.plugins.register.dao.PersonDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的Service
 */
@Service
public class PersonService {
    @Autowired
    private PersonDao personDao2;
    @Override
    public String toString() {
        return personDao2.toString();
    }
}
```

此时，我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonDao{remark='2'}
```

可以看到，此时命令行输出了personDao2的信息。

### 测试@Qualifier注解

从测试@Autowired注解的结果来看：**@Autowired注解默认优先按照类型去容器中找对应的组件，找到就赋值；如果找到多个相同类型的组件，再将属性名称作为组件的id，到 IOC 容器中进行查找。** 

如果IOC容器中存在多个相同类型的组件时，我们可不可以显示指定@Autowired注解装配哪个组件呢？有些小伙伴肯定会说：废话！你都这么问了，那肯定可以啊！没错，确实可以啊！此时，@Qualifier注解就派上用场了！

在之前的测试案例中，命令行输出了 `PersonDao{remark='2'}` 说明@Autowired注解装配了personDao2，那我们如何显示的让@Autowired注解装配personDao呢？

比较简单，我们只需要在PersonService类上personDao2字段上添加@Qualifier注解，显示指定@Autowired注解装配personDao，如下所示。

```java
@Qualifier("personDao")
@Autowired
private PersonDao personDao2;
```

此时，我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonDao{remark='1'}
```

可以看到，此时尽管字段的名称为personDao2，但是我们使用了@Qualifier注解显示指定@Autowired注解装配personDao对象，所以，最终的结果输出了personDao对象的信息。

### 测试容器中无组件的情况

如果IOC容器中无相应的组件，会发生什么情况呢？此时，我们删除PersonDao类上的@Repository注解，并且删除AutowiredConfig类中的personDao()方法上的@Bean注解，如下所示。

```java
package io.mykit.spring.plugins.register.dao;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的dao
 */
public class PersonDao {
    private String remark = "1";

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }

    @Override
    public String toString() {
        return "PersonDao{" +
                "remark='" + remark + '\'' +
                '}';
    }
}
```

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.plugins.register.dao.PersonDao;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试自动装配组件的Config配置类
 */
@Configuration
@ComponentScan(value = {
        "io.mykit.spring.plugins.register.dao",
        "io.mykit.spring.plugins.register.service",
        "io.mykit.spring.plugins.register.controller"})
public class AutowiredConfig {
    public PersonDao personDao(){
        PersonDao personDao = new PersonDao();
        personDao.setRemark("2");
        return personDao;
    }
}
```

此时IOC容器中不再有personDao，我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
Caused by: org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type 'io.mykit.spring.plugins.register.dao.PersonDao' available: expected at least 1 bean which qualifies as autowire candidate. Dependency annotations: {@org.springframework.beans.factory.annotation.Qualifier(value=personDao), @org.springframework.beans.factory.annotation.Autowired(required=true)}
```

可以看到，Spring抛出了异常，未找到相应的bean对象，**我们能不能让Spring不报错呢？** 那肯定可以啊！Spring的异常信息中都给出了相应的提示。

```bash
{@org.springframework.beans.factory.annotation.Qualifier(value=personDao), @org.springframework.beans.factory.annotation.Autowired(required=true)}
```

解决方案就是在PersonService类的@Autowired添加一个属性`required=false`，如下所示。

```java
@Qualifier("personDao")
@Autowired(required = false)
private PersonDao personDao2;
```

并且我们修改下PersonService的toString()方法，如下所示。

```java
@Override
public String toString() {
    return "PersonService{" +
        "personDao2=" + personDao2 +
        '}';
}
```

此时，还需要将AutowiredTest类的testAutowired01()方法中直接从IOC容器中获取personDao的代码删除，如下所示。

```java
@Test
public void testAutowired01(){
    //创建IOC容器
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AutowiredConfig.class);
    PersonService personService = context.getBean(PersonService.class);
    System.out.println(personService);
    context.close();
}
```

此时，我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonService{personDao2=null}
```

可以看到，当为@Autowired添加属性`required=false`后，即使IOC容器中没有对应的对象，Spring也不会抛出异常。此时，装配的对象就为null。

测试完成后，我们再次为PersonDao类添加@Repository注解，并且为AutowiredConfig类中的personDao()方法添加@Bean注解。

### 测试@Primary注解

在Spring中，对同一个接口，可能会有几种不同的实现类，而默认只会采取其中一种实现的情况下， 就可以使用@Primary注解来标注优先使用哪一个实现类。

首先，我们在AutowiredConfig类的personDao()方法上添加@Primary注解，此时，我们需要删除PersonService类中personDao字段上的@Qualifier注解，这是因为@Qualifier注解为显示指定装配哪个组件，如果使用了@Qualifier注解，无论是否使用了@Primary注解，都会装配@Qualifier注解标注的对象。

设置完成后，我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```java
PersonService{personDao2=PersonDao{remark='2'}}
```

可以看到，此时remark的值为2，装配了AutowiredConfig类中注入的personDao。

接下来，我们为PersonService类中personDao字段再次添加@Qualifier注解，如下所示。

```java
@Qualifier("personDao")
@Autowired(required = false)
private PersonDao personDao;
```

此时，我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonService{personDao=PersonDao{remark='1'}}
```

可以看到，此时，Spring装配了使用@Qualifier标注的personDao。

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

