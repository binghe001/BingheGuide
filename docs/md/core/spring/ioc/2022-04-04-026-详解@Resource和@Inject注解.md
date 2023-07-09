---
layout: post
category: binghe-spring-ioc
title: 第25章：详解@Resource和@Inject注解
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 我在 **冰河技术** 微信公众号中发表的《[【Spring注解驱动开发】使用@Autowired@Qualifier@Primary三大注解自动装配组件，你会了吗？](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247486002&idx=1&sn=9e42ec6586363d6ab1e61beb14ee3322&chksm=cee515fff9929ce951a597f0cdb0bb04a615aef1287cac954645cdfd551518c0169350cd846e&token=1511192793&lang=zh_CN#rd)》一文中，介绍了如何使用@Autowired、@Qualifier和@Primary注解自动装配Spring组件。那除了这三个注解以外，还有没有其他的注解可以自动装配组件呢？那必须有啊！今天，我们就一起说说@Resource注解和@Inject注解。
lock: need
---

# 《Spring注解驱动开发》第25章：详解@Resource和@Inject注解

## 写在前面

> 我在 **冰河技术** 微信公众号中发表的《[【Spring注解驱动开发】使用@Autowired@Qualifier@Primary三大注解自动装配组件，你会了吗？](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247486002&idx=1&sn=9e42ec6586363d6ab1e61beb14ee3322&chksm=cee515fff9929ce951a597f0cdb0bb04a615aef1287cac954645cdfd551518c0169350cd846e&token=1511192793&lang=zh_CN#rd)》一文中，介绍了如何使用@Autowired、@Qualifier和@Primary注解自动装配Spring组件。那除了这三个注解以外，还有没有其他的注解可以自动装配组件呢？那必须有啊！今天，我们就一起说说@Resource注解和@Inject注解。
>
> 关注 **冰河技术** 微信公众号，回复 “Spring注解”关键字领取源码工程。

## @Resource注解

@Resource（这个注解属于J2EE的，JSR250），默认安照名称进行装配，名称可以通过name属性进行指定， 如果没有指定name属性，当注解写在字段上时，默认取字段名进行按照名称查找，如果注解写在setter方法上默认取属性名进行装配。 当找不到与名称匹配的bean时才按照类型进行装配。但是需要注意的是，如果name属性一旦指定，就只会按照名称进行装配。

@Resource注解的源码如下所示。

```java
package javax.annotation;
import java.lang.annotation.*;
import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;
@Target({TYPE, FIELD, METHOD})
@Retention(RUNTIME)
public @interface Resource {
    String name() default "";
    String lookup() default "";
    Class<?> type() default java.lang.Object.class;
    enum AuthenticationType {
            CONTAINER,
            APPLICATION
    }
    AuthenticationType authenticationType() default AuthenticationType.CONTAINER;
    boolean shareable() default true;
    String mappedName() default "";
    String description() default "";
}
```

## @Inject注解

@Inject注解（JSR330）默认是根据参数名去寻找bean注入，支持spring的@Primary注解优先注入，@Inject注解可以增加@Named注解指定注入的bean。

@Inject注解的源码如下所示。

```java
package javax.inject;
import java.lang.annotation.Target;
import java.lang.annotation.Retention;
import java.lang.annotation.Documented;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
@Target({ METHOD, CONSTRUCTOR, FIELD })
@Retention(RUNTIME)
@Documented
public @interface Inject {}
```

**注意：要想使用@Inject注解，需要在项目的pom.xml文件中添加如下依赖。**

```xml
<dependency>
    <groupId>javax.inject</groupId>
    <artifactId>javax.inject</artifactId>
    <version>1</version>
</dependency>
```

## 项目案例

### 测试@Resource注解

首先，我们将项目中的PersonService类标注在personDao字段上的@Autowired注解和@Qualifier注解注释掉，然后添加@Resource注解，如下所示。

```java
//@Qualifier("personDao")
//@Autowired(required = false)
@Resource
private PersonDao personDao;
```

接下来，我们运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonService{personDao=PersonDao{remark='1'}}
```

可以看到，使用@Resource注解也能够自动装配组件，只不过此时自动装配的是remark为1的personDao。而不是我们在AutowiredConfig类中配置的优先装配的remark为2的personDao。AutowiredConfig类中配置的remark为2的personDao如下所示。

```java
@Primary
@Bean("personDao2")
public PersonDao personDao(){
    PersonDao personDao = new PersonDao();
    personDao.setRemark("2");
    return personDao;
}
```

我们在使用@Resource注解时，可以通过@Resource注解的name属性显示指定要装配的组件的名称。例如，我们要想装配remark为2的personDao，只需要为@Resource注解添加 `name="personDao2"`属性即可。如下所示。

```java
//@Qualifier("personDao")
//@Autowired(required = false)
@Resource(name = "personDao2")
private PersonDao personDao;
```

接下来，我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonService{personDao=PersonDao{remark='2'}}
```

可以看到，此时输出了remark为2的personDao，说明@Resource注解可以通过name属性显示指定要装配的bean。

### 测试@Inject注解

在PersonService类中，将@Resource注解注释掉，添加@Inject注解，如下所示。

```java
//@Qualifier("personDao")
//@Autowired(required = false)
//@Resource(name = "personDao2")
@Inject
private PersonDao personDao;
```

修改完毕后，我们运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonService{personDao=PersonDao{remark='2'}}
```

可以看到，使用@Inject注解默认输出的是remark为2的personDao。这是因为@Inject注解和@Autowired注解一样，默认优先装配使用了@Primary注解标注的组件。

## @Resource和@Inject注解与@Autowired注解的区别

**不同点**

* @Autowired是spring专有注解，@Resource是java中**JSR250中的规范**，@Inject是java中**JSR330中的规范**
* @Autowired支持参数required=false，@Resource，@Inject都不支持
* @Autowired，和@Inject支持@Primary注解优先注入，@Resource不支持
* @Autowired通过@Qualifier指定注入特定bean,@Resource可以通过参数name指定注入bean，@Inject需要@Named注解指定注入bean

**相同点**

三种注解都可以实现bean的注入。

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





