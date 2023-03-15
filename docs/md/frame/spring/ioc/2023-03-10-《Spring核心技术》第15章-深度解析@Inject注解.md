---
layout: post
category: binghe-code-spring
title: 第15章：深度解析@Inject注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第15章：深度解析@Inject注解
lock: need
---

# 《Spring核心技术》第15章-注入数据型注解：深度解析@Inject注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-15](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-15)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Inject注解注入Bean的案例和流程，从源码级别彻底掌握@Inject注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Inject注解，你真的彻底了解过吗？`

@Inject注解是JSR330规范中提供的注解，可以将Bean装配到类的方法，构造方法和字段中，也可以配合@Qualifier注解使用。

## 二、注解说明

`关于@Inject注解的一点点说明~~`

@Inject注解是JSR330规范中提供的注解，在@Inject注解中不提供任何属性，可以配合@Qualifier注解使用。也就是说，存在多个类型相同的Bean时，通过@Qualifier注解可以明确指定注入哪个Bean。

@Inject注解与@Autowired的区别：

（1）@Inject是JSR330规范实现的，@Autowired是spring自带的。

（2）@Autowired、@Inject用法基本一样，不同的是@Autowired有一个required属性。

### 2.1 注解源码

@Inject注解的源码详见：javax.inject.Inject。

```java
@Target({ METHOD, CONSTRUCTOR, FIELD })
@Retention(RUNTIME)
@Documented
public @interface Inject {}
```

可以看到，@Inject注解并没有提供任何属性，并且@Inject注解可以标注到方法、构造方法和字段上。

### 2.2 使用场景

在一定程度上，@Inject注解和@Autowired注解的使用场景基本相同，如果需要将Bean装配到类中的方法、构造方法和字段中，可以使用@Inject注解实现。

## 三、使用案例

`@Inject的实现案例，我们一起实现吧~~`

本节，就基于@Inject注解实现向Bean属性中赋值的案例，具体的实现步骤如下所示。

**（1）新增InjectDao类**

InjectDao类的源码详见：spring-annotation-chapter-15工程下的io.binghe.spring.annotation.chapter15.dao.InjectDao。

```java
@Repository
public class InjectDao {
}
```

可以看到，InjectDao类就是一个普通的dao类。

**（2）新增InjectService类**

InjectService类的源码详见：spring-annotation-chapter-15工程下的io.binghe.spring.annotation.chapter15.service.InjectService。

```java
@Service
public class InjectService {
    @Inject
    private InjectDao injectDao;
    @Override
    public String toString() {
        return "InjectService{" +
                "injectDao=" + injectDao +
                '}';
    }
}
```

可以看到，InjectService类是service层的实现类，并且在InjectService类中使用@Inject注解向injectDao成员变量中装配InjectDao类型的Bean对象。

**（3）新增InjectConfig类**

InjectConfig类的源码详见：spring-annotation-chapter-15工程下的io.binghe.spring.annotation.chapter15.config.InjectConfig。

```java
@Configuration
@ComponentScan(basePackages = {"io.binghe.spring.annotation.chapter15"})
public class InjectConfig {
}
```

可以看到，InjectConfig类上标注了@Configuration注解，说明InjectConfig类是案例的配置类，并且在InjectConfig类上使用@ComponentScan注解指定了要扫描的包名。

**（4）新增InjectTest类**

InjectTest类的源码详见：spring-annotation-chapter-15工程下的io.binghe.spring.annotation.chapter15.InjectTest。

```java
public class InjectTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(InjectConfig.class);
        InjectService injectService = context.getBean(InjectService.class);
        System.out.println(injectService);
    }
}
```

可以看到，在InjectTest类的main()方法中，从IOC容器中获取InjectService对象并打印。

**（5）运行InjectTest类**

运行InjectTest类的main()方法，输出的结果信息如下所示。

```bash
InjectService{injectDao=io.binghe.spring.annotation.chapter15.dao.InjectDao@a3d8174}
```

可以看到，通过@Inject注解成功向InjectService类的injectDao成员变量中装配了Bean对象。

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

注意：本章也可以从解析并获取 @Inject修饰的属性、为 @Inject修饰属性赋值和使用@Inject获取属性值三个方面分析源码时序图，与@Autowired注解的源码时序图基本相同，本节不再赘述。

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

注意：本章也可以从解析并获取 @Inject修饰的属性、为 @Inject修饰属性赋值和使用@Inject获取属性值三个方面分析源码的执行流程，与@Autowired注解的源码流程基本相同，本节不再赘述。

## 六、总结

`@Inject注解介绍完了，我们一起总结下吧！`

本章，主要对JSR330规范中提供的@Inject注解进行了简单的介绍。首先，介绍了注解的源码和使用场景。随后，给出了注解的使用案例。由于@Inject注解的源码时序图和源码解析与@Autowired注解基本相同，本章没有再次赘述，大家可以参考@Autowired注解一章。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Inject注解，通常会有如下几个经典面试题：

* @Inject注解的作用是什么？
* @Inject注解有哪些使用场景？
* @Inject向Bean的字段和方法注入值是如何实现的？
* @Inject注解在Spring内部的执行流程？
* @Inject注解在Spring源码中的执行流程与@Autowired和@Resource注解有何区别？
* 你在平时工作中，会在哪些场景下使用@Inject注解？
* 你从@Inject注解的设计中得到了哪些启发？

## 八、VIP服务

**强烈推荐阅读：《[原来大厂面试官也会在这里偷偷学习！](https://mp.weixin.qq.com/s/Zp0nI2RyFb_UCYpSsUt2OQ)》，如果文中优惠券过期，可长按或扫码下面优惠券二维码加入星球。**

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-18-008.png?raw=true" width="70%">
    <div style="font-size: 18px;">星球优惠券</div>
    <br/>
</div>

**冰河技术** 知识星球 **《SpringCloud Alibaba实战》** 从零搭建并开发微服务项目已完结；**《RPC手撸专栏》** 已经更新120+篇文章，已提交120+项目工程，120+项目源码Tag分支；**《Spring核心技术》** 专栏以Spring的核心注解为突破口，通过源码执行的时序图带你详细分析Spring底层源码，让你学习Spring底层源码不再枯燥。并这些专栏已经将源码的获取方式放到了知识星球中，同时在微信上创建了专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

目前，星球群已形成良好的技术讨论氛围，后续也会像PRC项目一样全程手撸企业级中间件项目，**涉及分布式、高并发、高性能、高可靠、高可扩展，让大家知其然，更知其所以然，从手写企业级中间件项目的过程中，充分掌握分布式、高并发、高性能、高可靠、高可扩展的编程技巧。**

**更加值得一提的是：有超过30+的大厂面试官悄悄在这里提升核心竞争力！**

### 星球提供的服务

冰河整理了星球提供的一些服务，如下所示。

加入星球，你将获得：

1.学习从零开始手撸可用于实际场景的高性能、可扩展的RPC框架项目

2.学习SpringCloud Alibaba实战项目—从零开发微服务项目

3.学习高并发、大流量业务场景的解决方案，体验大厂真正的高并发、大流量的业务场景

4.学习进大厂必备技能：性能调优、并发编程、分布式、微服务、框架源码、中间件开发、项目实战

5.提供站点 https://binghe.gitcode.host 所有学习内容的指导、帮助

6.GitHub：https://github.com/binghe001/BingheGuide - 非常有价值的技术资料仓库，包括冰河所有的博客开放案例代码

7.提供技术问题、系统架构、学习成长、晋升答辩等各项内容的回答

8.定期的整理和分享出各类专属星球的技术小册、电子书、编程视频、PDF文件

9.定期组织技术直播分享，传道、授业、解惑，指导阶段瓶颈突破技巧

### 如何加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

**好了，今天就到这儿吧，我是冰河，我们下期见~~**



## 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`学习加群`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>





## 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>




## 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>





## 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>