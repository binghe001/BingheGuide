---
layout: post
category: binghe-code-spring
title: 第13章：深度解析@Qualifier注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第13章：深度解析@Qualifier注解
lock: need
---

# 《Spring核心技术》第13章-注入数据型注解：深度解析@Qualifier注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-13](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-13)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Qualifier注解指定注入Bean的案例和流程，从源码级别彻底掌握@Qualifier注解在Spring底层的执行流程。

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

`Spring中的@Qualifier注解，你真的彻底了解过吗？`

如果Spring中存在多个类型相同但名称不同的Bean时，使用@Autowired注解向类的构造方法、方法、参数、字段中注入Bean对象时，如果需要向类的构造方法、方法、参数、字段中注入特定的Bean对象，就可以使用@Qualifier注解指定Bean的名称。

## 二、注解说明

`关于@Qualifier注解的一点点说明~~`

如果Spring中存在多个类型相同但名称不同的Bean时，使用@Autowired注解向类的构造方法、方法、参数、字段中注入Bean对象时，首先会根据Bean的类型注入，如果存在多个类型相同的Bean时，会根据Bean的名称注入，如果找不到对应名称的Bean时，就会抛出异常。此时，就可以通过@Qualifier注解明确指定要注入的Bean。

### 2.1 注解源码

@Qualifier注解的源码详见：org.springframework.beans.factory.annotation.Qualifier。

```java
/**
 * @author Mark Fisher
 * @author Juergen Hoeller
 * @since 2.5
 * @see Autowired
 */
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Qualifier {
	String value() default "";
}
```

从@Qualifier注解的源码可以看出，@Qualifier注解是从Spring 2.5版本开始提供的注解，可以标注到字段、方法、参数、类和其他注解上。在@Qualifier注解中只提供了一个String类型的value属性，具体含义如下所示。

* value：表示Bean的唯一标识。当使用Spring自动按照类型注入时，存在多个类型相同的Bean的时候，就可以使用此注解来明确注入哪个bean对象。

**注意：@Qualifier注解通常会和@Autowired注解一起使用。**

### 2.2 使用场景

在项目开发过程中，有这样一个场景会经常使用到@Qualifier注解。比如在项目中集成了多个消息中间件，包含：RocketMQ、Kafka、RabbitMQ和ActiveMQ，对外提供统一发送消息的接口，并且基于RocketMQ、Kafka、RabbitMQ和ActiveMQ实现的消息发送类上分别标注了不同的Bean名称。如果在业务系统中需要指定使用某种消息中间件来发送消息时，就需要使用@Qualifier注解明确指定Bean的名称。

总之，如果Spring中存在多个类型相同但名称不同的Bean时，使用@Autowired注解向类的构造方法、方法、参数、字段中注入Bean对象时，首先会根据Bean的类型注入，如果存在多个类型相同的Bean时，会根据Bean的名称注入，如果找不到对应名称的Bean时，就可以通过@Qualifier注解明确指定要注入的Bean。

## 三、使用案例

`@Qualifier的使用案例，我们一起实现吧~~`

本节，就简单介绍下当Spring中存在多个类型相同的Bean时，使用@Qualifier注解明确指定注入的Bean的案例。在案例的实现过程中，采用简单的MVC架构模式实现。具体案例实现步骤如下所示。

**（1）新增QualifierDao接口**

QualifierDao接口的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.dao.QualifierDao。

```java
public interface QualifierDao {
}
```

可以看到，QualifierDao接口就是一个简单的Java接口。

**（2）新增QualifierDao1类**

QualifierDao1类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.dao.impl.QualifierDao1。

```java
@Repository(value = "qualifierDao1")
public class QualifierDao1 implements QualifierDao {
    public QualifierDao1(){
        System.out.println("执行了QualifierDao1的构造方法...");
    }
}
```

可以看到，QualifierDao1类实现了QualifierDao接口，并使用@Repository注解执行了Bean的名称为qualifierDao1。

**（3）新增QualifierDao2类**

QualifierDao2类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.dao.impl.QualifierDao2。

```java
@Repository(value = "qualifierDao2")
public class QualifierDao2 implements QualifierDao {
    public QualifierDao2(){
        System.out.println("执行了QualifierDao2的构造方法...");
    }
}
```

可以看到，QualifierDao2类实现了QualifierDao接口，并使用@Repository注解执行了Bean的名称为qualifierDao2。

**（4）新增QualifierService类**

QualifierService类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.service.QualifierService。

```java
@Service
public class QualifierService {
    @Autowired
    @Qualifier("qualifierDao1")
    private QualifierDao qualifierDao;
    @Override
    public String toString() {
        return "QualifierService{" +
                "qualifierDao=" + qualifierDao +
                '}';
    }
}
```

可以看到，在QualifierService类上标注了@Service注解，当IOC容器启动扫描到QualifierService类时，就会将QualifierService类的Bean对象注入IOC容器。在QualifierService类中，使用@Autowired注解和 @Qualifier注解注入QualifierDao类的Bean对象。并且使用@Qualifier注解明确指定注入名称为qualifierDao1的QualifierDao对象。

**（5）新增QualifierConfig类**

QualifierConfig类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.config.QualifierConfig。

```java
@Configuration
@ComponentScan(value = {"io.binghe.spring.annotation.chapter13"})
public class QualifierConfig {
}
```

可以看到，在QualifierConfig类上标注了@Configuration注解，说明QualifierConfig类是Spring的配置类，同时在QualifierConfig类上使用@ComponentScan注解指定要扫描的包是io.binghe.spring.annotation.chapter13。

**（6）新增QualifierTest类**

QualifierTest类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.QualifierTest。

```java
public class QualifierTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(QualifierConfig.class);
        QualifierService qualifierService = context.getBean(QualifierService.class);
        System.out.println("qualifierService===>>> " + qualifierService);
    }
}
```

可以看到，在QualifierTest类中的main()方法中，会从IOC容器中获取QualifierService类的Bean对象并进行打印。

**（7）运行QualifierTest类**

运行QualifierTest类的main()方法，输出的结果信息如下所示。

```bash
执行了QualifierDao1的构造方法...
执行了QualifierDao2的构造方法...
qualifierService===>>> QualifierService{qualifierDao=io.binghe.spring.annotation.chapter13.dao.impl.QualifierDao1@6631f5ca}
```

从输出的结果信息中可以看到，执行了QualifierDao1类和QualifierDao2类的构造方法，并向QualifierService类中使用@Qualifier注解指定注入了QualifierDao1类的Bean对象。

另外，大家可以自行将QualifierService类中@Qualifier注解中的值修改为qualifierDao2，并测试结果，这里不再赘述。

**说明：当存在多个类型相同的Bean时，可以使用@Qualifier注解明确指定要注入的Bean。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

@Qualifier注解的源码时序图与@Autowired基本相同，可以参考第12章的内容。这里不再赘述。

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

@Qualifier注解的源码解析与@Autowired基本相同，可以参考第12章的内容。这里不再赘述。

## 六、总结

`@Qualifier注解介绍完了，我们一起总结下吧！`

本章，主要介绍了@Qualifier注解的源码和使用场景，并给出了@Qualifier注解的使用案例，由于@Qualifier注解的源码时序图和源码解析与@Autowired基本相同，可以参考第12章的内容，本章不再赘述。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Autowired注解，通常会有如下几个经典面试题：

* @Qualifier注解的作用是什么？
* @Qualifier注解有哪些使用场景？
* @Qualifier向Bean的字段和方法注入指定的值是如何实现的？
* @Qualifier注解在Spring内部的执行流程？
* 你在平时工作中，会在哪些场景下使用@Qualifier注解？
* 你从@Qualifier注解的设计中得到了哪些启发？

## 八、VIP服务

**强烈推荐阅读：《[原来大厂面试官也会在这里偷偷学习！](https://mp.weixin.qq.com/s/Zp0nI2RyFb_UCYpSsUt2OQ)》，如果文中优惠券过期，可长按或扫码下面优惠券二维码加入星球。**

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-18-008.png?raw=true" width="70%">
    <div style="font-size: 18px;">星球优惠券</div>
    <br/>
</div>

**冰河技术** 知识星球**《SpringCloud Alibaba实战》**从零搭建并开发微服务项目已完结；**《RPC手撸专栏》**已经更新120+篇文章，已提交120+项目工程，120+项目源码Tag分支；**《Spring核心技术》**专栏以Spring的核心注解为突破口，通过源码执行的时序图带你详细分析Spring底层源码，让你学习Spring底层源码不再枯燥。并这些专栏已经将源码的获取方式放到了知识星球中，同时在微信上创建了专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

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



