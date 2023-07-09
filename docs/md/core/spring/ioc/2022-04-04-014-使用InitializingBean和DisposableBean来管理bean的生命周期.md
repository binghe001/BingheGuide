---
layout: post
category: binghe-spring-ioc
title: 第13章：使用InitializingBean和DisposableBean来管理bean的生命周期
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在《[【Spring注解驱动开发】如何使用@Bean注解指定初始化和销毁的方法？看这一篇就够了！！](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484985&idx=1&sn=bf7ec702113f433f6677d0e9f4f5ae7d&chksm=cee519f4f99290e2c509926a61a7f9604d8a358cd364a78d6de7929f45b3b2a84f57b93f8f87&token=604767871&lang=zh_CN#rd)》一文中，我们讲述了如何使用@Bean注解来指定bean初始化和销毁的方法。具体的用法就是在@Bean注解中使用init-method属性和destroy-method属性来指定初始化方法和销毁方法。除此之外，Spring中是否还提供了其他的方式来对bean实例进行初始化和销毁呢？
lock: need
---

# 《Spring注解驱动开发》第13章：使用InitializingBean和DisposableBean来管理bean的生命周期

## 写在前面

> 在《[【Spring注解驱动开发】如何使用@Bean注解指定初始化和销毁的方法？看这一篇就够了！！](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484985&idx=1&sn=bf7ec702113f433f6677d0e9f4f5ae7d&chksm=cee519f4f99290e2c509926a61a7f9604d8a358cd364a78d6de7929f45b3b2a84f57b93f8f87&token=604767871&lang=zh_CN#rd)》一文中，我们讲述了如何使用@Bean注解来指定bean初始化和销毁的方法。具体的用法就是在@Bean注解中使用init-method属性和destroy-method属性来指定初始化方法和销毁方法。除此之外，Spring中是否还提供了其他的方式来对bean实例进行初始化和销毁呢？
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## InitializingBean接口

### 1.InitializingBean接口概述

Spring中提供了一个InitializingBean接口，InitializingBean接口为bean提供了属性初始化后的处理方法，它只包括afterPropertiesSet方法，凡是继承该接口的类，在bean的属性初始化后都会执行该方法。InitializingBean接口的源码如下所示。

```java
package org.springframework.beans.factory;
public interface InitializingBean {
	void afterPropertiesSet() throws Exception;
}
```

根据InitializingBean接口中提供的afterPropertiesSet()方法的名字可以推断出：afterPropertiesSet()方法是在属性赋好值之后调用的。那到底是不是这样呢？我们来分析下afterPropertiesSet()方法的调用时机。

### 2.何时调用InitializingBean接口？

我们定位到Spring中的org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory类下的invokeInitMethods()方法中，来查看Spring加载bean的方法。

**题外话：不要问我为什么会是这个invokeInitMethods()方法，如果你和我一样对Spring的源码非常熟悉的话，你也会知道是这个invokeInitMethods()方法，哈哈哈哈！所以，小伙伴们不要只顾着使用Spring，还是要多看看Spring的源码啊！Spring框架中使用了大量优秀的设计模型，其代码的编写规范和严谨程度也是业界开源框架中数一数二的，非常值得阅读。**

我们来到AbstractAutowireCapableBeanFactory类下的invokeInitMethods()方法，如下所示。

```java
protected void invokeInitMethods(String beanName, final Object bean, @Nullable RootBeanDefinition mbd)
    throws Throwable {
	//判断该bean是否实现了实现了InitializingBean接口，如果实现了InitializingBean接口，则调用bean的afterPropertiesSet方法
    boolean isInitializingBean = (bean instanceof InitializingBean);
    if (isInitializingBean && (mbd == null || !mbd.isExternallyManagedInitMethod("afterPropertiesSet"))) {
        if (logger.isTraceEnabled()) {
            logger.trace("Invoking afterPropertiesSet() on bean with name '" + beanName + "'");
        }
        if (System.getSecurityManager() != null) {
            try {
                AccessController.doPrivileged((PrivilegedExceptionAction<Object>) () -> {
                    //调用afterPropertiesSet()方法
                    ((InitializingBean) bean).afterPropertiesSet();
                    return null;
                }, getAccessControlContext());
            }
            catch (PrivilegedActionException pae) {
                throw pae.getException();
            }
        }
        else {
            //调用afterPropertiesSet()方法
            ((InitializingBean) bean).afterPropertiesSet();
        }
    }

    if (mbd != null && bean.getClass() != NullBean.class) {
        String initMethodName = mbd.getInitMethodName();
        if (StringUtils.hasLength(initMethodName) &&
            !(isInitializingBean && "afterPropertiesSet".equals(initMethodName)) &&
            !mbd.isExternallyManagedInitMethod(initMethodName)) {
            //通过反射的方式调用init-method
            invokeCustomInitMethod(beanName, bean, mbd);
        }
    }
}
```

分析上述代码后，我们可以初步得出如下信息：

* Spring为bean提供了两种初始化bean的方式，实现InitializingBean接口，实现afterPropertiesSet方法，或者在配置文件和@Bean注解中通过init-method指定，两种方式可以同时使用。
* 实现InitializingBean接口是直接调用afterPropertiesSet()方法，比通过反射调用init-method指定的方法效率相对来说要高点。但是init-method方式消除了对Spring的依赖。
* 如果调用afterPropertiesSet方法时出错，则不调用init-method指定的方法。

也就是说Spring为bean提供了两种初始化的方式，第一种实现InitializingBean接口，实现afterPropertiesSet方法，第二种配置文件或@Bean注解中通过init-method指定，两种方式可以同时使用，同时使用先调用afterPropertiesSet方法，后执行init-method指定的方法。

## DisposableBean接口

### 1.DisposableBean接口概述

实现org.springframework.beans.factory.DisposableBean接口的bean在销毁前，Spring将会调用DisposableBean接口的destroy()方法。我们先来看下DisposableBean接口的源码，如下所示。

```java
package org.springframework.beans.factory;
public interface DisposableBean {
	void destroy() throws Exception;
}
```

可以看到，在DisposableBean接口中只定义了一个destroy()方法。

在Bean生命周期结束前调用destory()方法做一些收尾工作，亦可以使用destory-method。前者与Spring耦合高，使用**类型强转.方法名()，**效率高。后者耦合低，使用反射，效率相对低

### 2.DisposableBean接口注意事项

多例bean的生命周期不归Spring容器来管理，这里的DisposableBean中的方法是由Spring容器来调用的，所以如果一个多例实现了DisposableBean是没有啥意义的，因为相应的方法根本不会被调用，当然在XML配置文件中指定了destroy方法，也是没有意义的。所以，在多实例bean情况下，Spring不会自动调用bean的销毁方法。

## 单实例bean案例

创建一个Animal的类实现InitializingBean和DisposableBean接口，代码如下：

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试InitializingBean接口和DisposableBean接口
 */
public class Animal implements InitializingBean, DisposableBean {
    public Animal(){
        System.out.println("执行了Animal类的无参数构造方法");
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        System.out.println("执行了Animal类的初始化方法。。。。。");

    }
    @Override
    public void destroy() throws Exception {
        System.out.println("执行了Animal类的销毁方法。。。。。");

    }
}
```

接下来，我们新建一个AnimalConfig类，并将Animal通过@Bean注解的方式注册到Spring容器中，如下所示。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.plugins.register.bean.Animal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
/**
 * @author binghe
 * @version 1.0.0
 * @description AnimalConfig
 */
@Configuration
@ComponentScan("io.mykit.spring.plugins.register.bean")
public class AnimalConfig {
    @Bean
    public Animal animal(){
        return new Animal();
    }
}
```

接下来，我们在BeanLifeCircleTest类中新增testBeanLifeCircle02()方法来进行测试，如下所示。

```java
@Test
public void testBeanLifeCircle02(){
    //创建IOC容器
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AnimalConfig.class);
    System.out.println("IOC容器创建完成...");
    //关闭IOC容器
    context.close();
}
```

运行BeanLifeCircleTest类中的testBeanLifeCircle02()方法，输出的结果信息如下所示。

```bash
执行了Animal类的无参数构造方法
执行了Animal类的初始化方法。。。。。
IOC容器创建完成...
执行了Animal类的销毁方法。。。。。
```

从输出的结果信息可以看出：单实例bean下，IOC容器创建完成后，会自动调用bean的初始化方法；而在容器销毁前，会自动调用bean的销毁方法。

## 多实例bean案例

多实例bean的案例代码基本与单实例bean的案例代码相同，只不过在AnimalConfig类中，我们在animal()方法上添加了@Scope("prototype")注解，如下所示。

```java
package io.mykit.spring.plugins.register.config;
import io.mykit.spring.plugins.register.bean.Animal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
/**
 * @author binghe
 * @version 1.0.0
 * @description AnimalConfig
 */
@Configuration
@ComponentScan("io.mykit.spring.plugins.register.bean")
public class AnimalConfig {
    @Bean
    @Scope("prototype")
    public Animal animal(){
        return new Animal();
    }
}
```

接下来，我们在BeanLifeCircleTest类中新增testBeanLifeCircle03()方法来进行测试，如下所示。

```java
@Test
public void testBeanLifeCircle03(){
    //创建IOC容器
    AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext(AnimalConfig.class);
    System.out.println("IOC容器创建完成...");
    System.out.println("-------");
    //调用时创建对象
    Object bean = ctx.getBean("animal");
    System.out.println("-------");
    //调用时创建对象
    Object bean1 = ctx.getBean("animal");
    System.out.println("-------");
    //关闭IOC容器
    ctx.close();
}
```

运行BeanLifeCircleTest类中的testBeanLifeCircle03()方法，输出的结果信息如下所示。

```bash
IOC容器创建完成...
-------
执行了Animal类的无参数构造方法
执行了Animal类的初始化方法。。。。。
-------
执行了Animal类的无参数构造方法
执行了Animal类的初始化方法。。。。。
-------
```

从输出的结果信息中可以看出：在多实例bean情况下，Spring不会自动调用bean的销毁方法。

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