---
layout: post
category: binghe-spring-ioc
title: 第42章：AnnotationAwareAspectJAutoProxyCreator深度解析
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在《Spring注解驱动开发》系列中的《[Spring中这么重要的AnnotationAwareAspectJAutoProxyCreator类是干嘛的？](https://binghe.blog.csdn.net/article/details/114650073)》一文中，我们简单分析了AnnotationAwareAspectJAutoProxyCreator类的作用，接下来，我们就以debug的方式来深入分析AnnotationAwareAspectJAutoProxyCreator的执行流程。同样的，我们还是以debug的形式来分析AnnotationAwareAspectJAutoProxyCreator类的执行流程，在`io.mykit.spring.plugins.register.config`包下创建AopConfig类，然后在AopConfig类中创建mathHandler()方法，如下所示。
lock: need
---

# 《Spring注解驱动开发》第42章：AnnotationAwareAspectJAutoProxyCreator深度解析

**大家好，我是冰河~~**

在《Spring注解驱动开发》系列中的《[Spring中这么重要的AnnotationAwareAspectJAutoProxyCreator类是干嘛的？](https://binghe.blog.csdn.net/article/details/114650073)》一文中，我们简单分析了AnnotationAwareAspectJAutoProxyCreator类的作用，接下来，我们就以debug的方式来深入分析AnnotationAwareAspectJAutoProxyCreator的执行流程。

同样的，我们还是以debug的形式来分析AnnotationAwareAspectJAutoProxyCreator类的执行流程，在`io.mykit.spring.plugins.register.config`包下创建AopConfig类，然后在AopConfig类中创建mathHandler()方法，如下所示。

```java
package io.mykit.spring.plugins.register.config;
import io.mykit.spring.plugins.register.aop.MathHandler;
import io.mykit.spring.plugins.register.aspect.LogAspect;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试AOP
 */
@Configuration
@EnableAspectJAutoProxy
public class AopConfig {
    @Bean
    public MathHandler mathHandler(){
        return new MathHandler();
    }
}
```

接下来，在`AopConfig#mathHandler()`方法中打上断点，如下所示。

![001](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-001.png)

接下来，启动`io.mykit.spring.test`包下的`AopTest#testAop01()`方法。

```java
package io.mykit.spring.test;
import io.mykit.spring.plugins.register.aop.MathHandler;
import io.mykit.spring.plugins.register.config.AopConfig;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试切面
 */
public class AopTest {

    @Test
    public void testAop01(){
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AopConfig.class);
        MathHandler mathHandler = context.getBean(MathHandler.class);
        mathHandler.add(1, 2);
        context.close();
    }
}
```

发现断点会进入`org.springframework.context.annotation`包下的`AnnotationConfigApplicationContext#AnnotationConfigApplicationContext()`方法，如下所示。

![003](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-003.png)

而此时的断点是定位到`AnnotationConfigApplicationContext#AnnotationConfigApplicationContext()`方法中调用`refresh()`方法的代码行。`refresh()`方法会刷新Spring容器。接下来，我们可以通过IDEA左下角的方法调用堆栈进入`refresh()`方法内部，如下所示。

![004](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-004.png)

此时发现`refresh()`方法位于`org.springframework.context.support`包下的`AbstractApplicationContext`类中。此时，会发现代码调用流程会定位在`AbstractApplicationContext#refresh()`方法中调用的`registerBeanPostProcessors()`方法代码行。如下所示。

![005](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-005.png)

`registerBeanPostProcessors()`方法的作用就是注册bean的后置处理器来拦截bean的创建。

接下来，进入`registerBeanPostProcessors()`方法，发现`registerBeanPostProcessors()`方法位于`org.springframework.context.support`包下的`AbstractApplicationContext`类中，如下所示。

![006](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-006.png)

接下来，进入`PostProcessorRegistrationDelegate#registerBeanPostProcessors()`方法，这个方法的作用就是注册bean的后置处理器。在这个方法中按照顺序依次做了如下操作：

（1）先获取容器中已经定义的需要创建对象的所有BeanPostProcessor

（2）为容器中添加别的BeanPostProcessor

（3）注册实现了`PriorityOrdered`接口的BeanPostProcessor

（4）注册实现了`Ordered`接口的BeanPostProcessor

（5）注册没有实现优先级接口的BeanPostProcessor

（6）注册BeanPostProcessor，也就是创建BeanPostProcessor对象保存到容器中，创建`interalAutoProxyCreator`的BeanPostProcessor对象（AnnotationAwareAspectJAutoProxyCreator类型的对象）。

在（6）中又会依次执行如下几个步骤。

1) 调用`createBeanInstance(String, RootBeanDefinition, Object[])`方法，创建Bean的实例

2) 调用`populateBean(String, RootBeanDefinition, BeanWrapper) `方法，为bean的属性赋值。

3) 调用`initializeBean(String, Object ,RootBeanDefinition mbd)`方法，初始化bean。

这三个方法都位于`org.springframework.beans.factory.support`包下的`AbstractAutowireCapableBeanFactory`类中。

而第3)步的执行又会依次执行如下几个步骤。

* 调用`invokeAwareMethods(String, Object)`方法，处理Aware接口的方法回调。
* 调用`applyBeanPostProcessorsBeforeInitialization(Object, String)`方法，应用后置处理器的`PostProcessorsBeforeInitialization()`方法。
* 调用`invokeInitMethods(String, Object, RootBeanDefinition)`方法，执行自定义的初始化方法。
* 调用`applyBeanPostProcessorsAfterInitialization(Object, String)`方法，执行后置处理器的`postProcessAfterInitialization(Object, String)`方法。如下所示。

4) `BeanPostProcessor(AnnotationAwareAspectJAutoProxyCreator)`创建成功，名称为`aspectJAdvisorsBuilder`。

![018](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-018.png)



接下来，我们看看方法的调用信息。

![007](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-007.png)

会发现此时逻辑调用会定位在`BeanPostProcessor pp = beanFactory.getBean(ppName, BeanPostProcessor.class);` 这行代码上。

同样的，我们进入`beanFactory.getBean(ppName, BeanPostProcessor.class);`方法。发现会进入`org.springframework.beans.factory.support`包下的`AbstractBeanFactory#getBean(String,Class)`方法。

![008](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-008.png)

继续进入`doGetBean()`方法，会发现逻辑执行定位到`doGetBean()`中如下代码处。

```java
sharedInstance = getSingleton(beanName, () -> {
    try {
        return createBean(beanName, mbd, args);
    }
    catch (BeansException ex) {
        // Explicitly remove instance from singleton cache: It might have been put there
        // eagerly by the creation process, to allow for circular reference resolution.
        // Also remove any beans that received a temporary reference to the bean.
        destroySingleton(beanName);
        throw ex;
    }
});
```

![009](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-009.png)

而在IOC容器中第一次调用`getSingleton()`方法时，不会存在实例，所以，第一次调用`getSingleton()`方法会返回null。

进入`getSingleton()`方法，如下所示。

![010](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-010.png)

此时，发现Spring会调用`singletonFactory.getObject()`方法，继续往下执行，会发现逻辑定位到`doGetBean()`方法的如下代码。

![011](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-011.png)

继续执行断点，会发现逻辑进入`org.springframework.beans.factory.support`包下的`AbstractAutowireCapableBeanFactory#createBean(String, RootBeanDefinition, Object[])`方法中，如下所示。

![012](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-012.png)

继续进入`doCreateBean(String,RootBeanDefinition,Object[])`方法，如下所示。

![013](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-013.png)

此时，会发现bean已经实例化完成了，如下所示。

![014](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-014.png)

接下来，就会初始化bean的信息。那具体bean是在哪里进行实例化的呢？我们找到`doCreateBean(String,RootBeanDefinition,Object[])`方法的如下代码片段。

![015](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-015.png)

同时，我们也会发现此时实例化的bean的类型为`org.springframework.aop.config.internalAutoProxyCreator`。

![016](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-016.png)

实例化完成之后就会在`doCreateBean(String,RootBeanDefinition,Object[])`方法的如下代码处进行初始化。

![013](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-013.png)

进入`initializeBean(String, Object ,RootBeanDefinition mbd)`方法。

![017](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-017.png)

会发现代码执行逻辑定位在`invokeAwareMethods(beanName, bean);`处。进入`invokeAwareMethods(beanName, bean);`方法。

![019](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-019.png)

这个方法就比较简单了，相信点击都能看懂，这里就不再赘述这个方法的逻辑了。此时，代码的执行逻辑会定位到`((BeanFactoryAware) bean).setBeanFactory(AbstractAutowireCapableBeanFactory.this);`。

继续执行会发现逻辑进入了`org.springframework.aop.framework.autoproxy`包下的`AbstractAdvisorAutoProxyCreator#setBeanFactory()`方法，如下所示。

![002](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-002.png)

首先，会调用父类的`setBeanFactory(BeanFactory)`方法，然后会调用`initBeanFactory(ConfigurableListableBeanFactory) `方法初始化BeanFactory。

继续往下执行，我们会发现调用的是`org.springframework.aop.aspectj.annotation`包下的`AnnotationAwareAspectJAutoProxyCreator#initBeanFactory(ConfigurableListableBeanFactory)`方法。

![020](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-020.png)

继续往下执行，代码逻辑会执行到`org.springframework.beans.factory.support`包下的`AbstractAutowireCapableBeanFactory#createBean(String, RootBeanDefinition, Object[])`方法中，并且会定位到`Object beanInstance = doCreateBean(beanName, mbdToUse, args);`代码行。

![021](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-021.png)

执行完会回到`org.springframework.beans.factory.support`包下的`DefaultSingletonBeanRegistry#getSingleton(String, ObjectFactory<?>)`方法，并且会执行`addSingleton(beanName, singletonObject);代码行，如下所示。

![022](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-044-022.png)

将bean放入容器中。

至此，整个bean的创建，实例化，初始化，添加到容器的过程就介绍完了。


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




