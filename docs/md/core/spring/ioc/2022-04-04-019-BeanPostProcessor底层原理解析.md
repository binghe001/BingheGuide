---
layout: post
category: binghe-spring-ioc
title: 第18章：BeanPostProcessor的执行流程
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在前面的文章中，我们讲述了BeanPostProcessor的postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法在bean初始化的前后调用，我们可以自定义类来实现BeanPostProcessor接口，并在postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法中指定我们自定义的逻辑。今天，我们来一起探讨下eanPostProcessor底层原理。
lock: need
---

# 《String注解驱动开发》第18章：BeanPostProcessor的执行流程

## 写在前面

> 在前面的文章中，我们讲述了BeanPostProcessor的postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法在bean初始化的前后调用，我们可以自定义类来实现BeanPostProcessor接口，并在postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法中指定我们自定义的逻辑。今天，我们来一起探讨下eanPostProcessor底层原理。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## bean的初始化和销毁

我们知道BeanPostProcessor的postProcessBeforeInitialization()方法在bean的初始化之前调用；而postProcessAfterInitialization()方法在bean初始化的之后调用。而bean的初始化和销毁方法我们可以通过如下方式进行指定。

### 1.通过@Bean指定init-method和destroy-method

```java
@Bean(initMethod="init",destroyMethod="detory")
public Car car(){
    return new Car();
}
```

### 2.通过让Bean实现InitializingBean（定义初始化逻辑）

```java
@Component
public class Cat implements InitializingBean,DisposableBean {
    public Cat(){
        System.out.println("cat constructor...");
    }
    @Override
    public void destroy() throws Exception {
        System.out.println("cat...destroy...");
    }
    @Override
    public void afterPropertiesSet() throws Exception {
        System.out.println("cat...afterPropertiesSet...");
    }
}
```

### 3.可以使用JSR250

* @PostConstruct：在bean创建完成并且属性赋值完成；来执行初始化方法。
* @PreDestroy：在容器销毁bean之前通知我们进行清理工作。

```java
@Component
public class Dog implements ApplicationContextAware {
    //@Autowired
    private ApplicationContext applicationContext;
    public Dog(){
        System.out.println("dog constructor...");
    }
    //对象创建并赋值之后调用
    @PostConstruct
    public void init(){
        System.out.println("Dog....@PostConstruct...");
    }
    //容器移除对象之前
    @PreDestroy
    public void detory(){
        System.out.println("Dog....@PreDestroy...");
    }
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
```

### 4.可以使用BeanPostProcessor

```java
/**
 * 后置处理器：初始化前后进行处理工作
 * 将后置处理器加入到容器中
 * 在bean初始化前后进行一些处理工作；
 * postProcessBeforeInitialization:在初始化之前工作
 * postProcessAfterInitialization:在初始化之后工作
 */
@Component
public class MyBeanPostProcessor implements BeanPostProcessor,Ordered {
    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("postProcessBeforeInitialization..."+beanName+"=>"+bean);
        return bean;
    }
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        // TODO Auto-generated method stub
        System.out.println("postProcessAfterInitialization..."+beanName+"=>"+bean);
        return bean;
    }
    @Override
    public int getOrder() {
        return 3;
    }
}
```

通过这几种方式，我们就可以对bean的整个生命周期进行控制：

* 从bean的实例化：调用bean的构造方法，我们可以在bean的无参构造方法中执行相应的逻辑。
* bean的初始化：在初始化时，可以通过BeanPostProcessor的postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法进行拦截，执行自定义的逻辑；通过@PostConstruct注解、InitializingBean和init-method来指定bean初始化前后执行的方法，执行自定义的逻辑。
* bean的销毁：可以通过@PreDestroy注解、DisposableBean和destroy-method来指定bean在销毁前执行的方法，指执行自定义的逻辑。

所以，通过上述方式，我们可以控制Spring中bean的整个生命周期。

## BeanPostProcessor源码解析

如果想深刻理解BeanPostProcessor的工作原理，那就不得不看下相关的源码，我们可以在MyBeanPostProcessor类的postProcessBeforeInitialization()方法和postProcessAfterInitialization()方法中打上断点来进行调试。如下所示。

![001](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-001.png)

随后，我们以Debug的方式来运行BeanLifeCircleTest类的testBeanLifeCircle04()方法，运行后的效果如下所示。

![002](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-002.png)

可以看到，程序已经运行到MyBeanPostProcessor类的postProcessBeforeInitialization()方法中，在IDEA的左下角我们可以清晰的看到方法的调用栈，如下所示。

![003](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-003.png)

通过这个方法调用栈，我们可以详细的分析从运行BeanLifeCircleTest类的testBeanLifeCircle04()方法开始，到进入MyBeanPostProcessor类的postProcessBeforeInitialization()方法的执行流程。只要我们在IDEA的方法调用栈中找到BeanLifeCircleTest类的testBeanLifeCircle04()方法，依次分析方法调用栈中在BeanLifeCircleTest类的testBeanLifeCircle04()方法上面位置的方法，即可了解整个方法调用栈的过程。要想定位方法调用栈中的方法，只需要在IDEA的方法调用栈中单击相应的方法即可。

**注意：方法调用栈是先进后出的，也就是说，最先调用的方法会最后退出，每调用一个方法，JVM会将当前调用的方法放入栈的栈顶，方法退出时，会将方法从栈顶的位置弹出。有关方法调用的具体细节内容，后续会在【JVM】专栏详细介绍，这里，小伙伴们就先了解到此即可。**

接下来，我们在IDEA的方法调用栈中，找到BeanLifeCircleTest类的testBeanLifeCircle04()方法并单击，此时IDEA的主界面会定位到BeanLifeCircleTest类的testBeanLifeCircle04()方法，如下所示。

![005](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-005.png)

在BeanLifeCircleTest类的testBeanLifeCircle04()方法中，首先通过new实例对象的方式创建了一个IOC容器。接下来，通过IDEA的方法调用栈继续分析，接下来，进入的是AnnotationConfigApplicationContext类的构造方法。

![006](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-006.png)

在AnnotationConfigApplicationContext类的构造方法中会调用refresh()方法。我们跟进方法调用栈，如下所示。

![007](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-007.png)

可以看到，方法的执行定位到AbstractApplicationContext类的refresh()方法中的如下代码行。

```java
finishBeanFactoryInitialization(beanFactory);
```

这行代码的作用就是：初始化所有的（非懒加载的）单实例bean对象。

我们继续跟进方法调用栈，如下所示。

![008](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-008.png)

此时，方法的执行定位到AbstractApplicationContext类的finishBeanFactoryInitialization()方法的如下代码行。

```java
beanFactory.preInstantiateSingletons();
```

这行代码的作用同样是：初始化所有的（非懒加载的）单实例bean。

我们继续跟进方法调用栈，如下所示。

![009](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-009.png)

可以看到，方法的执行定位到DefaultListableBeanFactory的preInstantiateSingletons()方法的最后一个else分支调用的getBean()方法上。继续跟进方法调用栈，如下所示。

![010](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-010.png)

此时方法定位到AbstractBeanFactory类中的getBean()方法中，在getBean()方法中，又调用了doGetBean()方法，通过方法调用栈我们可以得知方法的执行定位到AbstractBeanFactory类中的doGetBean()方法的如下代码段。

![011](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-011.png)

可以看到，在Spring内部是通过getSingleton()来获取单实例bean的，我们继续跟进方法调用栈，如下所示。

![012](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-012.png)

此时，方法定位到了DefaultSingletonBeanRegistry了类的getSingleton()方法的如下代码行。

```java
singletonObject = singletonFactory.getObject();
```

继续跟进方法调用栈，如下所示。

![013](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-013.png)

此时，方法会定位到AbstractBeanFactory类的doGetBean()方法中的如下代码行。

```java
return createBean(beanName, mbd, args);
```

也就是说，当第一次获取单实例bean时，由于单实例bean还未创建，Spring会调用createBean()方法来创建单实例bean。继续跟进方法调用栈，如下所示。

![014](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-014.png)

可以看到，方法的执行定位到AbstractAutowireCapableBeanFactory类的createBean()方法的如下代码行。

```java
Object beanInstance = doCreateBean(beanName, mbdToUse, args);
```

可以看到，Spring中创建单实例bean调用的是doCreateBean()方法。没错，继续跟进方法调用栈，如下所示。

![015](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-015.png)

方法的执行已经定位到AbstractAutowireCapableBeanFactory类的doCreateBean()方法的如下代码行。

```java
exposedObject = initializeBean(beanName, exposedObject, mbd);
```

继续跟进方法调用栈，如下所示。

![016](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-019-016.png)

方法的执行定位到AbstractAutowireCapableBeanFactory类的initializeBean()方法的如下代码行。

```java
wrappedBean = applyBeanPostProcessorsBeforeInitialization(wrappedBean, beanName);
```

小伙伴们需要重点留意一下这个applyBeanPostProcessorsBeforeInitialization()方法。回过头来我们再来看AbstractAutowireCapableBeanFactory类的doCreateBean()方法中的如下代码行。

```java
exposedObject = initializeBean(beanName, exposedObject, mbd);
```

没错，在AbstractAutowireCapableBeanFactory类的doCreateBean()方法中调用的initializeBean()方法中调用了后置处理器的逻辑。小伙伴们需要注意一下，在AbstractAutowireCapableBeanFactory类的doCreateBean()方法中调用的initializeBean()方法之前，调用了一个populateBean()方法，代码行如下所示。

```java
populateBean(beanName, mbd, instanceWrapper);
```

我们点到这个populateBean()方法中，看下这个方法执行了哪些逻辑，如下所示。

populateBean()方法同样是AbstractAutowireCapableBeanFactory类中的方法，populateBean()方法的代码比较多，其实逻辑非常简单，populateBean()方法做的工作就是为bean的属性赋值。也就是说，在Spring中会先调用populateBean()方法为属性赋好值，然后再调用initializeBean()方法。接下来，我们好好分析下initializeBean()方法，为了方便，我将Spring中AbstractAutowireCapableBeanFactory类的initializeBean()方法的代码拿出来，如下所示。

```java
protected Object initializeBean(final String beanName, final Object bean, @Nullable RootBeanDefinition mbd) {
    if (System.getSecurityManager() != null) {
        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            invokeAwareMethods(beanName, bean);
            return null;
        }, getAccessControlContext());
    }
    else {
        invokeAwareMethods(beanName, bean);
    }

    Object wrappedBean = bean;
    if (mbd == null || !mbd.isSynthetic()) {
        wrappedBean = applyBeanPostProcessorsBeforeInitialization(wrappedBean, beanName);
    }

    try {
        invokeInitMethods(beanName, wrappedBean, mbd);
    }
    catch (Throwable ex) {
        throw new BeanCreationException(
            (mbd != null ? mbd.getResourceDescription() : null),
            beanName, "Invocation of init method failed", ex);
    }
    if (mbd == null || !mbd.isSynthetic()) {
        wrappedBean = applyBeanPostProcessorsAfterInitialization(wrappedBean, beanName);
    }

    return wrappedBean;
}
```

在initializeBean()方法中，调用了invokeInitMethods()方法，代码行如下所示。

```java
invokeInitMethods(beanName, wrappedBean, mbd);
```

invokeInitMethods()方法的作用就是：执行初始化方法，这些初始化方法包括我们之前讲的： **在xml文件中的<bean>标签中使用init-method属性指定的初始化方法；在@Bean注解中使用initMehod属性指定的方法；使用@PostConstruct注解标注的方法；实现InitializingBean接口的方法等。**

**在调用invokeInitMethods()方法之前，Spring调用了applyBeanPostProcessorsBeforeInitialization()方法，代码行如下所示。**

```java
wrappedBean = applyBeanPostProcessorsBeforeInitialization(wrappedBean, beanName);
```

**在调用invokeInitMethods()方法之后，Spring调用了applyBeanPostProcessorsAfterInitialization()方法，如下所示。**

```java
wrappedBean = applyBeanPostProcessorsAfterInitialization(wrappedBean, beanName);
```

这里，我们先来看看applyBeanPostProcessorsBeforeInitialization()方法中具体执行了哪些逻辑，applyBeanPostProcessorsBeforeInitialization()方法位于AbstractAutowireCapableBeanFactory类中，源码如下所示。

```java
@Override
public Object applyBeanPostProcessorsBeforeInitialization(Object existingBean, String beanName)
    throws BeansException {

    Object result = existingBean;
    for (BeanPostProcessor processor : getBeanPostProcessors()) {
        Object current = processor.postProcessBeforeInitialization(result, beanName);
        if (current == null) {
            return result;
        }
        result = current;
    }
    return result;
}
```

可以看到，在applyBeanPostProcessorsBeforeInitialization()方法中，会遍历所有BeanPostProcessor对象，执行所有BeanPostProcessor对象的postProcessBeforeInitialization()方法，一旦BeanPostProcessor对象的postProcessBeforeInitialization()方法返回null，则后面的BeanPostProcessor对象不再执行，直接退出for循环。

看Spring源码，我们看到一个细节， **在Spring中调用initializeBean()方法之前，调用了populateBean()方法来为bean的属性赋值。** 

我们将关键代码的调用过程使用如下伪代码表述出来。

```java
populateBean(beanName, mbd, instanceWrapper);
initializeBean(beanName, exposedObject, mbd){
    applyBeanPostProcessorsBeforeInitialization(wrappedBean, beanName);
    invokeInitMethods(beanName, wrappedBean, mbd);
    applyBeanPostProcessorsAfterInitialization(wrappedBean, beanName);
}
```

也就是说，在Spring中，调用initializeBean()方法之前，调用了populateBean()方法为bean的属性赋值，为bean的属性赋好值之后，再调用initializeBean()方法进行初始化。

在initializeBean()中，调用自定义的初始化方法invokeInitMethods()之前，调用了applyBeanPostProcessorsBeforeInitialization()方法，而在调用自定义的初始化方法invokeInitMethods()之后，调用了applyBeanPostProcessorsAfterInitialization()方法。整个bean的初始化过程就结束了。

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