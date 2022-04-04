---
layout: post
category: binghe-spring-ioc
title: Spring中这么重要的AnnotationAwareAspectJAutoProxyCreator类是干嘛的？
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 停更了很久的【Spring注解系列】专题，终于重新更新了，我们还是接着之前的文章继续往下更新。在《[【Spring注解驱动开发】二狗子让我给他讲讲@EnableAspectJAutoProxy注解](https://mp.weixin.qq.com/s?__biz=Mzg4MjU0OTM1OA==&mid=2247489210&idx=1&sn=becc26b4b2d681007bfa52ce2448eed5&chksm=cf55a1bbf82228ada0bd72aec8670bf774918b7bbaa2613baa59d77008566400a75b7d5be6a9&token=464268589&lang=zh_CN#rd)》一文中，我们通过查看`@EnableAspectJAutoProxy` 注解的源码，如下所示。
lock: need
---

# Spring中这么重要的AnnotationAwareAspectJAutoProxyCreator类是干嘛的？

**大家好，我是冰河~~**

停更了很久的【Spring注解系列】专题，终于重新更新了，我们还是接着之前的文章继续往下更新。在《[【Spring注解驱动开发】二狗子让我给他讲讲@EnableAspectJAutoProxy注解](https://mp.weixin.qq.com/s?__biz=Mzg4MjU0OTM1OA==&mid=2247489210&idx=1&sn=becc26b4b2d681007bfa52ce2448eed5&chksm=cf55a1bbf82228ada0bd72aec8670bf774918b7bbaa2613baa59d77008566400a75b7d5be6a9&token=464268589&lang=zh_CN#rd)》一文中，我们通过查看`@EnableAspectJAutoProxy` 注解的源码，如下所示。

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
@Import(AspectJAutoProxyRegistrar.class)
public @interface EnableAspectJAutoProxy {
 boolean proxyTargetClass() default false;
 boolean exposeProxy() default false;
}
```

得知，`@EnableAspectJAutoProxy `注解是通过使用`@Import(AspectJAutoProxyRegistrar.class)` 给容器中注册一个名字叫做`internalAutoProxyCreator = AnnotationAwareAspectJAutoProxyCreator`的组件。

并且我们也分析了AnnotationAwareAspectJAutoProxyCreato类的核心继承关系，如下所示。

```bash
  AnnotationAwareAspectJAutoProxyCreator
       --AspectJAwareAdvisorAutoProxyCreator
         --AbstractAdvisorAutoProxyCreator
           --AbstractAutoProxyCreator
             -- ProxyProcessorSupport， SmartInstantiationAwareBeanPostProcessor, BeanFactoryAware
```

查看继承关系可以发现，此类实现了`Aware`与`BeanPostProcessor`接口，这两个接口都和Spring bean的初始化有关，由此推测此类主要处理方法都来自这两个接口的实现方法。同时该类也实现了order方法。

那今天，我们就来看看`AnnotationAwareAspectJAutoProxyCreator` 类的调用流程，具体来说，就是看看 ``AnnotationAwareAspectJAutoProxyCreator` 作为BeanPostProcessor做了哪些工作，作为BeanFactoryAware做了哪些工作。

## 分析AbstractAutoProxyCreator类

在 `AnnotationAwareAspectJAutoProxyCreator`类的继承关系上可以看出， 是在`AbstractAutoProxyCreator`类开始实现 `SmartInstantiationAwareBeanPostProcessor`接口和 `BeanFactoryAware` 接口的。

所以，我们先来看看 `AbstractAutoProxyCreator` 类进行分析。

由 `AbstractAutoProxyCreator` 类的定义我们可以看出，`AbstractAutoProxyCreator`类直接实现了`SmartInstantiationAwareBeanPostProcessor` 接口和 `BeanFactoryAware` 接口。

```java
public abstract class AbstractAutoProxyCreator extends ProxyProcessorSupport
		implements SmartInstantiationAwareBeanPostProcessor, BeanFactoryAware {
```

既然 `AbstractAutoProxyCreator` 实现了 `BeanFactoryAware` 接口， 那么 `AbstractAutoProxyCreator` 类中就一定存在setBeanFactory()方法，如下所示。

```java
@Override
public void setBeanFactory(BeanFactory beanFactory) {
    this.beanFactory = beanFactory;
}

@Nullable
protected BeanFactory getBeanFactory() {
    return this.beanFactory;
}
```

果然，我们在 `AbstractAutoProxyCreator` 类中找到了setBeanFactory()方法和getBeanFactory()方法。

另外，在 `AbstractAutoProxyCreator` 类中还存在与BeanPostProcessor后置处理器有关的方法，分别为：postProcessBeforeInstantiation()、postProcessAfterInstantiation()、postProcessProperties()、postProcessBeforeInitialization()、postProcessAfterInitialization()。整体源代码如下所示。

```java
@Override
public Object postProcessBeforeInstantiation(Class<?> beanClass, String beanName) {
    Object cacheKey = getCacheKey(beanClass, beanName);
    if (!StringUtils.hasLength(beanName) || !this.targetSourcedBeans.contains(beanName)){
        if (this.advisedBeans.containsKey(cacheKey)) {
            return null;
        }
        if (isInfrastructureClass(beanClass) || shouldSkip(beanClass, beanName)) {
            this.advisedBeans.put(cacheKey, Boolean.FALSE);
            return null;
        }
    }
    TargetSource targetSource = getCustomTargetSource(beanClass, beanName);
    if (targetSource != null) {
        if (StringUtils.hasLength(beanName)) {
            this.targetSourcedBeans.add(beanName);
        }
        Object[] specificInterceptors = getAdvicesAndAdvisorsForBean(beanClass, beanName, targetSource);
        Object proxy = createProxy(beanClass, beanName, specificInterceptors, targetSource);
        this.proxyTypes.put(cacheKey, proxy.getClass());
        return proxy;
    }
    return null;
}

@Override
public boolean postProcessAfterInstantiation(Object bean, String beanName) {
    return true;
}

@Override
public PropertyValues postProcessProperties(PropertyValues pvs, Object bean, String beanName) {
    return pvs;
}

@Override
public Object postProcessBeforeInitialization(Object bean, String beanName) {
    return bean;
}

@Override
public Object postProcessAfterInitialization(@Nullable Object bean, String beanName) {
    if (bean != null) {
        Object cacheKey = getCacheKey(bean.getClass(), beanName);
        if (this.earlyProxyReferences.remove(cacheKey) != bean) {
            return wrapIfNecessary(bean, beanName, cacheKey);
        }
    }
    return bean;
}
```

也就是说，在`AbstractAutoProxyCreator` 类中，存在后置处理器的逻辑。

到这，我们就在`AbstractAutoProxyCreator` 类中看到了`BeanFactoryAware` 的实现和后置处理器的实现。

接下来，我们再来看看`AbstractAutoProxyCreator` 的子类 `AbstractAdvisorAutoProxyCreator`类。

## 分析AbstractAdvisorAutoProxyCreator类

在 `AbstractAdvisorAutoProxyCreator`类中，我们会看到如下代码。

```java
@Override
public void setBeanFactory(BeanFactory beanFactory) {
    super.setBeanFactory(beanFactory);
    if (!(beanFactory instanceof ConfigurableListableBeanFactory)) {
        throw new IllegalArgumentException(
            "AdvisorAutoProxyCreator requires a ConfigurableListableBeanFactory: " + beanFactory);
    }
    initBeanFactory((ConfigurableListableBeanFactory) beanFactory);
}
```

说明在`AbstractAdvisorAutoProxyCreator`类中重写了setBeanFactory()方法。并且在`AbstractAdvisorAutoProxyCreator`类的setBeanFactory()方法中，首先会调用`AbstractAutoProxyCreator` 类中的setBeanFactory()方法。

在setBeanFactory()方法中会调用initBeanFactory()方法，initBeanFactory()方法的实现如下所示。

```java
protected void initBeanFactory(ConfigurableListableBeanFactory beanFactory) {
    this.advisorRetrievalHelper = new BeanFactoryAdvisorRetrievalHelperAdapter(beanFactory);
}
```

initBeanFactory()方法的实现比较简单，这里，我就不多说了。

另外，我们并没有在`AbstractAdvisorAutoProxyCreator`类中找到与后置处理器相关的方法。

接下来，我们继续分析`AbstractAdvisorAutoProxyCreator`类的子类AspectJAwareAdvisorAutoProxyCreator类。

## 分析AspectJAwareAdvisorAutoProxyCreator类

通过查看`AspectJAwareAdvisorAutoProxyCreator`类的源码，我们得知，在 `AspectJAwareAdvisorAutoProxyCreator`类中没有与后置处理器相关的代码。所以，我们继续向上分析 `AspectJAwareAdvisorAutoProxyCreator`类的子类 `AnnotationAwareAspectJAutoProxyCreator`。

## 分析AnnotationAwareAspectJAutoProxyCreator类

在 `AnnotationAwareAspectJAutoProxyCreator`类中，我们可以找到一个initBeanFactory()方法，如下所示。

```java
@Override
protected void initBeanFactory(ConfigurableListableBeanFactory beanFactory) {
    super.initBeanFactory(beanFactory);
    if (this.aspectJAdvisorFactory == null) {
        this.aspectJAdvisorFactory = new ReflectiveAspectJAdvisorFactory(beanFactory);
    }
    this.aspectJAdvisorsBuilder =
        new BeanFactoryAspectJAdvisorsBuilderAdapter(beanFactory, this.aspectJAdvisorFactory);
}
```

看到这里，小伙伴们对于setBeanFactory的调用流程有点清晰了吧？其实setBeanFactory()的调用流程为：首先会执行 `AbstractAdvisorAutoProxyCreator`类中的setBeanFactory()方法，在`AbstractAdvisorAutoProxyCreator`类中的setBeanFactory()方法中会调用其父类`AbstractAutoProxyCreator` 中的setBeanFactory()方法，然后在`AbstractAdvisorAutoProxyCreator`类中的setBeanFactory()方法中调用initBeanFactory()方法。由于在子类`AnnotationAwareAspectJAutoProxyCreator`中重写了initBeanFactory()方法，最终调用的就是`AnnotationAwareAspectJAutoProxyCreator`类中的initBeanFactory()方法。这么说有点绕，我们来看一张图吧。

![](https://img-blog.csdnimg.cn/20210311000758821.png)




注意，上图中的`AbstractAdvisorAutoProxyCreator`类中的setBeanFactory()方法作为程序调用的入口，它会依次调用`AbstractAutoProxyCreator#setBeanFactory()` 和 `AnnotationAwareAspectJAutoProxyCreator#initBeanFactory()` ，然后，再由 `AnnotationAwareAspectJAutoProxyCreator#initBeanFactory()` 调用 `AbstractAdvisorAutoProxyCreator#initBeanFactory()`。

除此之外，我们在`AnnotationAwareAspectJAutoProxyCreator`类中，并没有发现与后置处理器相关的代码了。

好了，以上就是我们分析的有关`AnnotationAwareAspectJAutoProxyCreator`类的源码。在下一篇文章中，我们开始debug调试这些源代码的具体执行流程。

**好了，今天就到这儿吧，我是冰河，大家有啥问题可以在下方留言，也可以加我微信：sun_shine_lyz，我拉你进群，一起交流技术，一起进阶，一起牛逼~~**

![](https://img-blog.csdnimg.cn/20210102235308513.jpg)

## 冰河原创PDF

关注 **冰河技术** 微信公众号：

回复 “**并发编程**” 领取《深入理解高并发编程（第1版）》PDF文档。

回复 “**并发源码**” 领取《并发编程核心知识（源码分析篇 第1版）》PDF文档。

回复 “**我要进大厂**” 领取《我要进大厂系列之面试圣经（第1版）》PDF文档。

回复 ”**限流**“ 领取《亿级流量下的分布式解决方案》PDF文档。

回复 “**设计模式**” 领取《深入浅出Java23种设计模式》PDF文档。

回复 “**Java8新特性**” 领取 《Java8新特性教程》PDF文档。

回复 “**分布式存储**” 领取《跟冰河学习分布式存储技术》 PDF文档。

回复 “**Nginx**” 领取《跟冰河学习Nginx技术》PDF文档。

回复 “**互联网工程**” 领取《跟冰河学习互联网工程技术》PDF文档。


## 写在最后

如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)
