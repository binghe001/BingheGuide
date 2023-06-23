---
layout: post
category: binghe-spring-ioc
title: 第21章：BeanPostProcessor后置处理器浅析
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 有些小伙伴问我，学习Spring是不是不用学习到这么细节的程度啊？感觉这些细节的部分在实际工作中使用不到啊，我到底需不需要学习到这么细节的程度呢？我的答案是：有必要学习到这么细节的程度，而且是有机会、有条件一定要学！吃透Spring的原理和源码！往往拉开人与人之间差距的就是这些细节的部分，当前只要是使用Java技术栈开发的Web项目，几乎都会使用Spring框架。而且目前各招聘网站上对于Java开发的要求几乎清一色的都是熟悉或者精通Spring。所以，你，很有必要学习Spring的细节知识点。
lock: need
---

# 《Spring注解驱动开发》第21章：BeanPostProcessor后置处理器浅析

## 写在前面

> 有些小伙伴问我，学习Spring是不是不用学习到这么细节的程度啊？感觉这些细节的部分在实际工作中使用不到啊，我到底需不需要学习到这么细节的程度呢？我的答案是：有必要学习到这么细节的程度，而且是有机会、有条件一定要学！吃透Spring的原理和源码！往往拉开人与人之间差距的就是这些细节的部分，当前只要是使用Java技术栈开发的Web项目，几乎都会使用Spring框架。而且目前各招聘网站上对于Java开发的要求几乎清一色的都是熟悉或者精通Spring。所以，你，很有必要学习Spring的细节知识点。
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## BeanPostProcessor后置处理器概述

首先，我们来看下BeanPostProcessor的源码，看下它到底是个什么鬼，如下所示。

```java
package org.springframework.beans.factory.config;
import org.springframework.beans.BeansException;
import org.springframework.lang.Nullable;
public interface BeanPostProcessor {
	@Nullable
	default Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}
	@Nullable
	default Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

}
```

从源码可以看出：BeanPostProcessor是一个接口，其中有两个方法，postProcessBeforeInitialization和postProcessAfterInitialization两个方法，这两个方法分别是在spring容器中的bean初始化前后执行，所以spring容器中的每一个bean对象初始化前后，都会执行BeanPostProcessor接口的实现类的这两个方法。

也就是说，**postProcessBeforeInitialization方法会在bean实例化和属性设置之后，自定义初始化方法之前被调用，而postProcessAfterInitialization方法会在自定义初始化方法之后被调用。当容器中存在多个BeanPostProcessor的实现类时，会按照它们在容器中注册的顺序执行。对于自定义BeanPostProcessor实现类，还可以让其实现Ordered接口自定义排序。**

因此我们可以在每个bean对象初始化前后，加上自己的逻辑。实现方式：自定义一个BeanPostProcessor接口的实现类MyBeanPostProcessor，然后在类MyBeanPostProcessor的postProcessBeforeInitialization和postProcessAfterInitialization方法里面写上自己的逻辑。

## BeanPostProcessor后置处理器实例

我们创建一个MyBeanPostProcessor类，实现BeanPostProcessor接口，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试BeanPostProcessor
 */
@Component
public class MyBeanPostProcessor implements BeanPostProcessor {

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("调用了postProcessBeforeInitialization方法，beanName = " + beanName + ", bean = " + bean);
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("调用了postProcessAfterInitialization，beanName = " + beanName + ", bean = " + bean);
        return bean;
    }
}
```

接下来，我们运行BeanLifeCircleTest类的testBeanLifeCircle04()方法，输出的结果信息如下所示。

```bash
调用了postProcessBeforeInitialization方法，beanName = animalConfig, bean = io.mykit.spring.plugins.register.config.AnimalConfig$$EnhancerBySpringCGLIB$$e8ab4f2e@56528192
调用了postProcessAfterInitialization，beanName = animalConfig, bean = io.mykit.spring.plugins.register.config.AnimalConfig$$EnhancerBySpringCGLIB$$e8ab4f2e@56528192
Cat类的构造方法...
调用了postProcessBeforeInitialization方法，beanName = cat, bean = io.mykit.spring.plugins.register.bean.Cat@1b1473ab
Cat的postConstruct()方法...
Cat的init()方法...
调用了postProcessAfterInitialization，beanName = cat, bean = io.mykit.spring.plugins.register.bean.Cat@1b1473ab
Cat的preDestroy()方法...
Cat的destroy()方法...
```

可以看到，postProcessBeforeInitialization方法会在bean实例化和属性设置之后，自定义初始化方法之前被调用，而postProcessAfterInitialization方法会在自定义初始化方法之后被调用。

也可以让实现Ordered接口自定义排序，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试BeanPostProcessor
 */
@Component
public class MyBeanPostProcessor implements BeanPostProcessor, Ordered {

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("调用了postProcessBeforeInitialization方法，beanName = " + beanName + ", bean = " + bean);
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("调用了postProcessAfterInitialization，beanName = " + beanName + ", bean = " + bean);
        return bean;
    }

    @Override
    public int getOrder() {
        return 3;
    }
}
```

再次运行BeanLifeCircleTest类的testBeanLifeCircle04()方法，输出的结果信息如下所示。

```bash
调用了postProcessBeforeInitialization方法，beanName = animalConfig, bean = io.mykit.spring.plugins.register.config.AnimalConfig$$EnhancerBySpringCGLIB$$b045438a@1ed1993a
调用了postProcessAfterInitialization，beanName = animalConfig, bean = io.mykit.spring.plugins.register.config.AnimalConfig$$EnhancerBySpringCGLIB$$b045438a@1ed1993a
Cat类的构造方法...
调用了postProcessBeforeInitialization方法，beanName = cat, bean = io.mykit.spring.plugins.register.bean.Cat@36c88a32
Cat的postConstruct()方法...
Cat的init()方法...
调用了postProcessAfterInitialization，beanName = cat, bean = io.mykit.spring.plugins.register.bean.Cat@36c88a32
Cat的preDestroy()方法...
Cat的destroy()方法...
```

## BeanPostProcessor后置处理器作用

后置处理器用于bean对象初始化前后进行逻辑增强。spring提供了BeanPostProcessor的很多实现类，例如AutowiredAnnotationBeanPostProcessor用于@Autowired注解的实现，AnnotationAwareAspectJAutoProxyCreator用于SpringAOP的动态代理等等。

除此之外，我们还可以自定义BeanPostProcessor的实现类，在其中写入需要的逻辑。下面以AnnotationAwareAspectJAutoProxyCreator为例，说明后置处理器是怎样工作的。我们都知道springAOP的实现原理是动态代理，最终放入容器的是代理类的对象，而不是bean本身的对象，那么spring是什么时候做到这一步的？就是在AnnotationAwareAspectJAutoProxyCreator后置处理器的postProcessAfterInitialization方法，即bean对象初始化完成之后，后置处理器会判断该bean是否注册了切面，如果是，则生成代理对象注入容器。Spring中的关键代码如下所示。

```java
/**
  * Create a proxy with the configured interceptors if the bean is
  * identified as one to proxy by the subclass.
  * @see #getAdvicesAndAdvisorsForBean
  */
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

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

<p align="right">部分参考：https://www.cnblogs.com/dubhlinn/p/10668156.html</p>

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)