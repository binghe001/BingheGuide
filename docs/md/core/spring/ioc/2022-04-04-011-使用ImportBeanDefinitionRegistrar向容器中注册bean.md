---
layout: post
category: binghe-spring-ioc
title: 第10章：在@Import注解中使用ImportBeanDefinitionRegistrar向容器中注册bean
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在前面的文章中，我们学习了如何使用@Import注解向Spring容器中导入bean，可以使用@Import注解快速向容器中导入bean，小伙伴们可以参见《[【Spring注解驱动开发】使用@Import注解给容器中快速导入一个组件](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484863&idx=1&sn=faca9edb10665d357089a290220ede2f&chksm=cee51a72f992936430364b018e07f062c2cb4bbe7111d0b615a1937215170976e5caf23a227b&token=1611686244&lang=zh_CN#rd)》。可以在@Import注解中使用ImportSelector接口导入bean，小伙伴们可以参见《[【Spring注解驱动开发】在@Import注解中使用ImportSelector接口导入bean](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484870&idx=1&sn=a371224a8c2b9f70a41ff88976d6b0e6&chksm=cee51a0bf992931d3e39ddf70061ac8de713c817ec6561075a740eb18c7269ce66d50459dd58&token=1611686244&lang=zh_CN#rd)》一文。今天，我们就来说说，如何在@Import注解中使用ImportBeanDefinitionRegistrar向容器中注册bean。
lock: need
---

# 《Spring注解驱动开发》第10章：在@Import注解中使用ImportBeanDefinitionRegistrar向容器中注册bean

## 写在前面

> 在前面的文章中，我们学习了如何使用@Import注解向Spring容器中导入bean，可以使用@Import注解快速向容器中导入bean，小伙伴们可以参见《[【Spring注解驱动开发】使用@Import注解给容器中快速导入一个组件](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484863&idx=1&sn=faca9edb10665d357089a290220ede2f&chksm=cee51a72f992936430364b018e07f062c2cb4bbe7111d0b615a1937215170976e5caf23a227b&token=1611686244&lang=zh_CN#rd)》。可以在@Import注解中使用ImportSelector接口导入bean，小伙伴们可以参见《[【Spring注解驱动开发】在@Import注解中使用ImportSelector接口导入bean](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484870&idx=1&sn=a371224a8c2b9f70a41ff88976d6b0e6&chksm=cee51a0bf992931d3e39ddf70061ac8de713c817ec6561075a740eb18c7269ce66d50459dd58&token=1611686244&lang=zh_CN#rd)》一文。今天，我们就来说说，如何在@Import注解中使用ImportBeanDefinitionRegistrar向容器中注册bean。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## ImportBeanDefinitionRegistrar概述

### 概述

我们先来看看ImportBeanDefinitionRegistrar是个什么鬼，点击进入ImportBeanDefinitionRegistrar源码，如下所示。

```java
package org.springframework.context.annotation;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.BeanNameGenerator;
import org.springframework.core.type.AnnotationMetadata;

public interface ImportBeanDefinitionRegistrar {

	default void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry,
			BeanNameGenerator importBeanNameGenerator) {

		registerBeanDefinitions(importingClassMetadata, registry);
	}

	default void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
	}

}
```

由源码可以看出，ImportBeanDefinitionRegistrar本质上是一个接口。在ImportBeanDefinitionRegistrar接口中，有一个registerBeanDefinitions()方法，通过registerBeanDefinitions()方法，我们可以向Spring容器中注册bean实例。

Spring官方在动态注册bean时，大部分套路其实是使用ImportBeanDefinitionRegistrar接口。

所有实现了该接口的类都会被ConfigurationClassPostProcessor处理，ConfigurationClassPostProcessor实现了BeanFactoryPostProcessor接口，所以ImportBeanDefinitionRegistrar中动态注册的bean是优先于依赖其的bean初始化的，也能被aop、validator等机制处理。

### 使用方法

ImportBeanDefinitionRegistrar需要配合@Configuration和@Import注解，@Configuration定义Java格式的Spring配置文件，@Import注解导入实现了ImportBeanDefinitionRegistrar接口的类。

## ImportBeanDefinitionRegistrar实例

既然ImportBeanDefinitionRegistrar是一个接口，那我们就创建一个MyImportBeanDefinitionRegistrar类，实现ImportBeanDefinitionRegistrar接口，如下所示。

```java
package io.mykit.spring.plugins.register.condition;

import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;

/**
 * @author binghe
 * @version 1.0.0
 * @description ImportBeanDefinitionRegistrar的实现类
 */
public class MyImportBeanDefinitionRegistrar implements ImportBeanDefinitionRegistrar {

    /**
     * AnnotationMetadata: 当前类的注解信息
     * BeanDefinitionRegistry：BeanDefinition注册类
     * 通过调用BeanDefinitionRegistry接口的registerBeanDefinition()方法，可以将所有需要添加到容器中的bean注入到容器中。
     */
    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry){

    }
}
```

可以看到，这里，我们先创建了MyImportBeanDefinitionRegistrar类的大体框架。接下来，我们在PersonConfig2类上的@Import注解中，添加MyImportBeanDefinitionRegistrar类，如下所示。

```java
@Configuration
@Import({Department.class, Employee.class, MyImportSelector.class, MyImportBeanDefinitionRegistrar.class})
public class PersonConfig2 {
```

接下来，创建一个Company类，作为测试测试ImportBeanDefinitionRegistrar接口的bean，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试ImportBeanDefinitionRegistrar接口的使用
 */
public class Company {
}
```

接下来，就要实现MyImportBeanDefinitionRegistrar类中的registerBeanDefinitions()方法的逻辑了，添加逻辑后的registerBeanDefinitions()方法如下所示。

```java
    /**
     * AnnotationMetadata: 当前类的注解信息
     * BeanDefinitionRegistry：BeanDefinition注册类
     * 通过调用BeanDefinitionRegistry接口的registerBeanDefinition()方法，可以将所有需要添加到容器中的bean注入到容器中。
     */
    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry){
        boolean employee = registry.containsBeanDefinition("employee");
        boolean department = registry.containsBeanDefinition("department");
        if (employee && department){
            BeanDefinition beanDefinition = new RootBeanDefinition(Company.class);
            registry.registerBeanDefinition("company", beanDefinition);
        }
    }
```

registerBeanDefinitions()方法的实现逻辑很简单，就是判断Spring容器中是否同时存在以employee命名的bean和以department命名的bean，如果同时存在以employee命名的bean和以department命名的bean，则向Spring容器中注入一个以company命名的bean。

接下来，我们就运行SpringBeanTest类中的testAnnotationConfig7()方法来进行测试，输出结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig2
io.mykit.spring.plugins.register.bean.Department
io.mykit.spring.plugins.register.bean.Employee
io.mykit.spring.plugins.register.bean.User
io.mykit.spring.plugins.register.bean.Role
person
binghe001
```

可以看到，在输出结果中，并没有看到“company”，这是因为输出结果中存在io.mykit.spring.plugins.register.bean.Department和io.mykit.spring.plugins.register.bean.Employee，并不存在我们代码逻辑中的department和employee。所以，我们将registerBeanDefinitions()方法的逻辑稍微修改下，修改后的代码如下所示。

```java
/**
  * AnnotationMetadata: 当前类的注解信息
  * BeanDefinitionRegistry：BeanDefinition注册类
  * 通过调用BeanDefinitionRegistry接口的registerBeanDefinition()方法，可以将所有需要添加到容器中的bean注入到容器中。
  */
@Override
public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry){
    boolean employee = registry.containsBeanDefinition(Employee.class.getName());
    boolean department = registry.containsBeanDefinition(Department.class.getName());
    if (employee && department){
        BeanDefinition beanDefinition = new RootBeanDefinition(Company.class);
        registry.registerBeanDefinition("company", beanDefinition);
    }
}
```

接下来，我们再次运行SpringBeanTest类中的testAnnotationConfig7()方法来进行测试，输出结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig2
io.mykit.spring.plugins.register.bean.Department
io.mykit.spring.plugins.register.bean.Employee
io.mykit.spring.plugins.register.bean.User
io.mykit.spring.plugins.register.bean.Role
person
binghe001
company
```

可以看到，此时输出了company，说明Spring容器中已经成功注册了以company命名的bean。

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 冰河技术 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。


> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)