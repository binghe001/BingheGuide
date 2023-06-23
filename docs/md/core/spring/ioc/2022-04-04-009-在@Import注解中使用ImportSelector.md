---
layout: post
category: binghe-spring-ioc
title: 第08章：在@Import注解中使用ImportSelector接口导入bean
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在上一篇关于Spring的@Import注解的文章《[【Spring注解驱动开发】使用@Import注解给容器中快速导入一个组件](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484863&idx=1&sn=faca9edb10665d357089a290220ede2f&chksm=cee51a72f992936430364b018e07f062c2cb4bbe7111d0b615a1937215170976e5caf23a227b&token=1557037040&lang=zh_CN#rd)》中，我们简单介绍了如何使用@Import注解给容器中快速导入一个组件，而我们知道，@Import注解总共包含三种使用方法，分别为：直接填class数组方式；ImportSelector方法（重点）；ImportBeanDefinitionRegistrar方式。那么，今天，我们就一起来学习关于@Import注解非常重要的第二种方式：ImportSelector方式。
lock: need
---
# 《Spring注解驱动开发》第08章：在@Import注解中使用ImportSelector接口导入bean

## 写在前面

> 在上一篇关于Spring的@Import注解的文章《[【Spring注解驱动开发】使用@Import注解给容器中快速导入一个组件](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484863&idx=1&sn=faca9edb10665d357089a290220ede2f&chksm=cee51a72f992936430364b018e07f062c2cb4bbe7111d0b615a1937215170976e5caf23a227b&token=1557037040&lang=zh_CN#rd)》中，我们简单介绍了如何使用@Import注解给容器中快速导入一个组件，而我们知道，@Import注解总共包含三种使用方法，分别为：直接填class数组方式；ImportSelector方法（重点）；ImportBeanDefinitionRegistrar方式。那么，今天，我们就一起来学习关于@Import注解非常重要的第二种方式：ImportSelector方式。
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## ImportSelector接口概述

ImportSelector接口是至spring中导入外部配置的核心接口，在SpringBoot的自动化配置和@EnableXXX(功能性注解)都有它的存在。我们先来看一下ImportSelector接口的源码，如下所示。

```java
package org.springframework.context.annotation;

import java.util.function.Predicate;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.lang.Nullable;

public interface ImportSelector {
	String[] selectImports(AnnotationMetadata importingClassMetadata);
	@Nullable
	default Predicate<String> getExclusionFilter() {
		return null;
	}
}
```

该接口文档上说的明明白白，其主要作用是收集需要导入的配置类，selectImports()方法的返回值就是我们向Spring容器中导入的类的全类名。如果该接口的实现类同时实现EnvironmentAware， BeanFactoryAware  ，BeanClassLoaderAware或者ResourceLoaderAware，那么在调用其selectImports方法之前先调用上述接口中对应的方法，如果需要在所有的@Configuration处理完在导入时可以实现DeferredImportSelector接口。

在ImportSelector接口的selectImports()方法中，存在一个AnnotationMetadata类型的参数，这个参数能够获取到当前标注@Import注解的类的所有注解信息。

**注意：如果ImportSelector接口展开讲的话，可以单独写一篇文章，那我就放在下一篇文章中讲吧，这里就不赘述了，嘿嘿。**

## ImportSelector接口实例

首先，我们创建一个MyImportSelector类实现ImportSelector接口，如下所示。

```java
package io.mykit.spring.plugins.register.selector;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试@Import注解中使用ImportSelector
 *              自定义逻辑，返回需要导入的组件
 */
public class MyImportSelector implements ImportSelector {
    /**
     * 返回值为需要导入到容器中的bean的全类名数组
     * AnnotationMetadata：当前标注@Import注解的类的所有注解信息
     */
    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        return new String[0];
    }
}
```

接下来，我们在PersonConfig2类的@Import注解中，导入MyImportSelector类，如下所示。

```java
@Configuration
@Import({Department.class, Employee.class, MyImportSelector.class})
public class PersonConfig2 {
```

至于使用MyImportSelector导入哪些bean，就需要在MyImportSelector类的selectImports()方法中进行设置了，只要在MyImportSelector类的selectImports()方法中返回要导入的类的全类名（包名+类名）即可。

我们继承创建两个Java bean对象，分别为User和Role，如下所示。

* User类

```java
package io.mykit.spring.plugins.register.bean;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试ImportSelector
 */
public class User {
}
```

* Role类

```java
package io.mykit.spring.plugins.register.bean;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试ImportSelector
 */
public class Role {
}
```

接下来，我们将User类和Role类的全类名返回到MyImportSelector类的selectImports()方法中，此时，MyImportSelector类的selectImports()方法如下所示。

```java
/**
 * 返回值为需要导入到容器中的bean的全类名数组
 * AnnotationMetadata：当前标注@Import注解的类的所有注解信息
 */
@Override
public String[] selectImports(AnnotationMetadata importingClassMetadata) {
    return new String[]{
        User.class.getName(),
        Role.class.getName()
    };
}
```

接下来，我们运行SpringBeanTest类的testAnnotationConfig7()方法，输出的结果信息如下所示。

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

可以看到，输出结果中多出了io.mykit.spring.plugins.register.bean.User和io.mykit.spring.plugins.register.bean.Role。

说明使用ImportSelector已经成功将User类和Role类导入到了Spring容器中。

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 冰河技术 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)