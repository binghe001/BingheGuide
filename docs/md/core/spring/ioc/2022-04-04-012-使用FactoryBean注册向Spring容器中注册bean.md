---
layout: post
category: binghe-spring-ioc
title: 第11章：使用FactoryBean向Spring容器中注册bean
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在前面的文章中，我们知道可以通过多种方式向Spring容器中注册bean。可以使用@Configuration结合@Bean向Spring容器中注册bean；可以按照条件向Spring容器中注册bean；可以使用@Import向容器中快速导入bean对象；可以在@Import中使用ImportBeanDefinitionRegistrar向容器中注册bean。
lock: need
---

# 《Spring注解驱动开发》第11章：使用FactoryBean向Spring容器中注册bean

## 写在前面

> 在前面的文章中，我们知道可以通过多种方式向Spring容器中注册bean。可以使用@Configuration结合@Bean向Spring容器中注册bean；可以按照条件向Spring容器中注册bean；可以使用@Import向容器中快速导入bean对象；可以在@Import中使用ImportBeanDefinitionRegistrar向容器中注册bean。
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## FactoryBean概述

一般情况下，Spring通过反射机制利用bean的class属性指定实现类来实例化bean 。在某些情况下，实例化bean过程比较复杂，如果按照传统的方式，则需要在<bean>标签中提供大量的配置信息，配置方式的灵活性是受限的，这时采用编码的方式可以得到一个更加简单的方案。Spring为此提供了一个org.springframework.bean.factory.FactoryBean的工厂类接口，用户可以通过实现该接口定制实例化bean的逻辑。

FactoryBean接口对于Spring框架来说占有重要的地位，Spring 自身就提供了70多个FactoryBean的实现。它们隐藏了实例化一些复杂bean的细节，给上层应用带来了便利。从Spring 3.0 开始， FactoryBean开始支持泛型，即接口声明改为FactoryBean<T> 的形式：

在Spring 5.2.6版本中，FactoryBean接口的定义如下所示。

```java
package org.springframework.beans.factory;
import org.springframework.lang.Nullable;

public interface FactoryBean<T> {

	String OBJECT_TYPE_ATTRIBUTE = "factoryBeanObjectType";

	@Nullable
	T getObject() throws Exception;

	@Nullable
	Class<?> getObjectType();

	default boolean isSingleton() {
		return true;
	}
}
```

* T getObject()：返回由FactoryBean创建的bean实例，如果isSingleton()返回true，则该实例会放到Spring容器中单实例缓存池中。

* boolean isSingleton()：返回由FactoryBean创建的bean实例的作用域是singleton还是prototype。

* Class<T> getObjectType()：返回FactoryBean创建的bean类型。

**这里，需要注意的是：当配置文件中<bean>标签的class属性配置的实现类是FactoryBean时，通过 getBean()方法返回的不是FactoryBean本身，而是FactoryBean#getObject()方法所返回的对象，相当于FactoryBean#getObject()代理了getBean()方法。**

## FactoryBean实例

首先，创建一个PersonFactoryBean，实现FactoryBean接口，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.factory.FactoryBean;
/**
 * @author binghe
 * @version 1.0.0
 * @description 商品的FactoryBean，测试FactoryBean
 */
public class PersonFactoryBean implements FactoryBean<Person> {

    //返回一个Person对象，这个对象会被注册到Spring容器中
    @Override
    public Person getObject() throws Exception {
        return new Person();
    }

    @Override
    public Class<?> getObjectType() {
        return Person.class;
    }

    //bean是否为单例;true:是；false:否
    @Override
    public boolean isSingleton() {
        return true;
    }
}
```

接下来，我们在PersonConfig2类中加入PersonFactoryBean的声明，如下所示。

```java
@Bean
public PersonFactoryBean personFactoryBean(){
    return new PersonFactoryBean();
}
```

这里需要小伙伴们注意的是：我在这里使用@Bean注解向Spring容器中添加的是PersonFactory对象。那我们就来看看Spring容器中有哪些bean。接下来，运行SpringBeanTest类中的testAnnotationConfig7()方法，输出的结果信息如下所示。

```java
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
personFactoryBean
company
```

可以看到，结果信息中输出了一个personFactoryBean，我们看下这个personFactoryBean到底是个什么鬼！此时，我们对SpringBeanTest类中的testAnnotationConfig7()方法稍加改动，添加获取personFactoryBean的代码，并输出personFactoryBean实例的类型，如下所示。

```java
@Test
public void testAnnotationConfig7(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig2.class);
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);

    Object personFactoryBean = context.getBean("personFactoryBean");
    System.out.println("personFactoryBean实例的类型为：" + personFactoryBean.getClass());
}
```

再次运行SpringBeanTest类中的testAnnotationConfig7()方法，输出的结果信息如下所示。

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
personFactoryBean
company
personFactoryBean实例的类型为：class io.mykit.spring.plugins.register.bean.Person
```

可以看到，虽然我在代码中使用@Bean注解注入的PersonFactoryBean对象，但是，实际上从Spring容器中获取到的bean对象却是调用PersonFactoryBean类中的getObject()获取到的Person对象。

**看到这里，是不是有种豁然开朗的感觉！！！**

在PersonFactoryBean类中，我们将Person对象设置为单实例bean，接下来，我们在SpringBeanTest类中的testAnnotationConfig7()方法多次获取Person对象，并输出多次获取的对象是否为同一对象，如下所示。

```java
@Test
public void testAnnotationConfig7(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig2.class);
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);

    Object personFactoryBean1 = context.getBean("personFactoryBean");
    Object personFactoryBean2 = context.getBean("personFactoryBean");
    System.out.println(personFactoryBean1 == personFactoryBean2);
}
```

运行testAnnotationConfig7()方法输出的结果信息如下所示。

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
personFactoryBean
company
true
```

可以看到，在PersonFactoryBean类的isSingleton()方法中返回true时，每次获取到的Person对象都是同一个对象，说明Person对象是单实例bean。

这里，可能就会有小伙伴要问了，如果将Person对象修改成多实例bean呢？别急，这里我们只需要在PersonFactoryBean类的isSingleton()方法中返回false，即可将Person对象设置为多实例bean，如下所示。

```java
//bean是否为单例;true:是；false:否
@Override
public boolean isSingleton() {
    return false;
}
```

再次运行SpringBeanTest类中的testAnnotationConfig7()方法，输出的结果信息如下所示。

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
personFactoryBean
company
false
```

可以看到，最终结果返回了false，说明此时Person对象是多实例bean。

## 如何在Spring容器中获取到FactoryBean对象？

之前，我们使用@Bean注解向Spring容器中注册的PersonFactoryBean，获取出来的确实Person对象。那么，小伙伴们可能会问：我就想获取PersonFactoryBean实例，该怎么办呢？

其实，这也很简单， **只需要在获取bean对象时，在id前面加上&符号即可**。

打开我们的测试类SpringBeanTest，在testAnnotationConfig7()方法中添加获取PersonFactoryBean实例的代码，如下所示。

```java
@Test
public void testAnnotationConfig7(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig2.class);
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);

    Object personFactoryBean1 = context.getBean("personFactoryBean");
    Object personFactoryBean2 = context.getBean("personFactoryBean");
    System.out.println("personFactoryBean1类型：" + personFactoryBean1.getClass());
    System.out.println("personFactoryBean2类型：" + personFactoryBean2.getClass());
    System.out.println(personFactoryBean1 == personFactoryBean2);

    Object personFactoryBean3 = context.getBean("&personFactoryBean");
    System.out.println("personFactoryBean3类型：" + personFactoryBean3.getClass());
}
```

运行SpringBeanTest类中的testAnnotationConfig7()方法，输出的结果信息如下所示。

```java
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
personFactoryBean
company
personFactoryBean1类型：class io.mykit.spring.plugins.register.bean.Person
personFactoryBean2类型：class io.mykit.spring.plugins.register.bean.Person
false
personFactoryBean3类型：class io.mykit.spring.plugins.register.bean.PersonFactoryBean
```

可以看到，在获取bean时，在id前面加上&符号就会获取到PersonFactoryBean实例对象。

那问题又来了！！**为什么在id前面加上&符号就会获取到PersonFactoryBean实例对象呢？**

接下来，我们就揭开这个神秘的面纱，打开BeanFactory接口，

```java
package org.springframework.beans.factory;
import org.springframework.beans.BeansException;
import org.springframework.core.ResolvableType;
import org.springframework.lang.Nullable;

public interface BeanFactory {
	String FACTORY_BEAN_PREFIX = "&";
    /**************以下省略n行代码***************/
}
```

看到这里，是不是明白了呢？没错，在BeanFactory接口中定义了一个&前缀，只要我们使用bean的id来从Spring容器中获取bean时，Spring就会知道我们是在获取FactoryBean本身。

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 冰河技术 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)