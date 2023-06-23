---
layout: post
category: binghe-spring-ioc
title: 第23章：使用@PropertySource加载配置文件
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 很多小伙伴都在问：冰河，你的Spring专题更新完了吗？怎么感觉像是写了一半啊？我：没有更新完呀，整个专题预计会有70多篇。那怎么更新了一半就去写别的了呢？那是因为有很多其他的小伙伴在后台留言说：急需学习一些其他的技术，所以，临时调整的。放心，Spring专题会持续更新的！这不，今天，我们就继续更新Spring专题。不出意外的话，会一直持续更新完！！
lock: need
---

# 《Spring注解驱动开发》第23章：使用@PropertySource加载配置文件

## 写在前面

> 很多小伙伴都在问：冰河，你的Spring专题更新完了吗？怎么感觉像是写了一半啊？我：没有更新完呀，整个专题预计会有70多篇。那怎么更新了一半就去写别的了呢？那是因为有很多其他的小伙伴在后台留言说：急需学习一些其他的技术，所以，临时调整的。放心，Spring专题会持续更新的！这不，今天，我们就继续更新Spring专题。不出意外的话，会一直持续更新完！！
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## @PropertySource注解概述

@PropertySource注解是Spring 3.1开始引入的配置类注解。通过@PropertySource注解将properties配置文件中的值存储到Spring的 Environment中，Environment接口提供方法去读取配置文件中的值，参数是properties文件中定义的key值。也可以使用@Value 注解用${}占位符注入属性。

@PropertySource注解的源代码如下所示。

```java
package org.springframework.context.annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.core.io.support.PropertySourceFactory;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Repeatable(PropertySources.class)
public @interface PropertySource {
	String name() default "";
	String[] value();
	boolean ignoreResourceNotFound() default false;
	String encoding() default "";
	Class<? extends PropertySourceFactory> factory() default PropertySourceFactory.class;
}

```

从@PropertySource的源码可以看出，我们可以通过@PropertySource注解指定多个properties文件，可以使用如下形式进行指定。

```java
@PropertySource(value={"classpath:xxx.properties", "classpath:yyy.properties"})
```

细心的读者可以看到，在@PropertySource注解类的上面标注了如下的注解信息。

```java
@Repeatable(PropertySources.class)
```

看到这里，小伙伴们是不是有种恍然大悟的感觉呢？没错，我们也可以使用@PropertySources注解来指定properties配置文件。

## @PropertySources注解

首先，我们也是看下@PropertySources注解的源码，如下所示。

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
public @interface PropertySources {
	PropertySource[] value();
}
```

@PropertySources注解的源码比较简单，只有一个PropertySource[]数组类型的属性value，那我们如何使用@PropertySources注解指定配置文件呢？其实也很简单，就是使用如下所示的方式就可以了。

```java
@PropertySources(value={
    @PropertySource(value={"classpath:xxx.properties"}),
    @PropertySource(value={"classpath:yyy.properties"}),
})
```

是不是很简单呢？接下来，我们就以一个小案例来说明@PropertySource注解的用法。

## 案例准备

首先，我们在工程的src/main/resources目录下创建一个配置文件person.properties文件，文件的内容如下所示。

```bash
person.nickName=zhangsan
```

接下来，我们在Person类中新增一个字段nickName，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.beans.factory.annotation.Value;
import java.io.Serializable;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试实体类
 */
@Data
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Person implements Serializable {
    private static final long serialVersionUID = 7387479910468805194L;
    @Value("binghe")
    private String name;
    @Value("#{20-2}")
    private Integer age;
    private String nickName;
}
```

目前，我们并没有为Person类的nickName字段赋值，所以，此时Person类的nickName字段的值为空。我们运行下PropertyValueTest类的testPropertyValue01()方法来看下输出结果，如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
propertyValueConfig
person
================================
Person(name=binghe, age=18, nickName=null)
Process finished with exit code 0
```

可以看出，Person类的nickName字段的值确实输出了null。

## 使用xml文件方式获取值

如果我们需要在xml文件中获取person.properties文件中的值，则我们首先需要在Spring的xml文件中引入context名称空间，并且使用context命名空间导入person.properties文件，之后在bean的属性字段中使用如下方式将person.properties文件中的值注入到Person类的nickName字段上。

```xml
<context:property-placeholder location="classpath:person.properties" />
<bean id = "person" class="io.mykit.spring.plugins.register.bean.Person">
    <property name="name" value="binghe"></property>
    <property name="age" value="18"></property>
    <property name="nickName" value="${person.nickName}"></property>
</bean>
```

整个bean.xml文件的内容如下所示。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/context
                           http://www.springframework.org/context/spring-context.xsd ">
    
    <context:property-placeholder location="classpath:person.properties"/>
    <bean id = "person" class="io.mykit.spring.plugins.register.bean.Person">
        <property name="name" value="binghe"></property>
        <property name="age" value="18"></property>
        <property name="nickName" value="${person.nickName}"></property>
    </bean>
</beans>
```

这样就可以将person.properties文件中的值注入到Person的nickName字段上。接下来，我们在PropertyValueTest类中创建testPropertyValue02()测试方法，如下所示。

```java
@Test
public void testPropertyValue02(){
    ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext("classpath:beans.xml");
    Person person = (Person) context.getBean("person");
    System.out.println(person);
}
```

我们运行PropertyValueTest类中创建的testPropertyValue02()方法，输出的结果信息如下所示。

```bash
Person(name=binghe, age=18, nickName=zhangsan)
```

## 使用注解方式获取值

如果我们使用注解的方式该如何做呢？首先，我们需要在PropertyValueConfig配置类上添加@PropertySource注解，如下所示。

```java
package io.mykit.spring.plugins.register.config;
import io.mykit.spring.plugins.register.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试属性赋值
 */
@PropertySource(value = {"classpath:person.properties"})
@Configuration
public class PropertyValueConfig {
    @Bean
    public Person person(){
        return new Person();
    }
}
```

这里使用的`@PropertySource(value = {"classpath:person.properties"})`就相当于xml文件中使用的`<context:property-placeholder location="classpath:person.properties"/>`。

接下来，我们就可以在Person类的nickName字段上使用@Value注解来获取person.properties文件中的值了，如下所示。

```java
@Value("${person.nickName}")
private String nickName;
```

配置完成后，我们再次运行PropertyValueTest类的testPropertyValue01()方法来看下输出结果，如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
propertyValueConfig
person
================================
Person(name=binghe, age=18, nickName=zhangsan)
```

可以看到，此时Person类的nickName字段已经注入了“zhangsan”这个值。

## 使用Environment获取值

这里，我们在PropertyValueTest类中创建testPropertyValue03()方法，来使用Environment获取person.properties中的值，如下所示。

```java
@Test
public void testPropertyValue03(){
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(PropertyValueConfig.class);
    Environment environment = context.getEnvironment();
    String nickName = environment.getProperty("person.nickName");
    System.out.println(nickName);
}
```

运行PropertyValueTest类中的testPropertyValue03()方法，输出的结果信息如下所示。

```bash
zhangsan
```

可以看到，使用Environment确实能够获取到person.properties中的值。

## 重磅福利

关注「 **冰河技术** 」微信公众号，后台回复 “**设计模式**” 关键字领取《**深入浅出Java 23种设计模式**》PDF文档。回复“**Java8**”关键字领取《**Java8新特性教程**》PDF文档。回复“**限流**”关键字获取《**亿级流量下的分布式限流解决方案**》PDF文档，三本PDF均是由冰河原创并整理的超硬核教程，面试必备！！

<font color="#FF0000">**好了，今天就聊到这儿吧！别忘了点个赞，给个在看和转发，让更多的人看到，一起学习，一起进步！！**</font>

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！

![](https://img-blog.csdnimg.cn/20200716220443647.png#pic_center)

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)