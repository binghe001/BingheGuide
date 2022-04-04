---
layout: post
category: binghe-spring-ioc
title: 【Spring注解开发】组件注册-使用@Configuration和@Bean给容器中注册组件
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在之前的Spring版本中，我们只能通过写XML配置文件来定义我们的Bean，XML配置不仅繁琐，而且很容易出错，稍有不慎就会导致编写的应用程序各种报错，排查半天，发现是XML文件配置不对！另外，每个项目编写大量的XML文件来配置Spring，也大大增加了项目维护的复杂度，往往很多个项目的Spring XML文件的配置大部分是相同的，只有很少量的配置不同，这也造成了配置文件上的冗余。
lock: need
---

# 【Spring注解开发】组件注册-使用@Configuration和@Bean给容器中注册组件

## 写在前面

> 在之前的Spring版本中，我们只能通过写XML配置文件来定义我们的Bean，XML配置不仅繁琐，而且很容易出错，稍有不慎就会导致编写的应用程序各种报错，排查半天，发现是XML文件配置不对！另外，每个项目编写大量的XML文件来配置Spring，也大大增加了项目维护的复杂度，往往很多个项目的Spring XML文件的配置大部分是相同的，只有很少量的配置不同，这也造成了配置文件上的冗余。
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## Spring IOC和DI

在Spring容器的底层，最重要的功能就是IOC和DI，也就是控制反转和依赖注入。

> IOC：控制反转,将类的对象的创建交给Spring类管理创建。
> DI：依赖注入,将类里面的属性在创建类的过程中给属性赋值。
> DI和IOC的关系：DI不能单独存在,DI需要在IOC的基础上来完成。

在Spring内部，所有的组件都会放到IOC容器中，组件之间的关系通过IOC容器来自动装配，也就是我们所说的依赖注入。接下来，我们就使用注解的方式来完成容器组件的注册、管理及依赖、注入等功能。

在介绍使用注解完成容器组件的注册、管理及依赖、注入等功能之前，我们先来看看使用XML文件是如何注入Bean的。

## 通过XML文件注入JavaBean

首先，我们在工程的io.mykit.spring.bean包下创建Person类，作为测试的JavaBean，代码如下所示。

```java
package io.mykit.spring.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
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
    private String name;
    private Integer age;
}
```

接下来，我们在工程的resources目录下创建Spring的配置文件beans.xml，通过beans.xml文件将Person类注入到Spring的IOC容器中，配置如下所示。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <bean id = "person" class="io.mykit.spring.bean.Person">
        <property name="name" value="binghe"></property>
        <property name="age" value="18"></property>
    </bean>
</beans>
```

到此，我们使用XML方式注入JavaBean就配置完成了。接下来，我们创建一个SpringBeanTest类来进行测试，这里，我使用的是Junit进行测试，测试方法如下所示。

```java
@Test
public void testXmlConfig(){
    ApplicationContext context = new ClassPathXmlApplicationContext("beans.xml");
    Person person = (Person) context.getBean("person");
    System.out.println(person);
}
```

运行testXmlConfig()方法，输出的结果信息如下。

```bash
Person(name=binghe, age=18)
```

从输出结果中，我们可以看出，Person类通过beans.xml文件的配置，已经注入到Spring的IOC容器中了。

## 通过注解注入JavaBean

通过XML文件，我们可以将JavaBean注入到Spring的IOC容器中。那使用注解又该如何实现呢？别急，其实使用注解比使用XML文件要简单的多，我们在项目的io.mykit.spring.plugins.register.config包下创建PersonConfig类，并在PersonConfig类上添加@Configuration注解来标注PersonConfig类是一个Spring的配置类，通过@Bean注解将Person类注入到Spring的IOC容器中。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 以注解的形式来配置Person
 */
@Configuration
public class PersonConfig {
     @Bean
    public Person person(){
        return new Person("binghe001", 18);
    }
}
```

没错，通过PersonConfig类我们就能够将Person类注入到Spring的IOC容器中，是不是很Nice！！主要我们在类上加上@Configuration注解，并在方法上加上@Bean注解，就能够将方法中创建的JavaBean注入到Spring的IOC容器中。

接下来，我们在SpringBeanTest类中创建一个testAnnotationConfig()方法来测试通过注解注入的Person类，如下所示。

```java
@Test
public void testAnnotationConfig(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig.class);
    Person person = context.getBean(Person.class);
    System.out.println(person);
}
```

运行testAnnotationConfig()方法，输出的结果信息如下所示。

```bash
Person(name=binghe001, age=18)
```

可以看出，通过注解将Person类注入到了Spring的IOC容器中。

到这里，我们已经明确，通过XML文件和注解两种方式都可以将JavaBean注入到Spring的IOC容器中。那么，使用注解将JavaBean注入到IOC容器中时，使用的bean的名称是什么呢？ 我们可以在testAnnotationConfig()方法中添加如下代码来获取Person类型下的注解名称。

```java
//按照类型找到对应的bean名称数组
String[] names = context.getBeanNamesForType(Person.class);
Arrays.stream(names).forEach(System.out::println);
```

完整的testAnnotationConfig()方法的代码如下所示。

```java
@Test
public void testAnnotationConfig(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig.class);
    Person person = context.getBean(Person.class);
    System.out.println(person);

    //按照类型找到对应的bean名称数组
    String[] names = context.getBeanNamesForType(Person.class);
    Arrays.stream(names).forEach(System.out::println);
}
```

运行testAnnotationConfig()方法输出的结果信息如下所示。

```bash
Person(name=binghe001, age=18)
person
```

那这里的person是啥？我们修改下PersonConfig类中的person()方法，将person()方法修改成person01()方法，如下所示。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 以注解的形式来配置Person
 */
@Configuration
public class PersonConfig {

    @Bean
    public Person person01(){
        return new Person("binghe001", 18);
    }
}
```

此时，我们再次运行testAnnotationConfig()方法，输出的结果信息如下所示。

```bash
Person(name=binghe001, age=18)
person01
```

看到这里，大家应该有种豁然开朗的感觉了，没错！！使用注解注入Javabean时，bean在IOC中的名称就是使用@Bean注解标注的方法名称。我们可不可以为bean单独指定名称呢？那必须可以啊！只要在@Bean注解中明确指定名称就可以了。比如下面的PersonConfig类的代码，我们将person01()方法上的@Bean注解修改成@Bean("person")注解，如下所示。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 以注解的形式来配置Person
 */
@Configuration
public class PersonConfig {

    @Bean("person")
    public Person person01(){
        return new Person("binghe001", 18);
    }
}
```

此时，我们再次运行testAnnotationConfig()方法，输出的结果信息如下所示。

```bash
Person(name=binghe001, age=18)
person
```

可以看到，此时，输出的JavaBean的名称为person。

**结论：我们在使用注解方式向Spring的IOC容器中注入JavaBean时，如果没有在@Bean注解中明确指定bean的名称，就使用当前方法的名称来作为bean的名称；如果在@Bean注解中明确指定了bean的名称，则使用@Bean注解中指定的名称来作为bean的名称。**

好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)