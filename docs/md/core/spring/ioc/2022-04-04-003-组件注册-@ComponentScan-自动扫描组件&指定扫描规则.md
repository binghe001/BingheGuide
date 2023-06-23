---
layout: post
category: binghe-spring-ioc
title: 第02章：使用@ComponentScan自动扫描组件并指定扫描规则
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在实际项目中，我们更多的是使用Spring的包扫描功能对项目中的包进行扫描，凡是在指定的包或子包中的类上标注了@Repository、@Service、@Controller、@Component注解的类都会被扫描到，并将这个类注入到Spring容器中。Spring包扫描功能可以使用XML文件进行配置，也可以直接使用@ComponentScan注解进行设置，使用@ComponentScan注解进行设置比使用XML文件配置要简单的多。
lock: need
---

# 《Spring注解驱动开发》第02章：使用@ComponentScan自动扫描组件并指定扫描规则

## 写在前面

> 在实际项目中，我们更多的是使用Spring的包扫描功能对项目中的包进行扫描，凡是在指定的包或子包中的类上标注了@Repository、@Service、@Controller、@Component注解的类都会被扫描到，并将这个类注入到Spring容器中。Spring包扫描功能可以使用XML文件进行配置，也可以直接使用@ComponentScan注解进行设置，使用@ComponentScan注解进行设置比使用XML文件配置要简单的多。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## 使用XML文件配置包扫描

我们可以在Spring的XML配置文件中配置包的扫描，在配置包扫描时，需要在Spring的XML文件中的beans节点中引入context标签，如下所示。

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/context
                           http://www.springframework.org/context/spring-context.xsd ">
```

接下来，我们就可以在XML文件中定义要扫描的包了，如下所示。

```xml
<context:component-scan base-package="io.mykit.spring"/>
```

整个beans.xml文件如下所示。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd
       http://www.springframework.org/schema/context
       http://www.springframework.org/schema/context.xsd">

    <context:component-scan base-package="io.mykit.spring"/>

    <bean id = "person" class="io.mykit.spring.bean.Person">
        <property name="name" value="binghe"></property>
        <property name="age" value="18"></property>
    </bean>
</beans>
```

此时，只要在io.mykit.spring包下，或者io.mykit.spring的子包下标注了@Repository、@Service、@Controller、@Component注解的类都会被扫描到，并自动注入到Spring容器中。

此时，我们分别创建PersonDao、PersonService、和PersonController类，并在这三个类中分别添加@Repository、@Service、@Controller注解，如下所示。

* PersonDao

```java
package io.mykit.spring.plugins.register.dao;

import org.springframework.stereotype.Repository;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的dao
 */
@Repository
public class PersonDao {
}
```



* PersonService

```java
package io.mykit.spring.plugins.register.service;

import org.springframework.stereotype.Service;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的Service
 */
@Service
public class PersonService {
}
```



* PersonController

```java
package io.mykit.spring.plugins.register.controller;

import org.springframework.stereotype.Controller;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试的controller
 */
@Controller
public class PersonController {
}
```

接下来，我们在SpringBeanTest类中新建一个测试方法testComponentScanByXml()进行测试，如下所示。

```java
@Test
public void testComponentScanByXml(){
    ApplicationContext context = new ClassPathXmlApplicationContext("beans.xml");
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);
}
```

运行测试用例，输出的结果信息如下所示。

```bash
personConfig
personController
personDao
personService
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
person
```

可以看到，除了输出我们自己创建的bean名称之外，也输出了Spring内部使用的一些重要的bean名称。

接下来，我们使用注解来完成这些功能。

## 使用注解配置包扫描

使用@ComponentScan注解之前我们先将beans.xml文件中的下述配置注释。

```xml
<context:component-scan base-package="io.mykit.spring"></context:component-scan>
```

注释后如下所示。

```xml
<!--<context:component-scan base-package="io.mykit.spring"></context:component-scan>-->
```

使用@ComponentScan注解配置包扫描就非常Easy了！在我们的PersonConfig类上添加@ComponentScan注解，并将扫描的包指定为io.mykit.spring即可，整个的PersonConfig类如下所示。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.bean.Person;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author binghe
 * @version 1.0.0
 * @description 以注解的形式来配置Person
 */
@Configuration
@ComponentScan(value = "io.mykit.spring")
public class PersonConfig {

    @Bean("person")
    public Person person01(){
        return new Person("binghe001", 18);
    }
}
```

没错，就是这么简单，只需要在类上添加@ComponentScan(value = "io.mykit.spring")注解即可。

接下来，我们在SpringBeanTest类中新增testComponentScanByAnnotation()方法，如下所示。

```java
@Test
public void testComponentScanByAnnotation(){
    ApplicationContext context = new AnnotationConfigApplicationContext(PersonConfig.class);
    String[] names = context.getBeanDefinitionNames();
    Arrays.stream(names).forEach(System.out::println);
}
```

运行testComponentScanByAnnotation()方法输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
personController
personDao
personService
person
```

可以看到使用@ComponentScan注解同样输出了bean的名称。

既然使用XML文件和注解的方式都能够将相应的类注入到Spring容器当中，那我们是使用XML文件还是使用注解呢？我更倾向于使用注解，如果你确实喜欢使用XML文件进行配置，也可以，哈哈，个人喜好嘛！好了，我们继续。

## 关于@ComponentScan注解

我们点开ComponentScan注解类，如下所示。

```java
package org.springframework.context.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.beans.factory.support.BeanNameGenerator;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.type.filter.TypeFilter;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Repeatable(ComponentScans.class)
public @interface ComponentScan {

	@AliasFor("basePackages")
	String[] value() default {};

	@AliasFor("value")
	String[] basePackages() default {};

	Class<?>[] basePackageClasses() default {};

	Class<? extends BeanNameGenerator> nameGenerator() default BeanNameGenerator.class;

	Class<? extends ScopeMetadataResolver> scopeResolver() default AnnotationScopeMetadataResolver.class;

	ScopedProxyMode scopedProxy() default ScopedProxyMode.DEFAULT;

	String resourcePattern() default ClassPathScanningCandidateComponentProvider.DEFAULT_RESOURCE_PATTERN;

	boolean useDefaultFilters() default true;

	Filter[] includeFilters() default {};

	Filter[] excludeFilters() default {};

	boolean lazyInit() default false;

	@Retention(RetentionPolicy.RUNTIME)
	@Target({})
	@interface Filter {
		FilterType type() default FilterType.ANNOTATION;
        
		@AliasFor("classes")
		Class<?>[] value() default {};
        
		@AliasFor("value")
		Class<?>[] classes() default {};
        
		String[] pattern() default {};
	}
}
```

这里，我们着重来看ComponentScan类的两个方法，如下所示。

```java
Filter[] includeFilters() default {};
Filter[] excludeFilters() default {};
```

includeFilters()方法表示Spring扫描的时候，只包含哪些注解，而excludeFilters()方法表示不包含哪些注解。两个方法的返回值都是Filter[]数组，在ComponentScan注解类的内部存在Filter注解类，大家可以看下上面的代码。

### 1.扫描时排除注解标注的类

例如，我们现在排除@Controller、@Service和@Repository注解，我们可以在PersonConfig类上通过@ComponentScan注解的excludeFilters()实现。例如，我们在PersonConfig类上添加了如下的注解。

```java
@ComponentScan(value = "io.mykit.spring", excludeFilters = {
        @Filter(type = FilterType.ANNOTATION, classes = {Controller.class, Service.class, Repository.class})
})
```

这样，我们就使得Spring在扫描包的时候排除了使用@Controller、@Service和@Repository注解标注的类。运行SpringBeanTest类中的testComponentScanByAnnotation()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
person
```

可以看到，输出的结果信息中不再输出personController、personService和personDao说明Spring在进行包扫描时，忽略了@Controller、@Service和@Repository注解标注的类。

### 2.扫描时只包含注解标注的类

我们也可以使用ComponentScan注解类的includeFilters()来指定Spring在进行包扫描时，只包含哪些注解标注的类。

**这里需要注意的是，当我们使用includeFilters()来指定只包含哪些注解标注的类时，需要禁用默认的过滤规则。**

例如，我们需要Spring在扫描时，只包含@Controller注解标注的类，可以在PersonConfig类上添加@ComponentScan注解，设置只包含@Controller注解标注的类，并禁用默认的过滤规则，如下所示。

```java
@ComponentScan(value = "io.mykit.spring", includeFilters = {
        @Filter(type = FilterType.ANNOTATION, classes = {Controller.class})
}, useDefaultFilters = false)
```

此时，我们再次运行SpringBeanTest类的testComponentScanByAnnotation()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
personController
person
```

可以看到，在输出的结果中，只包含了@Controller注解标注的组件名称，并没有输出@Service和@Repository注解标注的组件名称。

注意：在使用includeFilters()来指定只包含哪些注解标注的类时，结果信息中会一同输出Spring内部的组件名称。

### 3.重复注解

不知道小伙伴们有没有注意到ComponentScan注解类上有一个如下所示的注解。

```java
@Repeatable(ComponentScans.class)
```

我们先来看看@ComponentScans注解是个啥，如下所示。

```java
package org.springframework.context.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
public @interface ComponentScans {
	ComponentScan[] value();
}
```

可以看到，在ComponentScans注解类中只声明了一个返回ComponentScan[]数组的value()，说到这里，大家是不是就明白了，没错，这在Java8中是一个重复注解。

> 对于Java8不熟悉的小伙伴，可以到【[Java8新特性](https://mp.weixin.qq.com/mp/appmsgalbum?action=getalbum&__biz=Mzg3MzE1NTIzNA==&scene=1&album_id=1325066823947321344#wechat_redirect)】专栏查看关于Java8新特性的文章。专栏地址小伙伴们可以猛戳下面的链接地址进行查看：
>
> [https://mp.weixin.qq.com/mp/appmsgalbum?action=getalbum&__biz=Mzg3MzE1NTIzNA==&scene=1&album_id=1325066823947321344#wechat_redirect](https://mp.weixin.qq.com/mp/appmsgalbum?action=getalbum&__biz=Mzg3MzE1NTIzNA==&scene=1&album_id=1325066823947321344#wechat_redirect)

在Java8中表示@ComponentScan注解是一个重复注解，可以在一个类上重复使用这个注解，如下所示。

```java
@Configuration
@ComponentScan(value = "io.mykit.spring", includeFilters = {
        @Filter(type = FilterType.ANNOTATION, classes = {Controller.class})
}, useDefaultFilters = false)
@ComponentScan(value = "io.mykit.spring", includeFilters = {
        @Filter(type = FilterType.ANNOTATION, classes = {Service.class})
}, useDefaultFilters = false)
public class PersonConfig {

    @Bean("person")
    public Person person01(){
        return new Person("binghe001", 18);
    }
}
```

运行SpringBeanTest类的testComponentScanByAnnotation()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
personController
personService
person
```

可以看到，同时输出了@Controller注解和@Service注解标注的组件名称。

如果使用的是Java8之前的版本，我们就不能直接在类上写多个@ComponentScan注解了。此时，我们可以在PersonConfig类上使用@ComponentScans注解，如下所示。

```java
@ComponentScans(value = {
        @ComponentScan(value = "io.mykit.spring", includeFilters = {
                @Filter(type = FilterType.ANNOTATION, classes = {Controller.class})
        }, useDefaultFilters = false),
        @ComponentScan(value = "io.mykit.spring", includeFilters = {
                @Filter(type = FilterType.ANNOTATION, classes = {Service.class})
        }, useDefaultFilters = false)
})
```

再次运行SpringBeanTest类的testComponentScanByAnnotation()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.annotation.internalCommonAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
personConfig
personController
personService
person
```

与使用多个@ComponentScan注解输出的结果信息相同。

**总结：我们可以使用@ComponentScan注解来指定Spring扫描哪些包，可以使用excludeFilters()指定扫描时排除哪些组件，也可以使用includeFilters()指定扫描时只包含哪些组件。当使用includeFilters()指定只包含哪些组件时，需要禁用默认的过滤规则**

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)