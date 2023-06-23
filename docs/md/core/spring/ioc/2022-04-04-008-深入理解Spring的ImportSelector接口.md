---
layout: post
category: binghe-spring-ioc
title: 第07章：深入理解Spring的ImportSelector接口
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在前面的文章中，我们知道了可以使用ImportSelector接口实现向Spring容器中导入bean，那ImportSelector接口是如何实现的呢，接下来，我们就一探究竟！
lock: need
---

# 《Spring注解驱动开发》第07章：深入理解Spring的ImportSelector接口

## 写在前面

> 在前面的文章中，我们知道了可以使用ImportSelector接口实现向Spring容器中导入bean，那ImportSelector接口是如何实现的呢，接下来，我们就一探究竟！
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

## ImportSelector接口探秘

在这里我举个Spring中的实例来看一下：

```java
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(TransactionManagementConfigurationSelector.class)
public @interface EnableTransactionManagement {
    boolean proxyTargetClass() default false;

    AdviceMode mode() default AdviceMode.PROXY;

    int order() default Ordered.LOWEST_PRECEDENCE;
}
```

此注解是开启声明式事务的注解，那么它的@Import所导入的类为TransactionManagementConfigurationSelector，那么我们看一下其类图：

![](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-002.png)

由此可知该类实现类ImportSelector接口。

前面说过，在SpringBoot的自动化配置和@EnableXXX(功能性注解)都有ImportSelector接口的存在，那我们就来自己定义一个@EnableXXX注解来更加深刻的理解ImportSelector接口。

## 自定义@EnableXXX注解

在这里我们先准备两个Spring的项目工程:spring-project与ssm-project，其中spring-project里我们先创建好如下结构目录：

![](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-003.png)

### 创建实体类

```java
package org.hzgj.spring.study.bean
public class StudentBean{
    private Integer id;
    private String name;
    //省略setter和gettter
}
```

### 创建ImportSelector接口的实现类

```java
package org.hzgj.spring.study.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;

public class SpringStudySelector implements ImportSelector, BeanFactoryAware {
    private BeanFactory beanFactory;

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        importingClassMetadata.getAnnotationTypes().forEach(System.out::println);
        System.out.println(beanFactory);
        return new String[]{AppConfig.class.getName()};
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }
}
```

在这里我们实现ImportSelector接口和BeanFactoryAware接口，重写selectImports方法，最后我们返回的是AppConfig的类名，同时打印出相关的注解元数据与BeanFactory

### 自定义@EnableSpringStudy注解

```java
package org.hzgj.spring.study.annotation;

import org.hzgj.spring.study.config.SpringStudySelector;
import org.springframework.context.annotation.Import;
import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Documented
@Target(ElementType.TYPE)
@Import(SpringStudySelector.class)
public @interface EnableSpringStudy {
}
```

在这里我们仿照@EnableTransactionManagement来实现自定义注解，注意使用@Import导入我们刚才写的SpringStudySelector。

### 创建配置类

```java
package org.hzgj.spring.study.config;

import org.hzgj.spring.study.bean.StudentBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
    @Bean
    public StudentBean studentBean() {
        StudentBean studentBean = new StudentBean();
        studentBean.setId(19);
        studentBean.setName("admin");
        return studentBean;
    }
}
```

当都完成以后我们打个jar包，准备引入至其他工程：

![](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-004.png)

## 使用自定义@EnableXXX注解

 完成ssm-project工程中的AppConfig配置类

1) 首先我们将刚才的spring.jar导入到ssm-project工程里

2) 在对应的配置类上添加上spring-project中定义的@EnableSpringStudy注解

```java
@Configuration //表明此类是配置类
@ComponentScan // 扫描自定义的组件(repository service component controller)
@PropertySource("classpath:application.properties") // 读取application.properties
@MapperScan("com.bdqn.lyrk.ssm.study.app.mapper") //扫描Mybatis的Mapper接口
@EnableTransactionManagement //开启事务管理
@EnableSpringStudy
public class AppConfig {

  //....省略配置代码      
}
```

3）编写Main方法

```java
public static void main(String[] args) throws IOException {
        AnnotationConfigApplicationContext applicationContext = new AnnotationConfigApplicationContext(AppConfig.class);
        StudentBean studentBean = applicationContext.getBean(StudentBean.class);
        System.out.println(studentBean.getName());
}
```

运行后输出结果：

```bash
org.springframework.context.annotation.Configuration
org.springframework.context.annotation.ComponentScan
org.springframework.context.annotation.PropertySource
org.mybatis.spring.annotation.MapperScan
org.springframework.transaction.annotation.EnableTransactionManagement
org.hzgj.spring.study.annotation.EnableSpringStudy
org.springframework.beans.factory.support.DefaultListableBeanFactory@4b9e13df: defining beans [org.springframework.context.annotation.internalConfigurationAnnotationProcessor,org.springframework.context.annotation.internalAutowiredAnnotationProcessor,org.springframework.context.annotation.internalRequiredAnnotationProcessor,org.springframework.context.annotation.internalCommonAnnotationProcessor,org.springframework.context.event.internalEventListenerProcessor,org.springframework.context.event.internalEventListenerFactory,appConfig,propertiesConfig,logAspect,studentService]; root of factory hierarchy
admin
```

从这里我们可以看到ImportSelector接口中的方法参数，可以获取ssm-project项目下AppConfig的所有注解，并且能够获取当前BeanFactory所有配置的Bean。

## ImportSelector源码分析

这个接口在哪里调用呢？我们可以来看一下ConfigurationClassParser这个类的processImports方法。

```java
private void processImports(ConfigurationClass configClass, SourceClass currentSourceClass,
                            Collection<SourceClass> importCandidates, boolean checkForCircularImports) {

    if (importCandidates.isEmpty()) {
        return;
    }

    if (checkForCircularImports && isChainedImportOnStack(configClass)) {
        this.problemReporter.error(new CircularImportProblem(configClass, this.importStack));
    }
    else {
        this.importStack.push(configClass);
        try {
            for (SourceClass candidate : importCandidates) {　　　　　　　　　　　　//对ImportSelector的处理
                if (candidate.isAssignable(ImportSelector.class)) {
                    // Candidate class is an ImportSelector -> delegate to it to determine imports
                    Class<?> candidateClass = candidate.loadClass();
                    ImportSelector selector = BeanUtils.instantiateClass(candidateClass, ImportSelector.class);
                    ParserStrategyUtils.invokeAwareMethods(
                        selector, this.environment, this.resourceLoader, this.registry);
                    if (this.deferredImportSelectors != null && selector instanceof DeferredImportSelector) {　　　　　　　　　　　　　　　　//如果为延迟导入处理则加入集合当中
                        this.deferredImportSelectors.add(
                            new DeferredImportSelectorHolder(configClass, (DeferredImportSelector) selector));
                    }
                    else {　　　　　　　　　　　　　　　　//根据ImportSelector方法的返回值来进行递归操作
                        String[] importClassNames = selector.selectImports(currentSourceClass.getMetadata());
                        Collection<SourceClass> importSourceClasses = asSourceClasses(importClassNames);
                        processImports(configClass, currentSourceClass, importSourceClasses, false);
                    }
                }
                else if (candidate.isAssignable(ImportBeanDefinitionRegistrar.class)) {
                    // Candidate class is an ImportBeanDefinitionRegistrar ->
                    // delegate to it to register additional bean definitions
                    Class<?> candidateClass = candidate.loadClass();
                    ImportBeanDefinitionRegistrar registrar =
                        BeanUtils.instantiateClass(candidateClass, ImportBeanDefinitionRegistrar.class);
                    ParserStrategyUtils.invokeAwareMethods(
                        registrar, this.environment, this.resourceLoader, this.registry);
                    configClass.addImportBeanDefinitionRegistrar(registrar, currentSourceClass.getMetadata());
                }
                else {　　　　　　　　　　　　　　// 如果当前的类既不是ImportSelector也不是ImportBeanDefinitionRegistar就进行@Configuration的解析处理
                    // Candidate class not an ImportSelector or ImportBeanDefinitionRegistrar ->
                    // process it as an @Configuration class
                    this.importStack.registerImport(
                        currentSourceClass.getMetadata(), candidate.getMetadata().getClassName());
                    processConfigurationClass(candidate.asConfigClass(configClass));
                }
            }
        }
        catch (BeanDefinitionStoreException ex) {
            throw ex;
        }
        catch (Throwable ex) {
            throw new BeanDefinitionStoreException(
                "Failed to process import candidates for configuration class [" +
                configClass.getMetadata().getClassName() + "]", ex);
        }
        finally {
            this.importStack.pop();
        }
    }
}
```

在这里我们可以看到ImportSelector接口的返回值会递归进行解析，把解析到的类全名按照@Configuration进行处理。

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 冰河技术 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

部分内容来自：https://www.cnblogs.com/niechen/p/9262452.html

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)