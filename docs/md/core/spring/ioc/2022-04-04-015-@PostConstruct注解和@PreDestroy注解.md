---
layout: post
category: binghe-spring-ioc
title: 第14章：@PostConstruct注解和@PreDestroy注解吗
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在之前的文章中，我们介绍了如何使用@Bean注解指定初始化和销毁的方法，小伙伴们可以参见《[【Spring注解驱动开发】如何使用@Bean注解指定初始化和销毁的方法？看这一篇就够了！！](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484985&idx=1&sn=bf7ec702113f433f6677d0e9f4f5ae7d&chksm=cee519f4f99290e2c509926a61a7f9604d8a358cd364a78d6de7929f45b3b2a84f57b93f8f87&token=1099992343&lang=zh_CN#rd)》，也介绍了使用InitializingBean和DisposableBean来处理bean的初始化和销毁，小伙伴们可以参见《[【Spring注解驱动开发】Spring中的InitializingBean和DisposableBean，你真的了解吗？](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247485001&idx=1&sn=251bd90d3b04f2bd56c9d24f9df39f81&chksm=cee51984f992909216b2ab3e723561776b5032393d30e6cdf99af1c4c08e8facb790ea16955e&token=1099992343&lang=zh_CN#rd)》。除此之外，在JDK中也提供了两个注解能够在bean加载到Spring容器之后执行和在bean销毁之前执行，今天，我们就一起来看看这两个注解的用法。
lock: need
---

# 《Spring注解驱动开发》第14章：@PostConstruct注解和@PreDestroy注解吗

## 写在前面

> 在之前的文章中，我们介绍了如何使用@Bean注解指定初始化和销毁的方法，小伙伴们可以参见《[【Spring注解驱动开发】如何使用@Bean注解指定初始化和销毁的方法？看这一篇就够了！！](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484985&idx=1&sn=bf7ec702113f433f6677d0e9f4f5ae7d&chksm=cee519f4f99290e2c509926a61a7f9604d8a358cd364a78d6de7929f45b3b2a84f57b93f8f87&token=1099992343&lang=zh_CN#rd)》，也介绍了使用InitializingBean和DisposableBean来处理bean的初始化和销毁，小伙伴们可以参见《[【Spring注解驱动开发】Spring中的InitializingBean和DisposableBean，你真的了解吗？](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247485001&idx=1&sn=251bd90d3b04f2bd56c9d24f9df39f81&chksm=cee51984f992909216b2ab3e723561776b5032393d30e6cdf99af1c4c08e8facb790ea16955e&token=1099992343&lang=zh_CN#rd)》。除此之外，在JDK中也提供了两个注解能够在bean加载到Spring容器之后执行和在bean销毁之前执行，今天，我们就一起来看看这两个注解的用法。
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## @PostConstruct注解

@PostConstruct注解好多人以为是Spring提供的。其实是Java自己的注解。我们来看下@PostConstruct注解的源码，如下所示。

```java
package javax.annotation;
import java.lang.annotation.*;
import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;
@Documented
@Retention (RUNTIME)
@Target(METHOD)
public @interface PostConstruct {
}
```

从源码可以看出，**@PostConstruct注解是Java中的注解，并不是Spring提供的注解。**

@PostConstruct注解被用来修饰一个非静态的void()方法。被@PostConstruct修饰的方法会在服务器加载Servlet的时候运行，并且只会被服务器执行一次。PostConstruct在构造函数之后执行，init()方法之前执行。

通常我们会是在Spring框架中使用到@PostConstruct注解，该注解的方法在整个Bean初始化中的执行顺序：

**Constructor(构造方法) -> @Autowired(依赖注入) -> @PostConstruct(注释的方法)。**

## @PreDestroy注解

@PreDestroy注解同样是Java提供的，看下源码，如下所示。

```java
package javax.annotation;
import java.lang.annotation.*;
import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;
@Documented
@Retention (RUNTIME)
@Target(METHOD)
public @interface PreDestroy {
}
```

被@PreDestroy修饰的方法会在服务器卸载Servlet的时候运行，并且只会被服务器调用一次，类似于Servlet的destroy()方法。被@PreDestroy修饰的方法会在destroy()方法之后运行，在Servlet被彻底卸载之前。执行顺序如下所示。

**调用destroy()方法->@PreDestroy->destroy()方法->bean销毁。**

**总结：@PostConstruct，@PreDestroy是Java规范JSR-250引入的注解，定义了对象的创建和销毁工作，同一期规范中还有注解@Resource，Spring也支持了这些注解。**

## 案例程序

对@PostConstruct注解和@PreDestroy注解有了简单的了解之后，接下来，我们就写一个简单的程序来加深对这两个注解的理解。

我们创建一个Cat类，如下所示。

```java
package io.mykit.spring.plugins.register.bean;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试@PostConstruct注解和@PreDestroy注解
 */
public class Cat {

    public Cat(){
        System.out.println("Cat类的构造方法...");
    }

    public void init(){
        System.out.println("Cat的init()方法...");
    }

    @PostConstruct
    public void postConstruct(){
        System.out.println("Cat的postConstruct()方法...");
    }

    @PreDestroy
    public void preDestroy(){
        System.out.println("Cat的preDestroy()方法...");
    }

    public void destroy(){
        System.out.println("Cat的destroy()方法...");
    }
}
```

可以看到，在Cat类中，我们提供了构造方法，init()方法、destroy()方法，使用 @PostConstruct注解标注的postConstruct()方法和只用@PreDestroy注解标注的preDestroy()方法。接下来，我们在AnimalConfig类中使用@Bean注解将Cat类注册到Spring容器中，如下所示。

```java
@Bean(initMethod = "init", destroyMethod = "destroy")
public Cat cat(){
    return new Cat();
}
```

接下来，在BeanLifeCircleTest类中新建testBeanLifeCircle04()方法进行测试，如下所示。

```java
@Test
public void testBeanLifeCircle04(){
    //创建IOC容器
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AnimalConfig.class);
    //关闭IOC容器
    context.close();
}
```

运行BeanLifeCircleTest类中的testBeanLifeCircle04()方法，输出的结果信息如下所示。

```java
Cat类的构造方法...
Cat的postConstruct()方法...
Cat的init()方法...
Cat的preDestroy()方法...
Cat的destroy()方法...
```

从输出的结果信息中，可以看出执行的顺序是： **构造方法 -> @PostConstruct -> init()方法 -> @PreDestroy -> destroy()方法。**

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 冰河技术 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)