---
layout: post
category: binghe-spring-ioc
title: 【Spring注解驱动开发】使用InitializingBean和DisposableBean来管理bean的生命周期，你真的了解吗？
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在《[【Spring注解驱动开发】如何使用@Bean注解指定初始化和销毁的方法？看这一篇就够了！！](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484985&idx=1&sn=bf7ec702113f433f6677d0e9f4f5ae7d&chksm=cee519f4f99290e2c509926a61a7f9604d8a358cd364a78d6de7929f45b3b2a84f57b93f8f87&token=604767871&lang=zh_CN#rd)》一文中，我们讲述了如何使用@Bean注解来指定bean初始化和销毁的方法。具体的用法就是在@Bean注解中使用init-method属性和destroy-method属性来指定初始化方法和销毁方法。除此之外，Spring中是否还提供了其他的方式来对bean实例进行初始化和销毁呢？
lock: need
---

# 【Spring注解驱动开发】使用InitializingBean和DisposableBean来管理bean的生命周期，你真的了解吗？

## 写在前面

> 在《[【Spring注解驱动开发】如何使用@Bean注解指定初始化和销毁的方法？看这一篇就够了！！](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247484985&idx=1&sn=bf7ec702113f433f6677d0e9f4f5ae7d&chksm=cee519f4f99290e2c509926a61a7f9604d8a358cd364a78d6de7929f45b3b2a84f57b93f8f87&token=604767871&lang=zh_CN#rd)》一文中，我们讲述了如何使用@Bean注解来指定bean初始化和销毁的方法。具体的用法就是在@Bean注解中使用init-method属性和destroy-method属性来指定初始化方法和销毁方法。除此之外，Spring中是否还提供了其他的方式来对bean实例进行初始化和销毁呢？
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## InitializingBean接口

### 1.InitializingBean接口概述

Spring中提供了一个InitializingBean接口，InitializingBean接口为bean提供了属性初始化后的处理方法，它只包括afterPropertiesSet方法，凡是继承该接口的类，在bean的属性初始化后都会执行该方法。InitializingBean接口的源码如下所示。

```java
package org.springframework.beans.factory;
public interface InitializingBean {
	void afterPropertiesSet() throws Exception;
}
```

根据InitializingBean接口中提供的afterPropertiesSet()方法的名字可以推断出：afterPropertiesSet()方法是在属性赋好值之后调用的。那到底是不是这样呢？我们来分析下afterPropertiesSet()方法的调用时机。

### 2.何时调用InitializingBean接口？

我们定位到Spring中的org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory类下的invokeInitMethods()方法中，来查看Spring加载bean的方法。

**题外话：不要问我为什么会是这个invokeInitMethods()方法，如果你和我一样对Spring的源码非常熟悉的话，你也会知道是这个invokeInitMethods()方法，哈哈哈哈！所以，小伙伴们不要只顾着使用Spring，还是要多看看Spring的源码啊！Spring框架中使用了大量优秀的设计模型，其代码的编写规范和严谨程度也是业界开源框架中数一数二的，非常值得阅读。**

我们来到AbstractAutowireCapableBeanFactory类下的invokeInitMethods()方法，如下所示。

```java
protected void invokeInitMethods(String beanName, final Object bean, @Nullable RootBeanDefinition mbd)
    throws Throwable {
	//判断该bean是否实现了实现了InitializingBean接口，如果实现了InitializingBean接口，则调用bean的afterPropertiesSet方法
    boolean isInitializingBean = (bean instanceof InitializingBean);
    if (isInitializingBean && (mbd == null || !mbd.isExternallyManagedInitMethod("afterPropertiesSet"))) {
        if (logger.isTraceEnabled()) {
            logger.trace("Invoking afterPropertiesSet() on bean with name '" + beanName + "'");
        }
        if (System.getSecurityManager() != null) {
            try {
                AccessController.doPrivileged((PrivilegedExceptionAction<Object>) () -> {
                    //调用afterPropertiesSet()方法
                    ((InitializingBean) bean).afterPropertiesSet();
                    return null;
                }, getAccessControlContext());
            }
            catch (PrivilegedActionException pae) {
                throw pae.getException();
            }
        }
        else {
            //调用afterPropertiesSet()方法
            ((InitializingBean) bean).afterPropertiesSet();
        }
    }

    if (mbd != null && bean.getClass() != NullBean.class) {
        String initMethodName = mbd.getInitMethodName();
        if (StringUtils.hasLength(initMethodName) &&
            !(isInitializingBean && "afterPropertiesSet".equals(initMethodName)) &&
            !mbd.isExternallyManagedInitMethod(initMethodName)) {
            //通过反射的方式调用init-method
            invokeCustomInitMethod(beanName, bean, mbd);
        }
    }
}
```

分析上述代码后，我们可以初步得出如下信息：

* Spring为bean提供了两种初始化bean的方式，实现InitializingBean接口，实现afterPropertiesSet方法，或者在配置文件和@Bean注解中通过init-method指定，两种方式可以同时使用。
* 实现InitializingBean接口是直接调用afterPropertiesSet()方法，比通过反射调用init-method指定的方法效率相对来说要高点。但是init-method方式消除了对Spring的依赖。
* 如果调用afterPropertiesSet方法时出错，则不调用init-method指定的方法。

也就是说Spring为bean提供了两种初始化的方式，第一种实现InitializingBean接口，实现afterPropertiesSet方法，第二种配置文件或@Bean注解中通过init-method指定，两种方式可以同时使用，同时使用先调用afterPropertiesSet方法，后执行init-method指定的方法。

## DisposableBean接口

### 1.DisposableBean接口概述

实现org.springframework.beans.factory.DisposableBean接口的bean在销毁前，Spring将会调用DisposableBean接口的destroy()方法。我们先来看下DisposableBean接口的源码，如下所示。

```java
package org.springframework.beans.factory;
public interface DisposableBean {
	void destroy() throws Exception;
}
```

可以看到，在DisposableBean接口中只定义了一个destroy()方法。

在Bean生命周期结束前调用destory()方法做一些收尾工作，亦可以使用destory-method。前者与Spring耦合高，使用**类型强转.方法名()，**效率高。后者耦合低，使用反射，效率相对低

### 2.DisposableBean接口注意事项

多例bean的生命周期不归Spring容器来管理，这里的DisposableBean中的方法是由Spring容器来调用的，所以如果一个多例实现了DisposableBean是没有啥意义的，因为相应的方法根本不会被调用，当然在XML配置文件中指定了destroy方法，也是没有意义的。所以，在多实例bean情况下，Spring不会自动调用bean的销毁方法。

## 单实例bean案例

创建一个Animal的类实现InitializingBean和DisposableBean接口，代码如下：

```java
package io.mykit.spring.plugins.register.bean;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试InitializingBean接口和DisposableBean接口
 */
public class Animal implements InitializingBean, DisposableBean {
    public Animal(){
        System.out.println("执行了Animal类的无参数构造方法");
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        System.out.println("执行了Animal类的初始化方法。。。。。");

    }
    @Override
    public void destroy() throws Exception {
        System.out.println("执行了Animal类的销毁方法。。。。。");

    }
}
```

接下来，我们新建一个AnimalConfig类，并将Animal通过@Bean注解的方式注册到Spring容器中，如下所示。

```java
package io.mykit.spring.plugins.register.config;

import io.mykit.spring.plugins.register.bean.Animal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
/**
 * @author binghe
 * @version 1.0.0
 * @description AnimalConfig
 */
@Configuration
@ComponentScan("io.mykit.spring.plugins.register.bean")
public class AnimalConfig {
    @Bean
    public Animal animal(){
        return new Animal();
    }
}
```

接下来，我们在BeanLifeCircleTest类中新增testBeanLifeCircle02()方法来进行测试，如下所示。

```java
@Test
public void testBeanLifeCircle02(){
    //创建IOC容器
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AnimalConfig.class);
    System.out.println("IOC容器创建完成...");
    //关闭IOC容器
    context.close();
}
```

运行BeanLifeCircleTest类中的testBeanLifeCircle02()方法，输出的结果信息如下所示。

```bash
执行了Animal类的无参数构造方法
执行了Animal类的初始化方法。。。。。
IOC容器创建完成...
执行了Animal类的销毁方法。。。。。
```

从输出的结果信息可以看出：单实例bean下，IOC容器创建完成后，会自动调用bean的初始化方法；而在容器销毁前，会自动调用bean的销毁方法。

## 多实例bean案例

多实例bean的案例代码基本与单实例bean的案例代码相同，只不过在AnimalConfig类中，我们在animal()方法上添加了@Scope("prototype")注解，如下所示。

```java
package io.mykit.spring.plugins.register.config;
import io.mykit.spring.plugins.register.bean.Animal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
/**
 * @author binghe
 * @version 1.0.0
 * @description AnimalConfig
 */
@Configuration
@ComponentScan("io.mykit.spring.plugins.register.bean")
public class AnimalConfig {
    @Bean
    @Scope("prototype")
    public Animal animal(){
        return new Animal();
    }
}
```

接下来，我们在BeanLifeCircleTest类中新增testBeanLifeCircle03()方法来进行测试，如下所示。

```java
@Test
public void testBeanLifeCircle03(){
    //创建IOC容器
    AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext(AnimalConfig.class);
    System.out.println("IOC容器创建完成...");
    System.out.println("-------");
    //调用时创建对象
    Object bean = ctx.getBean("animal");
    System.out.println("-------");
    //调用时创建对象
    Object bean1 = ctx.getBean("animal");
    System.out.println("-------");
    //关闭IOC容器
    ctx.close();
}
```

运行BeanLifeCircleTest类中的testBeanLifeCircle03()方法，输出的结果信息如下所示。

```bash
IOC容器创建完成...
-------
执行了Animal类的无参数构造方法
执行了Animal类的初始化方法。。。。。
-------
执行了Animal类的无参数构造方法
执行了Animal类的初始化方法。。。。。
-------
```

从输出的结果信息中可以看出：在多实例bean情况下，Spring不会自动调用bean的销毁方法。

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 冰河技术 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)