---
title: 【付费】 第18章：深度解析@PostConstruct注解与@PreDestroy注解
pay: https://articles.zsxq.com/id_q1dtx07qi6tx.html
---

# 《Spring核心技术》第18章-生命周期型注解：深度解析@PostConstruct注解与@PreDestroy注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-18](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-18)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@PostConstruct注解与@PreDestroy注解标注的方法的执行时机和流程，从源码级别彻底掌握@PostConstruct注解与@PreDestroy注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * @PostConstruct源码时序图
  * @PreDestroy源码时序图
* 源码解析
  * @PostConstruct源码解析
  * @PreDestroy源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@PostConstruct与@PreDestroy注解，你真的彻底了解过吗？`

Spring中可以通过注解指定方法的执行时机，比如可以指定方法在创建Bean后在为属性赋值后，初始化Bean之前执行，也可以让方法在Bean销毁之前执行。那这些又是如何实现的呢？

## 二、注解说明

`关于@PostConstruct注解与@PreDestroy注解的一点点说明~~`

@PostConstruct注解与@PreDestroy注解都是JSR250规范中提供的注解。@PostConstruct注解标注的方法可以在创建Bean后在为属性赋值后，初始化Bean之前执行，@PreDestroy注解标注的方法可以在Bean销毁之前执行。在Spring6中，如果使用@PostConstruct注解与@PreDestroy注解，则需要在Maven的pom.xml文件中添加如下依赖。

```xml
<dependency>
    <groupId>jakarta.annotation</groupId>
    <artifactId>jakarta.annotation-api</artifactId>
    <version>2.1.1</version>
</dependency>
```

### 2.1 注解源码

**1.@PostConstruct注解**

@PostConstruct注解的源码详见：jakarta.annotation.PostConstruct。

```java
@Documented
@Retention (RUNTIME)
@Target(METHOD)
public @interface PostConstruct {
}
```

在实际开发项目的过程中，@PostConstruct注解通常被用来指定一些Bean对象的初始化操作。在@PostConstruct注解中并未提供任何属性。

**2.@PreDestroy注解**

@PreDestroy注解的源码详见：jakarta.annotation.PreDestroy。

```java
@Documented
@Retention (RUNTIME)
@Target(METHOD)
public @interface PreDestroy {
}
```

在实际开发项目的过程中，@PreDestroy注解通常被用来实现在Bean销毁之前执行的一些操作，比如释放资源、释放数据库连接等操作。在@PreDestroy注解中并未提供任何属性。

### 2.2 使用场景

使用Spring开发项目的过程中，如果在Bean对象创建完成后，需要对Bean对象中的成员进行一些初始化操作，就可以使用@PostConstruct注解注解实现。如果在Bean对象销毁之前，对系统中的一些资源进行清理，例如释放占用的资源，释放数据库连接等，就可以使用@PreDestroy注解实现。

## 三、使用案例

`一起实现@PostConstruct注解与@PreDestroy注解的案例，怎么样?`

本章，就一同实现@PostConstruct注解与@PreDestroy注解的案例，在@PostConstruct注解与@PreDestroy注解标注的方法中打印对应的日志，观察方法的执行时机。具体案例实现步骤如下所示。

**（1）新增PrePostBean类**

PrePostBean类的源码详见：spring-annotation-chapter-18工程下的io.binghe.spring.annotation.chapter18.bean.PrePostBean。

```java
public class PrePostBean {
    public PrePostBean(){
        System.out.println("执行PrePostBean的构造方法...");
    }
    public void init(){
        System.out.println("执行PrePostBean的init方法...");
    }
    @PostConstruct
    public void postConstruct(){
        System.out.println("执行PrePostBean的postConstruct方法...");
    }
    @PreDestroy
    public void preDestroy(){
        System.out.println("执行PrePostBean的preDestroy方法...");
    }
    public void destroy(){
        System.out.println("执行PrePostBean的destroy方法...");
    }
}
```

可以看到，在PrePostBean类中提供了多个方法，含义如下所示。

* PrePostBean()方法：构造方法。
* init()方法：初始化方法，会在@Bean注解中的initMethod属性中指定初始化方法。
* postConstruct()方法：被@PostConstruct注解标注的方法，会在为Bean的属性赋值之后，初始化Bean之前执行。
* preDestroy()：被@PreDestroy注解标注的方法，会在Bean销毁之前执行。
* destroy()方法：销毁方法，会在@Bean注解中的destroyMethod属性中指定销毁方法。

**（2）新增PrePostConfig类**

PrePostConfig类的源码详见：spring-annotation-chapter-18工程下的io.binghe.spring.annotation.chapter18.config.PrePostConfig。

```java
@Configuration
public class PrePostConfig {
    @Bean(initMethod = "init", destroyMethod = "destroy")
    public PrePostBean prePostBean(){
        return new PrePostBean();
    }
}
```

可以看到， 在PrePostConfig类上标注了@Configuration注解，说明PrePostConfig类是案例程序的配置类。并且在PrePostConfig类中的prePostBean()方法上标注了@Bean注解，并通过@Bean注解的initMethod属性指定的初始化方法为PrePostBean类的init()方法，通过@Bean注解的destroyMethod属性指定的销毁方法为PrePostBean类的destroy()方法。

**（3）新增PrePostTest类**

PrePostTest类的源码详见：spring-annotation-chapter-18工程下的io.binghe.spring.annotation.chapter18.PrePostTest。

```java
public class PrePostTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(PrePostConfig.class);
        context.close();
    }
}
```

可以看到，在PrePostTest类的main()方法中，调用AnnotationConfigApplicationContext类的构造方法创建IOC容器后，随后调用close()方法关闭IOC容器。

**（4）运行PrePostTest类**

运行PrePostTest类的main()方法，输出的结果信息如下所示。

```bash
执行PrePostBean的构造方法...
执行PrePostBean的postConstruct方法...
执行PrePostBean的init方法...
执行PrePostBean的preDestroy方法...
执行PrePostBean的destroy方法...
```

从输出的结果信息可以看出，方法的执行顺序为：构造方法—>被@PostConstruct注解标注的方法—>@Bean注解中initMethod属性指定的方法—>被@PreDestroy注解标注的方法—>@Bean注解中destroyMethod属性指定的方法。

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本章，会分别介绍@PostConstruct注解和@PreDestroy注解的源码时序图。

### 4.1 @PostConstruct源码时序图

本节，就简单介绍下@PostConstruct注解的源码时序图，@PostConstruct注解的源码时序图如图18-1~18-2所示。

![图18-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-13-001.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码