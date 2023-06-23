---
title: 【付费】 第17章：深度解析@Scope注解
pay: https://articles.zsxq.com/id_gbhw3a0m659q.html
---

# 《Spring核心技术》第17章-生命周期型注解：深度解析@Scope注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-17](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-17)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Scope指定Bean对象作用范围的案例和流程，从源码级别彻底掌握@Scope注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
  * 实现单例Bean
  * 实现原型Bean
* 源码时序图
  * 注册Bean的流程
  * 调用Bean工厂后置处理器
  * 获取Bean的流程
* 源码解析
  * 注册Bean的流程
  * 调用Bean工厂后置处理器
  * 获取Bean的流程
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Scope注解，你真的彻底了解过吗？`

在使用Spring开发项目时，有时需要指定Bean的作用范围，此时我们又该怎么做呢？

**注意：在本章中，忽略了Spring处理循环依赖的细节，后续会用单独的一章专门说明Spring的循环依赖问题。**

## 二、注解说明

`关于@Scope注解的一点点说明~~`

@Scope注解是Spring中提供的一个能够指定Bean的作用范围的注解，通过@Scope注解可以指定创建的Bean是单例的，还是原型的，也可以使用@Scope注解指定Bean在Web中的作用域，还可以自定义作用域。

### 2.1 注解源码

@Scope注解的源码详见：org.springframework.context.annotation.Scope。

```java
/**
 * @author Mark Fisher
 * @author Chris Beams
 * @author Sam Brannen
 * @since 2.5
 * @see org.springframework.stereotype.Component
 * @see org.springframework.context.annotation.Bean
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Scope {
	@AliasFor("scopeName")
	String value() default "";
	/**
	 * @since 4.2
	 */
	@AliasFor("value")
	String scopeName() default "";
	ScopedProxyMode proxyMode() default ScopedProxyMode.DEFAULT;
}
```

从@Scope注解的源码可以看出，@Scope注解是从Spring2.5版本开始提供的注解，并且在@Scope注解中提供了三个属性，具体含义分别如下所示。

* value：表示作用范围，可以取如下值。
  * singleton：表示单例Bean，IOC容器在启动时，就会创建Bean对象。如果标注了@Lazy注解，IOC容器在启动时，就不会创建Bean对象，会在第一次从IOC容器中获取Bean对象时，创建Bean对象。后续每次从IOC容器中获取的都是同一个Bean对象，同时，IOC容器会接管单例Bean对象的生命周期。
  * prototype：表示原型Bean。IOC容器在启动时，不会创建Bean对象，每次从IOC容器中获取Bean对象时，都会创建一个新的Bean对象。并且@Lazy注解对原型Bean不起作用，同时，IOC容器不会接管原型Bean对象的生命周期
  * request：表示作用域是当前请求范围。
  * session：表示作用域是当前会话范围。
  * application：表示作用域是当前应用范围。
* scopeName：Spring4.2版本开始新增的属性，作用与value属性相同。
* proxyMode：指定Bean对象使用的代理方式，可以取如下值。
  * DEFAULT：默认值，作用与NO相同。
  * NO：不使用代理。
  * INTERFACES：使用JDK基于接口的代理。
  * TARGET_CLASS：使用CGLIB基于目标类的子类创建代理对象。

### 2.2 使用场景

大部分场景下，使用Spring的单例Bean就足够了，Spring默认的类型也是单例Bean。单例Bean能够保证在Spring中不会重复创建相同的Bean对象，对性能有所提高。但是，如果单例Bean中存在非静态成员变量，可能会产生线程安全问题。如果设置为原型Bean，则每次从IOC容器中获取Bean对象时，都会重新生成一个新的Bean对象，每次生成新的Bean对象多少都会影响程序的性能。

早期开发中使用比较多的Struts2框架中的Action，由于其模型驱动和OGNL表达式的原因，就必须将Spring中的Bean配置成原型Bean。

## 三、使用案例

`@Scope注解指定Bean作用范围的案例，我们一起实现吧~~`

本章，就基于@Scope注解实现指定Bean的作用范围的案例，总体上会从单例Bean和原型Bean两个作用范围进行说明。

**注意：本章的案例和源码解析都是基于@Scope注解标注到方法上，结合@Bean注解进行分析的。**

### 3.1 实现单例Bean

本节，主要基于@Scope注解实现单例Bean，具体实现步骤如下所示。

**（1）新增ScopeBean类**

ScopeBean类的源码详见：spring-annotation-chapter-17工程下的io.binghe.spring.annotation.chapter17.bean.ScopeBean。

```java
public class ScopeBean {
    public ScopeBean(){
        System.out.println("执行ScopeBean类的构造方法...");
    }
}
```

可以看到，ScopeBean类就是一个普通的Java类，并且在构造方法中打印了日志。

**（2）新增ScopeConfig类**

ScopeConfig类的源码详见：spring-annotation-chapter-17工程下的io.binghe.spring.annotation.chapter17.config.ScopeConfig。

```java
@Configuration
public class ScopeConfig {
    @Bean
    @Scope(value = "singleton")
    public ScopeBean scopeBean(){
        return new ScopeBean();
    }
}
```

可以看到，在ScopeConfig类上标注了@Configuration注解，说明ScopeConfig类是案例程序的配置类。在ScopeConfig类中的scopeBean()方法上使用@Bean注解向IOC容器中注入ScopeBean类的Bean对象。同时，在scopeBean()方法上，使用 @Scope注解指定了Bean的作用范围为singleton，也就是单例Bean。此处，由于Spring默认就是单例Bean，所以，也可以将@Scope注解省略。

**（3）新增ScopeTest类**

ScopeTest类的源码详见：spring-annotation-chapter-17工程下的io.binghe.spring.annotation.chapter17.ScopeTest。

```java
public class ScopeTest {
    public static void main(String[] args) {
        System.out.println("创建IOC容器开始...");
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ScopeConfig.class);
        System.out.println("创建IOC容器结束...");
        System.out.println("从IOC容器中第一次获取Bean对象开始...");
        ScopeBean scopeBean = context.getBean(ScopeBean.class);
        System.out.println(scopeBean);
        System.out.println("从IOC容器中第一次获取Bean对象结束...");
        System.out.println("从IOC容器中第二次获取Bean对象开始...");
        scopeBean = context.getBean(ScopeBean.class);
        System.out.println(scopeBean);
        System.out.println("从IOC容器中第二次获取Bean对象结束...");
    }
}
```

可以看到，在ScopeTest类中，首先创建了IOC容器，随后连续两次从IOC容器中获取ScopeBean类的Bean对象，并打印对应的日志信息。

**（4）运行ScopeTest类**

运行ScopeTest类的main()方法，输出的结果信息如下所示。

```bash
创建IOC容器开始...
执行ScopeBean类的构造方法...
创建IOC容器结束...
从IOC容器中第一次获取Bean对象开始...
io.binghe.spring.annotation.chapter17.bean.ScopeBean@11fc564b
从IOC容器中第一次获取Bean对象结束...
从IOC容器中第二次获取Bean对象开始...
io.binghe.spring.annotation.chapter17.bean.ScopeBean@11fc564b
从IOC容器中第二次获取Bean对象结束...
```

从输出的结果信息可以看出，Spring在IOC容器启动时就会创建单例Bean，随后每次从IOC容器中获取的都是同一个Bean对象。

### 3.2 实现原型Bean

本节实现原型Bean的步骤比较简单，就是在3.1节的基础上进行改造。具体步骤如下所示。

**（1）修改ScopeConfig类**

将ScopeConfig类中的scopeBean()方法上的@Scope注解的value属性值修改为prototype，如下所示。

```java
@Bean
@Scope(value = "prototype")
public ScopeBean scopeBean(){
    return new ScopeBean();
}
```

此时，就会在Spring中创建ScopeBean类型的原型Bean。

**（2）运行ScopeTest类**

运行ScopeTest类的main()方法，输出的结果信息如下所示。

```bash
创建IOC容器开始...
创建IOC容器结束...
从IOC容器中第一次获取Bean对象开始...
执行ScopeBean类的构造方法...
io.binghe.spring.annotation.chapter17.bean.ScopeBean@fa36558
从IOC容器中第一次获取Bean对象结束...
从IOC容器中第二次获取Bean对象开始...
执行ScopeBean类的构造方法...
io.binghe.spring.annotation.chapter17.bean.ScopeBean@672872e1
从IOC容器中第二次获取Bean对象结束...
```

从输出的结果信息可以看出，Spring在IOC容器启动时，并不会创建单例Bean，而是从IOC容器中获取Bean对象时，才会创建Bean对象，并且每次从IOC容器中获取Bean对象时，都会创建新的Bean对象。

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本章，会从注册Bean的流程、调用Bean工厂后置处理器和获取Bean的流程三个方面分析@Scope注解的源码时序图。

### 4.1 注册Bean的流程

@Scope注解涉及到的注册Bean流程的源码时序图如图17-1所示。

![图17-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-12-001.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
