---
layout: post
category: binghe-spring-ioc
title: 第25章：详解@Resource和@Inject注解
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 我在 **冰河技术** 微信公众号中发表的《[【Spring注解驱动开发】使用@Autowired@Qualifier@Primary三大注解自动装配组件，你会了吗？](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247486002&idx=1&sn=9e42ec6586363d6ab1e61beb14ee3322&chksm=cee515fff9929ce951a597f0cdb0bb04a615aef1287cac954645cdfd551518c0169350cd846e&token=1511192793&lang=zh_CN#rd)》一文中，介绍了如何使用@Autowired、@Qualifier和@Primary注解自动装配Spring组件。那除了这三个注解以外，还有没有其他的注解可以自动装配组件呢？那必须有啊！今天，我们就一起说说@Resource注解和@Inject注解。
lock: need
---

# 《Spring注解驱动开发》第25章：详解@Resource和@Inject注解

## 写在前面

> 我在 **冰河技术** 微信公众号中发表的《[【Spring注解驱动开发】使用@Autowired@Qualifier@Primary三大注解自动装配组件，你会了吗？](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247486002&idx=1&sn=9e42ec6586363d6ab1e61beb14ee3322&chksm=cee515fff9929ce951a597f0cdb0bb04a615aef1287cac954645cdfd551518c0169350cd846e&token=1511192793&lang=zh_CN#rd)》一文中，介绍了如何使用@Autowired、@Qualifier和@Primary注解自动装配Spring组件。那除了这三个注解以外，还有没有其他的注解可以自动装配组件呢？那必须有啊！今天，我们就一起说说@Resource注解和@Inject注解。
>
> 关注 **冰河技术** 微信公众号，回复 “Spring注解”关键字领取源码工程。

## @Resource注解

@Resource（这个注解属于J2EE的，JSR250），默认安照名称进行装配，名称可以通过name属性进行指定， 如果没有指定name属性，当注解写在字段上时，默认取字段名进行按照名称查找，如果注解写在setter方法上默认取属性名进行装配。 当找不到与名称匹配的bean时才按照类型进行装配。但是需要注意的是，如果name属性一旦指定，就只会按照名称进行装配。

@Resource注解的源码如下所示。

```java
package javax.annotation;
import java.lang.annotation.*;
import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;
@Target({TYPE, FIELD, METHOD})
@Retention(RUNTIME)
public @interface Resource {
    String name() default "";
    String lookup() default "";
    Class<?> type() default java.lang.Object.class;
    enum AuthenticationType {
            CONTAINER,
            APPLICATION
    }
    AuthenticationType authenticationType() default AuthenticationType.CONTAINER;
    boolean shareable() default true;
    String mappedName() default "";
    String description() default "";
}
```

## @Inject注解

@Inject注解（JSR330）默认是根据参数名去寻找bean注入，支持spring的@Primary注解优先注入，@Inject注解可以增加@Named注解指定注入的bean。

@Inject注解的源码如下所示。

```java
package javax.inject;
import java.lang.annotation.Target;
import java.lang.annotation.Retention;
import java.lang.annotation.Documented;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
@Target({ METHOD, CONSTRUCTOR, FIELD })
@Retention(RUNTIME)
@Documented
public @interface Inject {}
```

**注意：要想使用@Inject注解，需要在项目的pom.xml文件中添加如下依赖。**

```xml
<dependency>
    <groupId>javax.inject</groupId>
    <artifactId>javax.inject</artifactId>
    <version>1</version>
</dependency>
```

## 项目案例

### 测试@Resource注解

首先，我们将项目中的PersonService类标注在personDao字段上的@Autowired注解和@Qualifier注解注释掉，然后添加@Resource注解，如下所示。

```java
//@Qualifier("personDao")
//@Autowired(required = false)
@Resource
private PersonDao personDao;
```

接下来，我们运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonService{personDao=PersonDao{remark='1'}}
```

可以看到，使用@Resource注解也能够自动装配组件，只不过此时自动装配的是remark为1的personDao。而不是我们在AutowiredConfig类中配置的优先装配的remark为2的personDao。AutowiredConfig类中配置的remark为2的personDao如下所示。

```java
@Primary
@Bean("personDao2")
public PersonDao personDao(){
    PersonDao personDao = new PersonDao();
    personDao.setRemark("2");
    return personDao;
}
```

我们在使用@Resource注解时，可以通过@Resource注解的name属性显示指定要装配的组件的名称。例如，我们要想装配remark为2的personDao，只需要为@Resource注解添加 `name="personDao2"`属性即可。如下所示。

```java
//@Qualifier("personDao")
//@Autowired(required = false)
@Resource(name = "personDao2")
private PersonDao personDao;
```

接下来，我们再次运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonService{personDao=PersonDao{remark='2'}}
```

可以看到，此时输出了remark为2的personDao，说明@Resource注解可以通过name属性显示指定要装配的bean。

### 测试@Inject注解

在PersonService类中，将@Resource注解注释掉，添加@Inject注解，如下所示。

```java
//@Qualifier("personDao")
//@Autowired(required = false)
//@Resource(name = "personDao2")
@Inject
private PersonDao personDao;
```

修改完毕后，我们运行AutowiredTest类的testAutowired01()方法，输出的结果信息如下所示。

```bash
PersonService{personDao=PersonDao{remark='2'}}
```

可以看到，使用@Inject注解默认输出的是remark为2的personDao。这是因为@Inject注解和@Autowired注解一样，默认优先装配使用了@Primary注解标注的组件。

## @Resource和@Inject注解与@Autowired注解的区别

**不同点**

* @Autowired是spring专有注解，@Resource是java中**JSR250中的规范**，@Inject是java中**JSR330中的规范**
* @Autowired支持参数required=false，@Resource，@Inject都不支持
* @Autowired，和@Inject支持@Primary注解优先注入，@Resource不支持
* @Autowired通过@Qualifier指定注入特定bean,@Resource可以通过参数name指定注入bean，@Inject需要@Named注解指定注入bean

**相同点**

三种注解都可以实现bean的注入。

## 重磅福利

关注「 **冰河技术** 」微信公众号，后台回复 “**设计模式**” 关键字领取《**深入浅出Java 23种设计模式**》PDF文档。回复“**Java8**”关键字领取《**Java8新特性教程**》PDF文档。回复“**限流**”关键字获取《**亿级流量下的分布式限流解决方案**》PDF文档，三本PDF均是由冰河原创并整理的超硬核教程，面试必备！！

<font color="#FF0000">**好了，今天就聊到这儿吧！别忘了点个赞，给个在看和转发，让更多的人看到，一起学习，一起进步！！**</font>

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)





