---
title: 【付费】第55章：深度解析@RequestAttribute注解
pay: https://articles.zsxq.com/id_8rw7tq1wuzom.html
---

# 《Spring核心技术》第55章-请求数据：深度解析@RequestAttribute注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-55](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-55)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@RequestAttribute注解的案例和流程，从源码级别彻底掌握@RequestAttribute注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 请求方法
  * 转发请求
  * 访问转发后的方法
* 源码解析
  * 请求方法
  * 转发请求
  * 访问转发后的方法
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@RequestAttribute注解，你真的彻底了解过吗？`

在基于SpringMVC或者SpringBoot开发Web应用程序时，如果不想通过HttpServletRequest的getAttribute()方法从请求域中获取数据，以此来达到与Servlet API进行解耦的目的，那我们又该如何实现呢？

## 二、注解说明

`关于@RequestAttribute注解的一点点说明~~`

@RequestAttribute注解指定属性名称就可以直接从当前请求的作用域中获取指定属性名称的值，接下来，看看@RequestAttribute注解的源码和使用场景。

### 2.1 注解源码

@RequestAttribute注解的源码详见：org.springframework.web.bind.annotation.RequestAttribute。

```java
/**
* @author Rossen Stoyanchev
 * @since 4.3
 * @see RequestMapping
 * @see SessionAttribute
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequestAttribute {
	@AliasFor("name")
	String value() default "";

	@AliasFor("value")
	String name() default "";

	boolean required() default true;
}
```

从源码可以看出，@RequestAttribute注解是从Spring4.3版本开始提供的注解，只能标注到方法中的参数上，并且在@RequestAttribute注解中提供了如下属性。

* value：String类型的属性，主要用于指定请求作用域中的属性名称。
* name：String类型的属性，作用与value属性相同。
* required：boolean类型的属性，表示请求作用域中的属性是否必需。true：必需；false：非必需。如果为true，则当前请求域中没有对应的属性，就会抛出异常。默认取值为true。

### 2.2 使用场景

在基于SpringMVC或者SpringBoot开发Web应用程序时，如果不想通过HttpServletRequest的getAttribute()方法从请求域中获取数据，从而实现与Servlet API进行解耦的目的，就可以使用@RequestAttribute注解实现。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
