---
title: 【付费】第56章：深度解析@SessionAttribute注解
pay: https://articles.zsxq.com/id_m3ssh7jnnpcg.html
---

# 《Spring核心技术》第56章：深度解析@SessionAttribute注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-56](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-56)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@SessionAttribute注解的案例和流程，从源码级别彻底掌握@SessionAttribute注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 请求保存Session数据的方法
  * 请求获取Session数据的方法
* 源码解析
  * 请求保存Session数据的方法
  * 请求获取Session数据的方法
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@SessionAttribute注解，你真的彻底了解过吗？`

在基于SpringMVC或者SpringBoot开发Web应用程序时，如果不想通过HttpSession的getAttribute()方法从Session作用域中获取数据，而是直接通过指定的属性名就能获取Session作用域中的数据，以此来达到与Servlet API进行解耦的目的，那我们又该如何实现呢？

## 二、注解说明

`关于@SessionAttribute注解的一点点说明~~`

@SessionAttribute注解指定属性名称就可以直接从当前Session的作用域中获取指定属性名称的值，接下来，就简单介绍下@SessionAttribute注解的源码和使用场景。

### 2.1 注解源码

@SessionAttribute注解的源码详见：org.springframework.web.bind.annotation.SessionAttribute。

```java
/**
 * @author Rossen Stoyanchev
 * @since 4.3
 * @see RequestMapping
 * @see SessionAttributes
 * @see RequestAttribute
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SessionAttribute {
	@AliasFor("name")
	String value() default "";

	@AliasFor("value")
	String name() default "";

	boolean required() default true;
}
```

从源码可以看出，@SessionAttribute注解是从Spring4.3版本开始提供的注解，只能标注到方法中的参数上，并且在@SessionAttribute注解中提供了如下属性信息。

* value：String类型的属性，用于指定在Session作用域中的属性的名称。
* name：String类型的属性，作用与value属性相同。
* required：boolean类型的属性，表示当前Session作用域中是否必须存在指定的属性名称。true：必须存在；false：非必须存在。如果为true，当前Session作用域中不存在指定的属性名称，则抛出异常。默认值为true。

### 2.2 使用场景

在基于SpringMVC或者SpringBoot开发Web应用程序时，如果不想通过HttpSession的getAttribute()方法从Session作用域中获取数据，而是直接通过指定的属性名称就能获取到Session作用域中的属性值，从而实现与Servlet API进行解耦的目的，就可以使用@SessionAttribute注解实现。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码