---
title: 【付费】第49章：深度解析@RequestHeader注解
pay: https://articles.zsxq.com/id_vd0nabjnlo9x.html
---

# 《Spring核心技术》第49章-绑定参数：深度解析@RequestHeader注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-49](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-49)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@RequestHeader注解解析消息头参数的案例和流程，从源码级别彻底掌握@RequestHeader注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@RequestHeader注解，你真的彻底了解过吗？`

在前面介绍的绑定控制器方法参数的注解中，基本都是绑定的请求参数和请求体中的数据，在Spring中，提供了一个@RequestHeader注解可以解析存放在请求头中的参数，

本节，就对@RequestHeader注解获取参数的案例和执行流程一探究竟。

## 二、注解说明

`关于@RequestHeader注解的一点点说明~~`

使用@RequestHeader注解可以获取到存放在请求头中的参数信息。

### 2.1 注解源码

@RequestHeader注解的源码详见：org.springframework.web.bind.annotation.RequestHeader。

```java
/*
* @author Juergen Hoeller
 * @author Sam Brannen
 * @since 3.0
 * @see RequestMapping
 * @see RequestParam
 * @see CookieValue
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequestHeader {
	@AliasFor("name")
	String value() default "";
	/**
	 * @since 4.2
	 */
	@AliasFor("value")
	String name() default "";
	boolean required() default true;
	String defaultValue() default ValueConstants.DEFAULT_NONE;
}
```

从源码可以看出，@RequestHeader注解是从Spring3.0开始提供的注解，只能标注到参数上，并且在@RequestHeader注解中，提供了如下属性信息。

* value：String类型的属性，用于指定消息头的名称。
* name：Spring从4.2版本开始提供的String类型的属性，作用与value属性相同。
* required：boolean类型的属性，用于指定是否必须有此消息头。true：必须有，false：非必须有。如果设置为true时，请求中没有此消息头会强制报错，默认为true。
* defaultValue：String类型的属性，用于指定消息头的默认值。

### 2.2 使用场景

如果需要在方法中获取请求头中的参数，就可以使用@RequestHeader注解实现从请求头中获取消息头的参数值，并将其赋值给控制器类中的方法的形参。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
