---
title: 【付费】第46章：深度解析@RequestParam注解
pay: https://articles.zsxq.com/id_uvbwbxp5pwgw.html
---

# 《Spring核心技术》第46章-绑定参数：深度解析@RequestParam注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-46](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-46)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@RequestParam注解解析参数的案例和流程，从源码级别彻底掌握@RequestParam注解在Spring底层的执行流程。

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

`Spring中的@RequestParams注解，你真的彻底了解过吗？`

基于SpringMVC或者SpringBoot开发过Web应用程序的小伙伴，多多少少可能都会接触到@RequestParams注解，@RequestParams注解注解可以接收客户端传递过来的参数，那么问题来了，@RequestParams注解到底是怎么绑定和接收客户端传递过来的参数呢？Spring底层又是怎么解析到这个参数的呢？

本章，就对@RequestMapping注解在源码层面的执行流程一探究竟。

## 二、注解说明

`关于@RequestParams注解的一点点说明~~`

@RequestParams注解可以用来接收客户端传递过来的参数，可以接收单个参数，表单数据、文件数据，也可以接收Map等集合类型的参数。

### 2.1 注解源码

@RequestParams注解的源码详见：org.springframework.web.bind.annotation.RequestParam。

```java
/**
 * @author Arjen Poutsma
 * @author Juergen Hoeller
 * @author Sam Brannen
 * @since 2.5
 * @see RequestMapping
 * @see RequestHeader
 * @see CookieValue
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequestParam {
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

从源码可以看出，@RequestParam注解是从Spring2.5版本开始提供的注解，主要标注到参数上用来接收客户端传递的参数，在@RequestParam注解内部提供了如下属性。

* value：String类型的属性，指定URL中参数的名称。
* name：Spring4.2版本开始提供的String类型的属性，与name属性作用相同。
* required：boolean类型的属性，指定对应的参数是否必须有值，true：必须有值，false：可以没有值。如果为true时，参数没有值就会报错。
* defaultValue：String类型的属性，指定参数没有值时的默认值。

### 2.2 使用场景

@RequestParam注解主要用于获取请求的参数值，并且为控制器类中的方法形参的参数赋值。如果请求参数的名称与控制器中方法的形参的参数名称一致，@RequestParam注解可以省略。如果使用@RequestParam注解没有获取到参数值时，可以使用@RequestParam注解提供默认的参数值。

使用@RequestParam参数既可以接收单个参数，表单数据、文件数据，也可以接收Map集合等类型的参数。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码