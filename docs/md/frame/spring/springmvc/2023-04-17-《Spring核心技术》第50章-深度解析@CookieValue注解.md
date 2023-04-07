---
title: 【付费】第50章：深度解析@CookieValue注解
pay: https://articles.zsxq.com/id_aphnzhoz3wd3.html
---

# 《Spring核心技术》第50章-绑定参数：深度解析@CookieValue注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-50](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-50)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@CookieValue注解解析Cookie参数的案例和流程，从源码级别彻底掌握@CookieValue注解在Spring底层的执行流程。

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

`Spring中的@CookieValue注解，你真的彻底了解过吗？`

Spring中在绑定控制器方法参数方面，除了提供了获取请求参数数据、消息头数据和消息体数据外，还提供了一个@CookieValue注解能够获取Cookie中的数据，并将其绑定到控制器中的方法参数上。

本章，就简单聊聊@CookieValue注解的使用案例、在Spring底层执行的源码时序图和源码执行流程。

## 二、注解说明

`关于@CookieValue注解的一点点说明~~`

使用@CookieValue注解可以从消息头中获取到Cookie的值，并将Cookie值赋值给方法的形参。

### 2.1 注解源码

@CookieValue注解的源码详见：org.springframework.web.bind.annotation.CookieValue。

```java
/**
 * @author Juergen Hoeller
 * @author Sam Brannen
 * @since 3.0
 * @see RequestMapping
 * @see RequestParam
 * @see RequestHeader
 * @see org.springframework.web.bind.annotation.RequestMapping
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CookieValue {
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

从源码可以看出，@CookieValue注解是从Spring3.0开始提供的注解，只能标注到方法的参数上，并且在@CookieValue注解中提供了如下属性信息。

* value：String类型的属性，用于指定Cookie的名称。
* name：Spring4.2版本开始提供的String类型的属性，作用与value属性相同。
* required：boolean类型的属性，用于指定是否必须有Cookie信息。true：必须有，false：非必须有。如果设置为true时，请求中没有此Cookie信息会强制报错，默认为true。
* defaultValue：String类型的属性，用于指定Cookie的默认值。

### 2.2 使用场景

如果需要在方法中获取Cookie值，就可以使用@CookieValue注解实现从请求头中获取Cookie的参数值，并将其赋值给控制器类中的方法的形参。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
