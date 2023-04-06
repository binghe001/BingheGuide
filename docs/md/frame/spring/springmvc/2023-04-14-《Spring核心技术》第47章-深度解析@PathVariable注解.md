---
title: 【付费】第47章：深度解析@PathVariable注解
pay: https://articles.zsxq.com/id_27gccis9me0v.html
---

# 《Spring核心技术》第47章-绑定参数：深度解析@PathVariable注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-47](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-47)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@PathVariable注解解析参数的案例和流程，从源码级别彻底掌握@PathVariable注解在Spring底层的执行流程。

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

`Spring中的@PathVariable注解，你真的彻底了解过吗？`

基于SpringMVC或者SpringBoot开发Web应用程序时，除了@RequestParams注解可以接收参数外，@PathVariable注解也可以接收客户端传递过来的参数。在前面的文章中，介绍了@RequestParams注解是如何绑定和接收客户端传递过来的参数， 本章，就介绍下@PathVariable注解是如何接收和解析参数的。

## 二、注解说明

`关于@PathVariable注解的一点点说明~~`

@PathVariable注解能够使SpringMVC支持Rest风格的URL链接，并且能够使用@PathVariable注解获取请求URL中占位符对应的参数值。

### 2.1 注解源码

@PathVariable注解对应的源码详见：org.springframework.web.bind.annotation.PathVariable。

```java
/**
 * @author Arjen Poutsma
 * @author Juergen Hoeller
 * @since 3.0
 * @see RequestMapping
 * @see org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PathVariable {
	@AliasFor("name")
	String value() default "";

	/**
	 * @since 4.3.3
	 */
	@AliasFor("value")
	String name() default "";

	/**
	 * @since 4.3.3
	 */
	boolean required() default true;
}
```

从源码可以看出，@PathVariable注解是从Spring3.0开始提供的注解，只能标注到参数上。在@PathVariable注解中提供了如下属性。

* value：String类型的属性，用于指定URL中占位符的名称。
* name：Spring从4.3.3版本开始提供的String类型的属性，作用与value属性相同。
* required：Spring从4.3.3版本开始提供的String类型的属性，用于指定URL中是否必须存在当前占位符的参数，默认值为true。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码