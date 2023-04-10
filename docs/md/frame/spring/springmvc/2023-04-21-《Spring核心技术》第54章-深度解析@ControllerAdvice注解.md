---
title: 【付费】第54章：深度解析@ControllerAdvice注解
pay: https://articles.zsxq.com/id_l1q55mu4o9ou.html
---

# 《Spring核心技术》第54章-提供通知：深度解析@ControllerAdvice注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-54](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-54)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@ControllerAdvice注解增强通知的案例和流程，从源码级别彻底掌握@ControllerAdvice注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 启动Tomcat
  * 捕获异常
* 源码解析
  * 启动Tomcat
  * 捕获异常
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@ControllerAdvice注解，你真的彻底了解过吗？`

在基于SpringMVC或者SpringBoot开发Web应用程序时，通常都会设计并开发自己的异常处理器，统一处理各种各样的异常。这种异常处理器就可以使用@ControllerAdvice注解结合@ExceptionHandler注解实现。除了@ExceptionHandler注解外，@ControllerAdvice注解也可以结合@ModelAttribute注解和@InitBinder注解使用。

## 二、注解说明

`关于@ControllerAdvice注解的一点点说明~~`

@ControllerAdvice注解可以给控制器提供一个增强的通知，能够结合@ExceptionHandler注解、@ModelAttribute注解和@InitBinder注解使用。

### 2.1 注解源码

@ControllerAdvice注解的源码详见：org.springframework.web.bind.annotation.ControllerAdvice。

```java
/**
 * @author Rossen Stoyanchev
 * @author Brian Clozel
 * @author Sam Brannen
 * @since 3.2
 * @see org.springframework.stereotype.Controller
 * @see RestControllerAdvice
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Component
public @interface ControllerAdvice {
	/**
	 * @since 4.0
	 * @see #basePackages
	 */
	@AliasFor("basePackages")
	String[] value() default {};

	/**
	 * @since 4.0
	 */
	@AliasFor("value")
	String[] basePackages() default {};

	/**
	 * @since 4.0
	 */
	Class<?>[] basePackageClasses() default {};

	/**
	 * @since 4.0
	 */
	Class<?>[] assignableTypes() default {};

	/**
	 * @since 4.0
	 */
	Class<? extends Annotation>[] annotations() default {};
}
```

从源码可以看出，@ControllerAdvice注解是从Spring3.2版本开始提供的注解，只能标注到类上。同时，可以看到，在@ControllerAdvice注解上标注了@Component注解，说明@ControllerAdvice注解本质上还是@Component注解。在@ControllerAdvice注解中提供了如下属性信息。

* value：Spring数组类型的属性，指定进行增强的控制器所在的包名。
* basePackages：作用与value相同。
* basePackageClasses：Class数组类型的属性，指定进行增强的类的Class对象。
* assignableTypes：Class数组类型的属性，对特定的Class对象进行增强。
* annotations：Class数组类型的属性，对特定的注解进行增强。

### 2.2 使用场景

在基于SpringMVC或者SpringBoot开发Web应用程序时，基本上都会用到异常处理器，来统一处理各种各样的异常，这些异常处理器就可以使用@ControllerAdvice注解结合@ExceptionHandler注解实现。当然，@ControllerAdvice注解也可以结合@ModelAttribute注解实现增强模型属性数据的功能，结合@InitBinder注解实现参数绑定、参数类型转换和结果数据的格式化等功能的增强操作。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码