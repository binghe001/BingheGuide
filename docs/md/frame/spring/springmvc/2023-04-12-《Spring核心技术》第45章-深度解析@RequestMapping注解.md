---
title: 【付费】第45章：深度解析@RequestMapping注解
pay: https://articles.zsxq.com/id_lr7351z398mb.html
---

# 《Spring核心技术》第45章：深度解析@RequestMapping注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-45](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-45)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@RequestMapping注解注册映射关系和定位HandlerMethod的案例和流程，从源码级别彻底掌握@RequestMapping注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 衍生注解
  * 使用场景
* 使用案例
* 源码时序图
  * 建立映射关系
  * 定位处理方法
  * 访问处理方法
* 源码解析
  * 建立映射关系
  * 定位处理方法
  * 访问处理方法
  * 容错处理机制
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@RequestMapping注解，你真的彻底了解过吗？`

基于SpringMVC或者SpringBoot开发过Web应用程序的小伙伴，一定对@RequestMapping这个注解不陌生，在方法上标注了@RequestMapping注解后，通过某个链接就能够访问到对应的方法，那你知道@RequestMapping注解在源码层面的执行流程吗？

本章，就对@RequestMapping注解在源码层面的执行流程一探究竟。

## 二、注解说明

`关于@RequestMapping注解的一点点说明~~`

在类上标注了@Controller注解或者@RestController注解之后，同时方法上如果标注了@RequestMapping注解，则方法会和某个链接自动建立映射关系，通过链接地址就能够访问到对应的方法。

### 2.1 注解源码

@RequestMapping注解的源码详见：org.springframework.web.bind.annotation.RequestMapping。

```java
/**
 * @author Juergen Hoeller
 * @author Arjen Poutsma
 * @author Sam Brannen
 * @since 2.5
 * @see GetMapping
 * @see PostMapping
 * @see PutMapping
 * @see DeleteMapping
 * @see PatchMapping
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Mapping
@Reflective(ControllerMappingReflectiveProcessor.class)
public @interface RequestMapping {

	String name() default "";

	@AliasFor("path")
	String[] value() default {};

	/**
	 * @since 4.2
	 */
	@AliasFor("value")
	String[] path() default {};

	/**
	 * GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE, TRACE.
	 */
	RequestMethod[] method() default {};
	String[] params() default {};

	/**
	 * RequestMapping(value = "/something", headers = "content-type=text/*")
	 */
	String[] headers() default {};

	/**
	 * consumes = "text/plain"
	 * consumes = {"text/plain", "application/*"}
	 * consumes = MediaType.TEXT_PLAIN_VALUE
	 */
	String[] consumes() default {};

	/**
	 * produces = "text/plain"
	 * produces = {"text/plain", "application/*"}
	 * produces = MediaType.TEXT_PLAIN_VALUE
	 * produces = "text/plain;charset=UTF-8"
	 */
	String[] produces() default {};
}
```

从源码可以看出，@RequestMapping注解是从Spring2.5版本开始提供的注解，可以标注到类和方法上，并且在@RequestMapping注解中提供了多个属性。

* name：String类型的属性，为请求的URL指定一个名称。

* value：String数组类型的属性，指定请求的URL。

* path：从Spring4.2版本开始提供的String数组类型的属性，作用与value属性相同。

* method：RequestMethod枚举数组类型的属性，用于指定请求的方法，取值可以为RequestMethod枚举类型中的GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE。既可以指定单个RequestMethod枚举类型，也可以同时指定多个RequestMethod枚举类型，不指定时，表示处理所有的RequestMethod枚举类型。

* params：String数组类型的属性，用于指定请求参数，支持简单的表达式，使用params属性时，要求请求的参数Key和Value必须与params属性中配置的Key和Value相同。例如下面的示例所示。

  * @RequestMapping(value = "/binghe", params = {"userName"})：表示请求参数中必须有userName。
  * @RequestMapping(value = "/binghe", params = {"userId = 1001"})：表示请求的参数中Key为userId，值为1001。

  可以使用params属性实现同一个URL映射到不同的方法上，请求时根据不同的参数映射到不同的方法上。

* headers：String数组类型的属性，用于指定请求头信息，主要是限制请求头的信息，当请求头中必须包含某些指定的头信息时，才能让方法处理请求。例如下面的示例所示。

  * @RequestMapping(value = "/binghe", headers = "content-type=text/*")

* consumes：String数组类型的属性，用于指定要接收的请求体（消息体）的类型，只有满足这些类型的请求才会被处理，不指定时，表示处理所有类型。取值可以参见：org.springframework.http.MediaType。例如下面的示例所示。

  * @RequestMapping(value = "/binghe", consumes = {"text/plain", "application/*"})
  * @RequestMapping(value = "/binghe", consumes = MediaType.TEXT_PLAIN_VALUE)

  还有一点就是consumes属性支持类似逻辑非操作，例如下面的示例所示。

  * @RequestMapping(value = "/binghe", consumes = {"!text/plain", "application/*"})
  * @RequestMapping(value = "/binghe", consumes = !MediaType.TEXT_PLAIN_VALUE)

* produces：String数组类型的属性，用于指定要响应的消息体的类型，指定的类型必须是请求头（Accept）中所包含的类型。当请求头（Accept）中包含指定的类型时才会响应结果，取值可以参见：org.springframework.http.MediaType。例如下面的实例所示。

  * @RequestMapping(value = "/binghe", produces= {"text/plain", "application/*"})
  * @RequestMapping(value = "/binghe", produces = MediaType.TEXT_PLAIN_VALUE)

  还有一点就是produces属性支持类似逻辑非操作，例如下面的示例所示。

  * @RequestMapping(value = "/binghe", produces = {"!text/plain", "application/*"})
  * @RequestMapping(value = "/binghe", produces = !MediaType.TEXT_PLAIN_VALUE)

  **注意：使用@RequestMapping注解时，只要出现两个或以上的属性时，多个属性之间的关系是与关系，表示必须同时满足条件才会处理。**

### 2.2 衍生注解

@RequestMapping注解还有五个衍生注解，分别如下所示。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码