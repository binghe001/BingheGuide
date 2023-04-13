---
title: 【付费】第59章：深度解析@CrossOrigin注解
pay: https://articles.zsxq.com/id_iehog588vfef.html
---

# 《Spring核心技术》第59章-跨域访问：深度解析@CrossOrigin注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-59](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-59)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@CrossOrigin注解的案例和流程，从源码级别彻底掌握@CrossOrigin注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 启动程序
  * 请求链接
* 源码解析
  * 启动程序
  * 请求链接
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@CrossOrigin注解，你真的彻底了解过吗？`

@CrossOrigin注解能够解决跨域问题，所谓跨域就是请求不在同一个域名下。一个典型的场景就是：在前后端分离的场景下，前端部署在`binghe001.com`域名下，要去访问`binghe002.com`域名下的图片等资源，就会出现跨域问题。这种跨域问题，如果不对这种跨域问题进行处理，访问过程就会报错。Spring中提供的@CrossOrigin注解就能够解决访问过程中的跨域问题。

## 二、注解说明

`关于@CrossOrigin注解的一点点说明~~`

@CrossOrigin注解是Spring中专门提供的一个用于处理跨域请求的注解，本节，就对@CrossOrigin注解的源码和使用场景进行简单的介绍。

### 2.1 注解源码

@CrossOrigin注解的源码详见：org.springframework.web.bind.annotation.CrossOrigin。

```java
/**
 * @author Russell Allen
 * @author Sebastien Deleuze
 * @author Sam Brannen
 * @author Ruslan Akhundov
 * @since 4.2
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CrossOrigin {
	@AliasFor("origins")
	String[] value() default {};
	@AliasFor("value")
	String[] origins() default {};

	/**
	 * @since 5.3
	 */
	String[] originPatterns() default {};
	String[] allowedHeaders() default {};
	String[] exposedHeaders() default {};
	RequestMethod[] methods() default {};
	String allowCredentials() default "";
	long maxAge() default -1;
}
```

从源码可以看出，@CrossOrigin注解是从Spring4.2版本开始提供的注解，可以标注到类上，也可以标注到方法上。在@CrossOrigin注解中，提供了如下属性信息。

* value：String数组类型的属性，用于指定可以跨域请求的源列表，例如：`value="http://binghe.com"`，则表示允许binghe.com域名下的资源实现跨域请求，如果指定为*，则是允许任意请求源跨域请求。
* origins：String数组类型的属性，作用与value属性相同。
* originPatterns：从Spring5.3版本开始提供的String数组类型的属性，可以用于设置多个跨域匹配规则。
* allowedHeaders：String数组类型的属性，用于指定请求时允许跨域请求的请求头列表。例如：`allowedHeaders="Content-Type"`。默认表示所有请求头都可以跨域请求。
* exposedHeaders：String数组类型的属性，表示响应头中允许访问的消息头，例如，`exposedHeaders="Content-Length"`。
* methods：RequestMethod数组类型的属性，表示允许跨域请求的HTTP方法。默认情况下，允许请求的HTTP方法与@RequestMapping注解相同。
* allowCredentials：String类型的属性，表示是否允许跨域发送Cookie信息，使用此属性时，必须在value属性或者origins属性中明确指定具体的访问域。
* maxAge：long类型的属性，表示预处理响应的最大缓存时间，单位为秒。默认值为1800秒，也就是30分钟。

### 2.2 使用场景

在基于SpringMVC或者SpringBoot开发Web应用时，如果采用前后端分离模式进行开发，前端与后端程序不在同一个域下，例如后端程序部署在`binghe001.com`下，前端程序部署在`binghe002.com`下，前端程序需要访问后端的服务。或者前端程序需要跨域访问外界的资源，例如，前端部署在`binghe001.com`下，需要跨域访问`binghe002.com`下的图片资源，此时就可以使用@CrossOrigin注解来处理跨域访问的问题。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
