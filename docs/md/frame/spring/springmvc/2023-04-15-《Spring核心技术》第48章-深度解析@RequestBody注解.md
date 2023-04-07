---
title: 【付费】第48章：深度解析@RequestBody注解
pay: https://articles.zsxq.com/id_wzt9ndj1t2o2.html
---

# 《Spring核心技术》第48章-绑定参数：深度解析@RequestBody注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-48](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-48)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@RequestBody注解解析参数的案例和流程，从源码级别彻底掌握@RequestBody注解在Spring底层的执行流程。

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

`Spring中的@RequestBody注解，你真的彻底了解过吗？`

在前面的文章中，介绍了如何使用@RequestParam注解和@PathVariable注解获取参数，除了使用@RequestParam注解和@PathVariable注解可以获取参数外，在Spring中还可以使用@RequestBody注解获取参数。

本节，就对@RequestBody注解获取参数的案例和执行流程一探究竟。

## 二、注解说明

`关于@RequestBody注解的一点点说明~~`

使用@RequestBody注解可以获取全部的请求体，并且可以根据不同的contentType获取不同的消息转换器，使用消息转换器将数据转换成不同的数据格式。

### 2.1 注解源码

@RequestBody注解的源码详见：org.springframework.web.bind.annotation.RequestBody。

```java
/**
 * @author Arjen Poutsma
 * @since 3.0
 * @see RequestHeader
 * @see ResponseBody
 * @see org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequestBody {
    /*
	 * @since 3.2
	 */
	boolean required() default true;

}
```

从源码可以看出，@RequestBody注解是从Spring3.0版本开始提供的注解，只能标注到参数上，在@RequestBody注解中提供了一个boolean类型的属性。

* required：Spring3.2版本开始提供的boolean类型的属性，表示是否必须有请求体。true：必须有请求体，false：可以没有请求体。如果为true时，未获取到请求体的数据时会强制报错。默认取值为true。

### 2.2 使用场景

如果在基于SpringMVC或者SpringBoot开发Web应用程序时，需要获取全部的请求体，此时就可以使用@RequestBody注解实现。并且在使用@RequestBody注解获取请求体时，可以自定义消息的转换器，将接收到的数据转换成不同的数据格式。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码