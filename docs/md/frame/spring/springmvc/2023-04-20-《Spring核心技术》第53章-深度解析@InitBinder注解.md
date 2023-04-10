---
title: 【付费】第53章：深度解析@InitBinder注解
pay: https://articles.zsxq.com/id_qcwj4wrgz6vo.html
---

# 《Spring核心技术》第53章：深度解析@InitBinder注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-53](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-53)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@InitBinder注解注册PropertyEditor、Converter和Formatter组件的案例和流程，从源码级别彻底掌握@InitBinder注解在Spring底层的执行流程。

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

`Spring中的@InitBinder注解，你真的彻底了解过吗？`

Spring中存在这样一个注解，它能够初始化WebDataBinder类的实例对象，将请求对象绑定到模型对象上，也可以将基于字符串的请求参数的类型转换成控制器方法形参的类型，还可以将服务返回的对象数据格式化成JSON等字符串数据。这个注解就是Spring中的@InitBinder注解。本章，就一起探讨下@InitBinder注解。

## 二、注解说明

`关于@InitBinder注解的一点点说明~~`

@InitBinder注解可以注册PropertyEditor、Converter和Formatter组件，实现参数绑定、参数类型转换和结果数据的格式化等功能。

### 2.1 注解源码

@InitBinder注解的源码详见：org.springframework.web.bind.annotation.InitBinder。

```java
/**
 * @author Juergen Hoeller
 * @author Sebastien Deleuze
 * @since 2.5
 * @see ControllerAdvice
 * @see org.springframework.web.bind.WebDataBinder
 * @see org.springframework.web.context.request.WebRequest
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Reflective
public @interface InitBinder {
	String[] value() default {};
}
```

从源码可以看出，@InitBinder注解是从Spring2.5版本开始提供的注解，并且只能标注到方法上，在@InitBinder注解中提供了一个String数组类型的value属性。

* value：String数组类型的属性，用于指定给哪些参数进行绑定。

### 2.2 使用场景

如果在控制器类中，需要将请求的参数绑定到模型对象、将基于字符串的请求参数的类型转换成控制器方法形参的类型或者将服务返回的对象数据格式化成JSON等字符串数据，就可以使用@InitBinder注解实现。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码