---
title: 【付费】第52章：深度解析@ExceptionHandler注解
pay: https://articles.zsxq.com/id_0zdvz0bk7zgn.html
---

# 《Spring核心技术》第52章-增强控制器方法：深度解析@ExceptionHandler注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-52](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-52)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@ExceptionHandler注解捕获异常的案例和流程，从源码级别彻底掌握@ExceptionHandler注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 获取参数
  * 调用控制器方法
  * 捕获异常
* 源码解析
  * 获取参数
  * 调用控制器方法
  * 捕获异常
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@ExceptionHandler注解，你真的彻底了解过吗？`

在基于SpringMVC或者SpringBoot开发Web应用时，往往需要在程序中处理很多的异常情况，如果在程序中大量使用try-catch代码块来捕获异常则显得代码比较杂乱。即使在程序中使用了大量的try-catch代码块来捕获异常，也难免会存在未捕获的异常，一旦在生产环境中触发了这些未捕获的异常，可能会造成意想不到的后果。那有什么办法来统一捕获和处理这些异常吗？

## 二、注解说明

`关于@ExceptionHandler注解的一点点说明~~`

@ExceptionHandler注解能够统一捕获并处理异常，在@ExceptionHandler标注的方法中可以同一捕获异常，根据具体情况向客户端程序提示具体的友好异常信息。

### 2.1 注解源码

@ExceptionHandler注解的源码详见：org.springframework.web.bind.annotation.ExceptionHandler。

```java
/**
 * @author Arjen Poutsma
 * @author Juergen Hoeller
 * @since 3.0
 * @see ControllerAdvice
 * @see org.springframework.web.context.request.WebRequest
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Reflective(ExceptionHandlerReflectiveProcessor.class)
public @interface ExceptionHandler {
	Class<? extends Throwable>[] value() default {};
}
```

从源码可以看出，@ExceptionHandler注解是从Spring3.0版本开始提供的注解，只能标注到方法上，并且在@ExceptionHandler注解中提供了如下属性信息。

* value：Class数组类型的属性，主要是用于指定捕获的异常类型。

### 2.2 使用场景

如果在基于SpringMVC或者SpringBoot开发应用程序时，想统一捕获并处理异常信息，就可以使用@ExceptionHandler注解实现。


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码