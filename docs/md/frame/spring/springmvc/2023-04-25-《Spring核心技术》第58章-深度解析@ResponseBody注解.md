---
title: 【付费】第58章：深度解析@ResponseBody注解
pay: https://articles.zsxq.com/id_x5e4eh58lfrv.html
---

# 《Spring核心技术》第58章-响应结果：深度解析@ResponseBody注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-58](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-58)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@ResponseBody注解的案例和流程，从源码级别彻底掌握@ResponseBody注解在Spring底层的执行流程。

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

`Spring中的@ResponseBody注解，你真的彻底了解过吗？`

在前面的文章中，介绍@RestController注解时，提了下@ResponseBody注解，@RestController注解同时具备@Controller注解和@ResponseBody注解的功能，也在前面文章的案例程序中使用过@ResponseBody注解，那你真的了解@ResponseBody注解吗？

## 二、注解说明

`关于@ResponseBody注解的一点点说明~~`

@ResponseBody注解可以标注到类和方法上，能够将方法处理的结果数据返回给客户端，本节，就对@ResponseBody注解进行简单的说明。

### 2.1 注解源码

@ResponseBody注解的源码详见：org.springframework.web.bind.annotation.ResponseBody。

```java
/** 
 * @author Arjen Poutsma
 * @since 3.0
 * @see RequestBody
 * @see RestController
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface ResponseBody {

}
```

从源码可以看出，@ResponseBody注解是从Spring3.0版本开始提供的注解，可以标注到类上，也可以标注到方法上，并且在@ResponseBody注解中没有提供任何属性。

### 2.2 使用场景

@ResponseBody注解往往会结合@Controller注解和@RequestMapping注解使用，能够将方法的返回结果响应给客户端程序。也可以使用@RestController注解和@RequestMapping注解实现，@RestController注解中就包含了@ResponseBody注解的功能。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码