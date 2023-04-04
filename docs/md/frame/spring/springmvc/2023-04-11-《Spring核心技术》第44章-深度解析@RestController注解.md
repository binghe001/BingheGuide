---
title: 【付费】第44章：深度解析@RestController注解
pay: https://articles.zsxq.com/id_wrrk6j19tov0.html
---

# 《Spring核心技术》第44章-配置控制器：深度解析@RestController注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-44](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-44)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@RestController注解建立方法映射的案例和流程，从源码级别彻底掌握@RestController注解在Spring底层的执行流程。

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

`Spring中的@RestController注解，你真的彻底了解过吗？`

基于SpringMVC或者SpringBoot开发Web应用时，除了@Controller注解使用的比较多之外，@RestController注解也是使用的比较频繁的注解。@RestController注解不仅仅具备@Controller注解的所有功能，并且还能将方法返回的结果数据自动以流的形式输出给客服端。从本质上讲，@RestController注解就是@Controller注解与@ResponseBody注解的组合。

本章，还是单独介绍@RestController注解，配合使用@RequestMapping等方法映射注解会在后续文章中介绍，关于@ResponseBody注解也会在后续的文章中进行详细介绍。

## 二、注解说明

`关于@RestController注解的一点点说明~~`

SpringMVC基于@Controller注解和@ResponseBody注解扩展了@RestController注解，使得@RestController注解同时具备于@Controller注解和@ResponseBody注解的功能。

### 2.1 注解源码

@RestController注解的源码详见：org.springframework.web.bind.annotation.RestController。

```java
/**
 * @author Rossen Stoyanchev
 * @author Sam Brannen
 * @since 4.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Controller
@ResponseBody
public @interface RestController {
	/**
	 * @since 4.0.1
	 */
	@AliasFor(annotation = Controller.class)
	String value() default "";

}
```

从源码可以看出@RestController注解是从Spring4.0开始提供的注解，只能标注到类上，并且在@RestController注解上标注了@Controller注解和@ResponseBody注解，说明@RestController注解同时具备@Controller注解和@ResponseBody注解的功能。并且在@RestController注解内部提供了一个Spring类型的value属性。

* value：指定注入IOC容器时的Bean的唯一标识。

### 2.2 使用场景

与@Controller注解一样，当基于SpringMVC或者SpringBoot开发Web应用时，标注到类上表示控制器类，控制器类往往会对外提供接口，并且Spring通过@RestController注解能够解析当前类中的方法，如果当前类中存在公有方法，并且方法上标注了@RequestMapping注解（含：@GetMapping注解、@PostMapping注解、@PutMapping注解、@DeleteMapping注解和@PatchMapping注解），则可以建立方法映射，对外提供访问链接，通过访问特定的链接就能够映射到对应的方法上。

与@Controller注解不同的是，@RestController注解还具备@ResponseBody注解的功能，能够将方法返回的结果数据自动以流的形式输出给客服端。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码