---
title: 【付费】第51章：深度解析@ModelAttribute注解
pay: https://articles.zsxq.com/id_6zpnxo0j94za.html
---

# 《Spring核心技术》第51章-增强控制器方法：深度解析@ModelAttribute注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-51](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-51)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@ModelAttribute注解标注方法和参数的案例和流程，从源码级别彻底掌握@ModelAttribute注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 执行@ModelAttribute标注的方法
  * 执行控制器方法
* 源码解析
  * 执行@ModelAttribute标注的方法
  * 执行控制器方法
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@ModelAttribute注解，你真的彻底了解过吗？`

Spring支持将数据存入某个数据结构，例如Model、Map、ModelMap中，然后使用@ModelAttribute注解从这些数据结构中将数据获取出来，赋值给方法中的参数。那么问题来了，你了解过Spring中的@ModelAttribute注解吗？

## 二、注解说明

`关于@ModelAttribute注解的一点点说明~~`

@ModelAttribute注解支持将数据存入某个数据结构，然后在方法的参数上使用@ModelAttribute注解从数据结构中获取之前存入的数据。

### 2.1 注解源码

@ModelAttribute注解的源码详见：org.springframework.web.bind.annotation.ModelAttribute。

```java
/**
* @author Juergen Hoeller
 * @author Rossen Stoyanchev
 * @author Sebastien Deleuze
 * @since 2.5
 * @see ControllerAdvice
 */
@Target({ElementType.PARAMETER, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Reflective
public @interface ModelAttribute {
	@AliasFor("name")
	String value() default "";
	/**
	 * @since 4.3
	 */
	@AliasFor("value")
	String name() default "";
	/**
	 * @since 4.3
	 */
	boolean binding() default true;
}
```

从源码可以看出，@ModelAttribute注解是从Spring2.5版本开始提供的注解，可以标注到参数和方法上。当标注到方法上时，表示执行控制器类的方法之前，会先执行使用@ModelAttribute注解标注的方法向Model、Map、ModelMap等数据结构中存入数据。当标注到参数上时，能够从Model、Map、ModelMap等数据结构中获取数据，并赋值给参数。

在@ModelAttribute注解中，提供了如下属性。

* value：String类型的属性，如果注解标注到方法上，表示存入数据时的Key，存入数据的值是方法的返回值。如果注解标注到参数上，则可以从Model、Map和ModelMap等数据结构中获取数据，此时表示要获取的数据的Key。
* name：从Spring4.3版本开始提供的String类型的属性，作用与value属性相同。
* binding：从Spring4.3版本开始提供的boolean类型的属性，表示是否支持绑定数据，true：支持，false：不支持。默认为true。

### 2.2 使用场景

在基于SpringMVC或者SpringBoot开发Web应用程序时，如果需要在控制器方法执行之前执行一些方法，处理一些数据逻辑，然后将数据存储到诸如Model、Map和ModelMap等数据结构中。随后，在控制器方法中自动获取之前存储的数据，并将其绑定到方法的参数上，此时就可以使用@ModelAttribute注解实现。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码