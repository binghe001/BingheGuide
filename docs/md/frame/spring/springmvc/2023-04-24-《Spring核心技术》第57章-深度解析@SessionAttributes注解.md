---
title: 【付费】第57章：深度解析@SessionAttributes注解
pay: https://articles.zsxq.com/id_wnv2f8smr4c6.html
---

# 《Spring核心技术》第57章-会话数据：深度解析@SessionAttributes注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-57](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-57)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@SessionAttributes注解的案例和流程，从源码级别彻底掌握@SessionAttributes注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 请求方法
  * 重定向请求
  * 访问重定向后的方法
* 源码解析
  * 请求方法
  * 重定向请求
  * 访问重定向后的方法
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@SessionAttributes注解，你真的彻底了解过吗？`

在全面的文章中，介绍了@SessionAttribute注解，@SessionAttribute注解只能标注到方法的参数上，能够通过属性名称即可从当前Session的作用域中获取对应的数据。本章，就简单介绍下@SessionAttributes注解，尽管两个注解相似度比较高，仅仅相差一个字母s，但二者的差异还是蛮大的。

## 二、注解说明

`关于@SessionAttributes注解的一点点说明~~`

@SessionAttributes注解能够将数据保存到当前Session的作用域中，随后可以使用@SessionAttributes注解从当前作用域中获取数据，也可以使用HttpSession从当前作用域中获取数据。

### 2.1 注解源码

@SessionAttributes注解的源码详见：org.springframework.web.bind.annotation.SessionAttributes。

```java
/**
 * @author Juergen Hoeller
 * @author Sam Brannen
 * @since 2.5
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface SessionAttributes {

	@AliasFor("names")
	String[] value() default {};
	/**
	 * @since 4.2
	 */
	@AliasFor("value")
	String[] names() default {};
	Class<?>[] types() default {};
}
```

从源码可以看出，@SessionAttributes注解是从Spring2.5版本开始提供的注解，只能标注到类上，并且在@SessionAttributes注解中提供了如下属性。

* value：String数组类型的属性，表示要存入Session作用域中的名称。
* names：String数组类型的属性，作用与value属性相同。
* types：Class数组类型的属性，表示要存入Session域中的类的Class类型。

### 2.2 使用场景

在基于SpringMVC或者SpringBoot开发应用程序时，如果不想使用Servlet API操作Session数据，就可以使用@SessionAttributes注解实现把数据存入Session作用域。这样，就能够与Servlet API进行解耦，无需一次次手动向Session作用域中保存数据和读取数据。


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
