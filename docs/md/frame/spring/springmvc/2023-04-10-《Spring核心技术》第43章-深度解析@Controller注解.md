---
title: 【付费】第43章：深度解析@Controller注解
pay: https://articles.zsxq.com/id_2tkel05tilvq.html
---

# 《Spring核心技术》第43章-配置控制器：深度解析@Controller注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-43](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-43)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Controller注解建立方法映射的案例和流程，从源码级别彻底掌握@Controller注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
* 源码解析
  *  DispatcherServlet基础知识
  * @Controller注解源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Controller注解，你真的彻底了解过吗？`

不管是使用SpringMVC，还是使用SpringBoot开发Web程序时，@Controller注解都是使用的比较多的注解，使用@Controller注解主要是将当前类标注为表现层的控制器。那你对@Controller注解真的了解了吗？

## 二、注解说明

`关于@Controller注解的一点点说明~~`

Spring基于@Component注解扩展了@Controller注解，@Controller注解主要标注到控制器类上。

### 2.1 注解源码

@Controller注解的源码详见：org.springframework.stereotype.Controller。

```java
/**
 * @author Arjen Poutsma
 * @author Juergen Hoeller
 * @since 2.5
 * @see Component
 * @see org.springframework.web.bind.annotation.RequestMapping
 * @see org.springframework.context.annotation.ClassPathBeanDefinitionScanner
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Component
public @interface Controller {
	@AliasFor(annotation = Component.class)
	String value() default "";

}
```

从源码可以看出，@Controller注解是从Spring2.5版本开始提供的注解，只能标注到类上，并且在@Controller注解上标注了@Component注解，说明@Controller注解是基于@Component注解扩展出的注解。并且在@Controller注解中提供了一个value属性。

* value：Spring类型的属性，表示注入IOC容器时Bean的唯一标识。

### 2.2 使用场景

当基于SpringMVC或者SpringBoot开发Web应用时，标注到类上表示控制器类，控制器类往往会对外提供接口，并且@Controller注解能够解析当前类中的方法，如果当前类中存在公有方法，并且方法上标注了@RequestMapping注解（含：@GetMapping注解、@PostMapping注解、@PutMapping注解、@DeleteMapping注解和@PatchMapping注解），则可以建立方法映射，对外提供访问链接，通过访问特定的链接就能够映射到对应的方法上。

## 三、使用案例

`一起实现@Controller注解的案例吧~~`

@Controller注解是使用SpringMVC和SpringBoot开发Web应用程序时，使用的比较多的注解。本节，就简单实现@Controller注解的使用案例。具体实现步骤如下所示。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码