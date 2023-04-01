---
title: 【付费】第42章：深度解析@Controller注解
pay: https://articles.zsxq.com/id_rt2w9t6inv5j.html
---

# 《Spring核心技术》第42章-配置控制器：深度解析@Controller注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-42](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-42)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Controller注解注册Controller组件的案例和流程，从源码级别彻底掌握@Controller注解在Spring底层的执行流程。

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

从源码可以看出，@Controller注解是从Spring2.5版本开始提供的注解，只能标注到类上，并且在@Controller注解上标注了@Component注解。并且在@Controller注解中提供了一个value属性。

* value：Spring类型的属性，表示注入IOC容器时Bean的唯一标识。

### 2.2 使用场景

当基于SpringMVC或者SpringBoot开发Web应用时，标注到类上表示控制器类，控制器类往往会对外提供接口。

## 三、使用案例

`一起实现@Controller注解的案例吧~~`

@Controller注解是使用SpringMVC和SpringBoot开发Web应用程序时，使用的比较多的注解。本节，就简单实现@Controller注解的使用案例。具体实现步骤如下所示。

**（1）新增BingheController类**

BingheController类的源码详见：spring-annotation-chapter-42工程下的io.binghe.spring.annotation.chapter42.controller.BingheController。

```java
@Controller
public class BingheController {
}
```

可以看到，BingheController类是一个空的Java类，并且在BingheController类上标注了@Controller注解，说明BingheController类是一个控制器类。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
