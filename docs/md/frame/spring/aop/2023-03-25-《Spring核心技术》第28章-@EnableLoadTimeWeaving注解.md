---
title: 【付费】第28章：@EnableLoadTimeWeaving注解
pay: https://articles.zsxq.com/id_hsvnjsdjoci8.html
---

# 《Spring核心技术》第28章：@EnableLoadTimeWeaving注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-28](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-28)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★☆☆

* **本章重点**：进一步学习并掌握@EnableLoadTimeWeaving注解切换不同场景实现类增强的案例和流程。

------

本章目录如下所示：

* 学习指引
* 注解说明

  * 注解源码
  * 使用场景
* 使用案例
* 总结
* 思考
* VIP服务

## 一、学习指引

`在Spring AOP中，你了解过@EnableLoadTimeWeaving注解吗？`

Spring中有这么一个注解，可以实现切换不同场景下实现目标类的增强，这个注解就是@EnableLoadTimeWeaving注解。很多工作多年的开发人员对于@EnableLoadTimeWeaving注解都不是很了解。本章，我们就一起来聊聊@EnableLoadTimeWeaving注解。

## 二、注解说明

`关于@EnableLoadTimeWeaving注解的一点点说明~~`

Spring默认是在编译时，将切面类织入到Java类中，那你有没有想过怎么让切面类在类加载的时候就织入到Java类中？

### 2.1 注解源码

@EnableLoadTimeWeaving注解主要用于切换不同场景下实现类的增强功能，源码详见：org.springframework.context.annotation.EnableLoadTimeWeaving。

```java
/**
 * @author Chris Beams
 * @since 3.1
 * @see LoadTimeWeaver
 * @see DefaultContextLoadTimeWeaver
 * @see org.aspectj.weaver.loadtime.ClassPreProcessorAgentAdapter
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(LoadTimeWeavingConfiguration.class)
public @interface EnableLoadTimeWeaving {
	AspectJWeaving aspectjWeaving() default AspectJWeaving.AUTODETECT;
	enum AspectJWeaving {
		ENABLED,
		DISABLED,
		AUTODETECT;
	}
}
```

从@EnableLoadTimeWeaving注解的源码可以看出，@EnableLoadTimeWeaving注解是从Spring3.1版本开始提供的注解，开启@EnableLoadTimeWeaving注解只能标注到类上。在@EnableLoadTimeWeaving注解中提供了一个AspectJWeaving枚举类型的aspectjWeaving属性。具体含义如下所示。

* aspectjWeaving：是否开启LTW的支持。具体取值如下所示。
  * ENABLED：开启LTW支持。
  * DISABLED：不开启LTW支持。
  * AUTODETECT：检测类路径下的META-INF目录下是否存在aop.xml文件，如果存在，则开启LTW支持，否则，不开启LTW支持。

### 2.2 使用场景

在Java 语言中，从织入切面的方式上来看，存在三种织入方式：编译期织入、类加载期织入和运行期织入。编译期织入是指在Java编译期，采用特殊的编译器，将切面织入到Java类中；而类加载期织入则指通过特殊的类加载器，在类字节码加载到JVM时，织入切
面；运行期织入则是采用CGLib工具或JDK动态代理进行切面的织入。

AspectJ提供了两种切面织入方式，第一种通过特殊编译器，在编译期，将AspectJ语言编写的切面类织入到Java类中，可以通过一个Ant或Maven任务来完成这个操作；第二种方式是类加载期织入，也简称为LTW（Load Time Weaving）。

> 使用场景的以上内容摘录自互联网。

Spring默认是在编译期，将AspectJ语言编写的切面类织入到Java类中，可以使用@EnableLoadTimeWeaving注解开启LTW支持，也就是开启在类加载时，将AspectJ语言编写的切面类织入到Java类中的支持。

## 三、使用案例


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
