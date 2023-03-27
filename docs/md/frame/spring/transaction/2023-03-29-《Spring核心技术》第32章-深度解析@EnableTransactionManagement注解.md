---
title: 【付费】第32章：深度解析@EnableTransactionManagement注解
pay: https://articles.zsxq.com/id_8oxd67xgmkdk.html
---

# 《Spring核心技术》第32章：深度解析@EnableTransactionManagement注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：从源码级别彻底掌握@EnableTransactionManagement注解在Spring底层开启事务的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 源码时序图
* 源码解析
  * 解析解析总体流程类
  * 解析AutoProxyRegistrar类
  * 解析InfrastructureAdvisorAutoProxyCreator类
  * 解析ProxyTransactionManagementConfiguration类
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@EnableTransactionManagement注解，你真的彻底了解过吗？`

基于Spring事务开发过应用程序的小伙伴都知道，在配置类上添加@EnableTransactionManagement注解后，就能够开启Spring事务，那你知道@EnableTransactionManagement注解在Spring底层都做了哪些事情吗？

## 二、注解说明

`关于@EnableTransactionManagement注解的一点点说明~~`

在配置类上标注@EnableTransactionManagement注解后，就表示程序开启了基于注解的Spring事务功能，那@EnableTransactionManagement注解中都包含哪些信息呢？

### 2.1 注解源码

@EnableTransactionManagement注解的源码详见：org.springframework.transaction.annotation.EnableTransactionManagement。

```java
/**
 * @author Chris Beams
 * @author Juergen Hoeller
 * @since 3.1
 * @see TransactionManagementConfigurer
 * @see TransactionManagementConfigurationSelector
 * @see ProxyTransactionManagementConfiguration
 * @see org.springframework.transaction.aspectj.AspectJTransactionManagementConfiguration
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(TransactionManagementConfigurationSelector.class)
public @interface EnableTransactionManagement {
	boolean proxyTargetClass() default false;
	AdviceMode mode() default AdviceMode.PROXY;
	int order() default Ordered.LOWEST_PRECEDENCE;
}
```

@EnableTransactionManagement注解表示Spring支持基于注解的事务，同时开启了事务。从源码可以看出，@EnableTransactionManagement注解是从Spring3.1版本开始提供的注解，并且在注解上使用@Import注解导入了TransactionManagementConfigurationSelector类，TransactionManagementConfigurationSelector类就是@EnableTransactionManagement注解的核心所在。另外，在@EnableTransactionManagement注解中提供了三个属性，分别如下所示。

* proxyTargetClass：boolean类型的属性，表示指定目标类代理还是指定接口代理。取值为true或者false，true：指定目标类代理，此时会使用CGLib代理，false：指定接口代理，此时会使用JDK代理。默认取值为false，使用JDK代理接口。
* mode：AdviceMode枚举类型的属性，表示事务通知是如何执行的。取值为PROXY或者ASPECTJ，PROXY：事务会通过代理的方式执行，ASPECTJ：事务会通过aspectj的方式执行。如果是同一个类中调用的话，可以指定为ASPECTJ。
* order：表示事务处理的执行顺序，默认值为Ordered.LOWEST_PRECEDENCE，也就是最低优先级，实际值为：Integer.MAX_VALUE。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码