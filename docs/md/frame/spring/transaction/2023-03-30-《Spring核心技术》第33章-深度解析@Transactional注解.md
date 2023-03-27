---
title: 【付费】第33章：深度解析@Transactional注解
pay: https://articles.zsxq.com/id_ezlz9t1pjks0.html
---

# 《Spring核心技术》第33章：深度解析@Transactional注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：从源码级别彻底掌握Spring底层解析@Transactional注解属性的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Transactional注解，你真的彻底了解过吗？`

学习过Spring事务的小伙伴对@Transactional注解应该都不陌生，在需要使用Spring事务的方法上标注@Transactional注解，Spring在执行方法时，就能够自动开启事务、提交事务以及回滚事务。此时，完全不需要开发人员过多的关注事务的开启、提交与回滚操作。那经常使用@Transactional注解的你，是否想过Spring底层是如何解析@Transactional注解的呢？

## 二、注解说明

`关于@Transactional注解的一点点说明~~`

在基于Spring注解开发应用程序时，如果需要使用Spring事务，通常会在方法上标注@Transactional注解搞定，那关于@Transactional注解有哪些细节需要关注呢？

### 2.1 注解源码

@Transactional注解的源码详见：org.springframework.transaction.annotation.Transactional。

```java
/**
 * @author Colin Sampaleanu
 * @author Juergen Hoeller
 * @author Sam Brannen
 * @author Mark Paluch
 * @since 1.2
 * @see org.springframework.transaction.interceptor.TransactionAttribute
 * @see org.springframework.transaction.interceptor.DefaultTransactionAttribute
 * @see org.springframework.transaction.interceptor.RuleBasedTransactionAttribute
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@Reflective
public @interface Transactional {
	@AliasFor("transactionManager")
	String value() default "";
	/**
	 * @since 4.2
	 */
	@AliasFor("value")
	String transactionManager() default "";
	/**
	 * @since 5.3
	 */
	String[] label() default {};
	Propagation propagation() default Propagation.REQUIRED;
	Isolation isolation() default Isolation.DEFAULT;
	int timeout() default TransactionDefinition.TIMEOUT_DEFAULT;

	/**
	 * @since 5.3
	 */
	String timeoutString() default "";
	boolean readOnly() default false;
	Class<? extends Throwable>[] rollbackFor() default {};
	String[] rollbackForClassName() default {};
	Class<? extends Throwable>[] noRollbackFor() default {};
	String[] noRollbackForClassName() default {};
}
```

从@Transactional注解的源码可以看出，@Transactional是从Spring1.2版本开始提供的注解，可以标注到接口上，类上，也可以标注到方法上。当标注到接口上时，当前接口的所有实现类中，实现了接口的方法都会支持Spring事务。当标注到类上时，当前类的所有方法都支持Spring事务。当标注到方法上时，当前方法支持Spring事务。

**Spring事务的优先级为：标注到方法上的事务优先级 > 标注到类上的事务优先级 > 标注到接口上的事务优先级。**

**注意：Spring中的事务会有失效的场景，在后续的文章中会详细解析Spring事务失效的场景。**

在实际项目开发过程中，通常会标注到方法上。在@Transactional注解中，提供了如下属性。

* value：String类型的属性，用以指定事务管理器的唯一标识
* transactionManager：Spring4.2版本开始新增的String类型的属性，作用同value属性。
* label：Spring5.3版本新增的String数组类型的属性，设置属性的标签。
* propagation：Propagation枚举类型的属性，指定事务的传播行为，具体可以参见第31章的相关内容。
* isolation：Isolation枚举类型的属性，指定事务的隔离级别，具体可以参见第31章的相关内容。
* timeout：指定事务的超时时间，单位为秒，当事务执行时间超过timeout秒时，就会触发超时回滚操作，并释放事务占用的资源。
* timeoutString：Spring5.3版本开始提供的String类型的属性，以String类型设置超时时间，单位为秒。
* readOnly：指定是否为只读事务，true：是只读事务，false：非只读事务。
* rollbackFor：指定异常类的Class对象，当抛出指定类型的异常或者其子类型的异常时，事务会自动回滚。
* rollbackForClassName：指定异常类的全类名，当抛出指定全类名的异常或者其子类型的异常时，事务会自动回滚。
* noRollbackFor：指定异常类的Class对象，当抛出指定类型的异常或者其子类型的异常时，事务不会自动回滚。
* noRollbackForClassName：指定异常类的全类名，当抛出指定全类名的异常或者其子类型的异常时，事务不会自动回滚。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码