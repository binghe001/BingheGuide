---
title: 【付费】第36章：深度解析@TransactionEventListener注解
pay: https://articles.zsxq.com/id_6mqzv4xx6n58.html
---

# 《Spring核心技术》第36章：深度解析@TransactionEventListener注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-36](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-36)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：掌握@TransactionEventListener注解的案例和使用场景，从源码级别彻底掌握Spring底层解析@TransactionEventListener注解属性的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 事务提交流程
  * 事务回滚流程
* 源码解析
  * 事务提交流程
  * 事务回滚流程
* 总结
* 思考
* VIP服务

## 一、学习指引

`你了解过@TransactionEventListener注解吗？`

相信熟悉Spring事务的小伙伴对@EnableTransactionManagement注解和@Transactional注解都比较熟悉了，这两个注解也是基于Spring注解开发应用程序时，使用最多的两个事务注解。在Spring的事务中除了这两个注解外，还有一个@TransactionalEventListener注解，本章，简单介绍下@TransactionalEventListener注解。

## 二、注解说明

`关于@TransactionEventListener注解的一点点说明~~`

如果在程序里需要获取Spring事务的信息，在事务提交和回滚前后做一些处理，就可以使用@TransactionalEventListener注解实现。

### 2.1 注解源码

 @TransactionalEventListener注解的源码详见：org.springframework.transaction.event.TransactionalEventListener。

```java
/**
 * @author Stephane Nicoll
 * @author Sam Brannen
 * @author Oliver Drotbohm
 * @since 4.2
 * @see TransactionalApplicationListener
 * @see TransactionalApplicationListenerMethodAdapter
 */
@Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EventListener
public @interface TransactionalEventListener {
    
	TransactionPhase phase() default TransactionPhase.AFTER_COMMIT;
    
	boolean fallbackExecution() default false;
    
	@AliasFor(annotation = EventListener.class, attribute = "classes")
	Class<?>[] value() default {};
    
	@AliasFor(annotation = EventListener.class, attribute = "classes")
	Class<?>[] classes() default {};
    
	@AliasFor(annotation = EventListener.class, attribute = "condition")
	String condition() default "";
	/**
	 * @since 5.3
	 */
	@AliasFor(annotation = EventListener.class, attribute = "id")
	String id() default "";
}
```

从源码可以看出，@TransactionalEventListener注解是从Spring4.2版本开始提供的注解，并且在@TransactionalEventListener注解上标注了@EventListener注解，说明@TransactionalEventListener注解是一个事件监听器注解。能够监听事务的执行过程，并且可以在事务提交前后和事务回滚前后执行一些额外的功能。

在@TransactionalEventListener注解中提供了如下属性。

* phase：TransactionPhase枚举类型的属性，表示事务监听器的执行时机，主要有如下取值：
  * BEFORE_COMMIT：事务提交之前。
  * AFTER_COMMIT：事务提交之后，默认值。
  * AFTER_ROLLBACK：事务回滚之后。
  * AFTER_COMPLETION：事务完成之后。
* fallbackExecution：boolean类型，表示如果没有事务，对应的event事件是否已经执行，默认为false，表示没有事务就不执行。
* value：Class数组类型，表示事件类的Class对象，可以指定多个事件类的Class对象。
* classes：Class数组类型，作用同value。
* condition：String类型，指定执行事件处理器的条件。取值是通过Spring的el表达式编写的。

### 2.2 使用场景


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码



