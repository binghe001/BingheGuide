---
title: 【付费】第30章：深度解析Spring事务三大接口
pay: https://articles.zsxq.com/id_ho2wnitvu0w1.html
---

# 《Spring核心技术》第30章：深度解析Spring事务三大接口

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握Spring事务的三大接口，从源码解析彻底理解Spring事务三大接口的设计和流程。

------

本章目录如下所示：

* 学习指引
* PlatformTransactionManager接口
* TransactionDefinition接口
* TransactionStatus接口
* 总结
* 思考
* VIP服务

## 一、学习指引

`你了解过Spring事务的三大接口吗？`

Spring能够支持事务的管理功能，最核心的就是Spring事务的三大接口，这三大接口分别为：PlatformTransactionManager、TransactionDefinition和TransactionStatus，本章就对这三大接口进行简单的介绍。

## 二、PlatformTransactionManager接口

`分析下PlatformTransactionManager接口~~`

通过Spring的源码，可以得知：Spring并不是直接管理事务的，而是提供了多种事务管理器。通过这些事务管理器，Spring将事务管理的职责委托给了Hibernate、MyBatis或者JTA等持久化框架的事务来实现。

PlatformTransactionManager接口的源码详见：org.springframework.transaction.PlatformTransactionManager。

```java
public interface PlatformTransactionManager extends TransactionManager {
	 /**
	 *获取事务状态
	 */
	 TransactionStatus getTransaction(@Nullable TransactionDefinition definition) throws TransactionException;
	 /**
	 *提交事务
	 */
	 void commit(TransactionStatus status) throws TransactionException;
	 /**
	 *回滚事务
	 */
	 void rollback(TransactionStatus status) throws TransactionException;
}
```

通过PlatformTransactionManager接口，Spring为Hibernate、MyBatis或者JTA等持久化框架提供了事务管理器，但是具体的实现还是要各自的框架自己完成。

## 三、TransactionDefinition接口

`分析下TransactionDefinition接口~~`

TransactionDefinition接口的源码详见：org.springframework.transaction.TransactionDefinition。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码