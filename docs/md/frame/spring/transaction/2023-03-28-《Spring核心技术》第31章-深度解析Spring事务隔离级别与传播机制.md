---
title: 【付费】第31章：深度解析Spring事务隔离级别与传播机制
pay: https://articles.zsxq.com/id_ho2wnitvu0w1.html
---

# 《Spring核心技术》第31章：深度解析Spring事务隔离级别与传播机制

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握Spring事务的隔离级别与传播机制，从源码角度彻底理解Spring事务的隔离级别与传播机制。

------

本章目录如下所示：

* 学习指引
* 事务隔离级别
  * ISOLATION_DEFAULT隔离级别
  * ISOLATION_READ_UNCOMMITTED隔离级别
  * ISOLATION_READ_COMMITTED隔离级别
  * ISOLATION_REPEATABLE_READ隔离级别
  * ISOLATION_SERIALIZABLE隔离级别
* 事务传播机制
  * 七种事务传播机制类型
  * REQUIRED事务传播类型
  * REQUIRES_NEW事务传播类型
  * SUPPORTS事务传播类型
  * MANDATORY事务传播类型
  * NOT_SUPPORTED事务传播类型
  * NEVER事务传播类型
  * NESTED事务传播类型
  * 常用的事务传播类型

* 总结
* 思考
* VIP服务

## 一、学习指引

`你了解过Spring事务的隔离级别和传播机制吗？`

关于Spring事务，有两个非常重要的知识点，那就是Spring事务的隔离级别和事务传播机制，本章，就系统介绍下Spring中的事务隔离级别和事务传播机制。

## 二、事务隔离级别

`相信学习过Spring事务的小伙伴都应该了解过Spring的事务隔离级别吧？`

在Spring中，存在着五种隔离级别，分别为ISOLATION_DEFAULT、ISOLATION_READ_UNCOMMITTED、ISOLATION_READ_COMMITTED、ISOLATION_REPEATABLE_READ、ISOLATION_SERIALIZABLE。

接下来，就简单介绍下这些Spring的事务隔离级别。

### 2.1 ISOLATION_DEFAULT隔离级别

ISOLATION_DEFAULT隔离级别是Spring中PlatformTransactionManager默认的事务隔离级别，如果将Spring的事务隔离级别设置为ISOLATION_DEFAULT，则会使用数据库默认的事务隔离级别。

也就是说，将Spring的事务隔离级别设置为ISOLATION_DEFAULT时，Spring不做事务隔离级别的处理，会直接使用数据库默认的事务隔离级别。

### 2.2 ISOLATION_READ_UNCOMMITTED隔离级别

ISOLATION_READ_UNCOMMITTED隔离级别是Spring中最低级别的隔离级别。当Spring中的隔离级别设置为ISOLATION_READ_UNCOMMITTED时，一个事务A能够读取到另一个事务B未提交的数据。这种隔离级别下会产生脏读、不可重复读和幻读的问题。相当于MySQL中的READ UNCOMMITTED隔离级别。

### 2.3 ISOLATION_READ_COMMITTED隔离级别

ISOLATION_READ_COMMITTED隔离级别能够保证一个事务A修改的数据提交之后才能被另一个事务B读取，另一个事务B不能读取事务A未提交的事务。在这种隔离级别下，解决了脏读问题，但是可能会出现不可重复读和幻读的问题。相当于MySQL中的READ COMMITTED隔离级别。

### 2.4 ISOLATION_REPEATABLE_READ隔离级别

ISOLATION_REPEATABLE_READ隔离级别能够保证不会出现脏读和不可重复读的问题，但是可能会出现幻读的问题。如果一个事务A第一次按照一定的查询条件从数据表中查询出数据后，另一个事务B向同一个数据表中插入了符合事务A的查询条件的数据，事务A再次从数据表中查询数据时，会将事务B新插入的数据查询出来。相当于MySQL中的REPEATABLE READ隔离级别。

### 2.5 ISOLATION_SERIALIZABLE隔离级别

ISOLATION_SERIALIZABLE隔离级别下，事务只能够按照特定的顺序执行，也就是多个事务之间只能够按照串行化的顺序执行。这是一种最可靠的隔离级别，但是这种可靠性付出了极大的代价，那就是牺牲了并发性。相当于MySQL中的SERIALIZABLE隔离级别。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
