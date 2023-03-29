---
title: 【付费】第35章：深度解析Spring底层事务传播机制源码
pay: https://articles.zsxq.com/id_6sw4tcdnl0qf.html
---

# 《Spring核心技术》第35章：深度解析Spring底层事务传播机制源码

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：从源码级别彻底掌握Spring中的七种事务传播机制。

------

本章目录如下所示：

* 学习指引
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring事务用了那么久，你了解过Spring事务传播机制对应的源码吗？`

通过对Spring声明式事务篇章的学习，已经知道Spring中提供了七种事务的传播机制，那Spring在源码层面是如何处理这七种传播机制的呢？今天，就一起简单聊聊Spring事务传播机制对应的源码。

## 二、源码解析

`一起来看看Spring七种事务传播类型对应的源码吧！`

Spring中提供了七种事务传播类型，来支持Spring的事务传播机制，本节，就简单聊聊Spring中七种事务传播类型和其对应的源码。

### 2.1 REQUIRED事务传播类型

**1.类型描述**

REQUIRED事务传播类型表示如果当前没有事务，就新创建一个事务；如果已经存在一个事务，就加入这个事务，这是最常见的事务传播类型，也是Spring当中默认的事务传播类型。

**这里，需要重点注意的是：外部不存在事务时，开启新的事务；外部存在事务时，加入到外部事务中。并且如果调用端发生异常，则调用端和被调用端的事务都将会回滚。在这种事务传播类型下，当前操作必须在一个事务中执行。**

REQUIRED事务传播类型在Propagation枚举类中的源码如下所示。

```java
REQUIRED(TransactionDefinition.PROPAGATION_REQUIRED)
```

基本用法如下代码片段所示。

```java
@Transactional(propagation=Propagation.REQUIRED)
```

**2.对应源码**

（1）如果当前没有事务，就新创建一个事务

源码详见：org.springframework.transaction.support.AbstractPlatformTransactionManager#getTransaction(@Nullable TransactionDefinition definition)。

```java
else if (def.getPropagationBehavior() == TransactionDefinition.PROPAGATION_REQUIRED ||
         def.getPropagationBehavior() == TransactionDefinition.PROPAGATION_REQUIRES_NEW ||
         def.getPropagationBehavior() == TransactionDefinition.PROPAGATION_NESTED) {
    SuspendedResourcesHolder suspendedResources = suspend(null);
    if (debugEnabled) {
        logger.debug("Creating new transaction with name [" + def.getName() + "]: " + def);
    }
    try {
        return startTransaction(def, transaction, debugEnabled, suspendedResources);
    }
    catch (RuntimeException | Error ex) {
        resume(null, suspendedResources);
        throw ex;
    }
}
```

startTransaction()方法源码详见：org.springframework.transaction.support.AbstractPlatformTransactionManager#startTransaction(TransactionDefinition definition, Object transaction, boolean debugEnabled, @Nullable SuspendedResourcesHolder suspendedResources)。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
