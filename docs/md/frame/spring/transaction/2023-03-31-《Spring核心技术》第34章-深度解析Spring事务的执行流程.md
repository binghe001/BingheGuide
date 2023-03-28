---
title: 【付费】第34章：深度解析Spring事务的执行流程
pay: https://articles.zsxq.com/id_8q0nz7rucvjd.html
---

# 《Spring核心技术》第34章：深度解析Spring事务的执行流程

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：从源码级别彻底掌握Spring底层执行事务的流程。

------

本章目录如下所示：

* 学习指引
* 源码时序图
  * 事务整体流程
  * 创建事务流程
  * 调用目标方法流程
  * 提交事务流程
  * 回滚事务流程
* 源码解析
  * 事务整体流程
  * 创建事务流程
  * 调用目标方法流程
  * 提交事务流程
  * 回滚事务流程
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring事务用了那么久，你知道事务的执行流程吗？`

在声明式事务篇章前面的文章中，系统介绍了Spring事务的概述信息，并提供了案例实战程序，深度解析了Spring事务的隔离级别和传播机制，深度解析了深度解析@EnableTransactionManagement注解在Spring底层的执行流程，也详细分析了Spring底层解析@Transactional注解的流程。本章，就系统介绍下Spring事务的执行流程。

## 二、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

结合源码时序图理解Spring底层的源码执行流程，会理解的更加深刻。本节就以源码时序图的方式，直观的感受下Spring事务在源码层面的执行流程。本节，主要从事务的整体流程、创建事务的流程、提交事务的流程和回滚事务的流程几个方面介绍Spring事务在源码层面的执行流程。

**注意：本节的源码时序图以第29章中的案例程序为基础进行分析。**

### 2.1 事务整体流程

Spring底层执行事务整体流程的源码时序图如图34-1~34-2所示。

![图34-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-31-001.png)


## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码


