---
title: 【付费】第37章：七大场景深度分析Spring事务嵌套最佳实践
pay: https://articles.zsxq.com/id_je5i1cblcqkn.html
---

# 《Spring核心技术》第37章：七大场景深度分析Spring事务嵌套最佳实践

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-37](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-37)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：从根本上彻底理解Spring嵌套事务的最佳实践方式与最佳案例。

------

本章目录如下所示：

* 学习指引
* 最佳实践
  * 准备工作
  * 最佳实践场景一
  * 最佳实践场景二
  * 最佳实践场景三
  * 最佳实践场景四
  * 最佳实践场景五
  * 最佳实践场景六
  * 最佳实践场景七
* 总结
* 思考
* VIP服务

## 一、学习指引

`你了解过Spring嵌套事务的最佳实践吗？`

在基于Spring开发应用程序时，涉及到事务操作时，最常使用的就是在方法上标注@Transactional注解。但是，有时由于项目逻辑比较复杂，调用的方法比较多，可能就会出现外层方法标注了@Transactional注解，而内层方法也会标注@Transactional注解的现象，造成事务的嵌套，如果对Spring事务的传播机制不太了解的话，可能就会造成实际的结果数据和预期的结果数据不一致。

本章，就以案例的形式专门聊聊Spring嵌套事务的最佳实践。

## 二、最佳实践

`以案例的形式来说明Spring事务嵌套的最佳实践！`

本章的案例程序以大家最熟悉的下单减库存为例来说明Spring嵌套事务的最佳实践案例。

### 2.1 准备工作

这里以典型的电商场景为例。电商场景中，一个典型的操作就是下单减库存。本节就以下单减库存的场景为例，介绍Spring嵌套事务的最佳实践，并且说明Spring事务传播机制的设计精髓。

（1）创建Maven项目spring-annotation-chapter-37，并在pom.xml文件中添加Maven依赖。

```xml
<dependencies>
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <version>${jdbc.version}</version>
    </dependency>

    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-jdbc</artifactId>
        <version>${spring.version}</version>
    </dependency>

    <dependency>
        <groupId>org.mybatis</groupId>
        <artifactId>mybatis</artifactId>
        <version>${mybatis.version}</version>
    </dependency>

    <dependency>
        <groupId>org.mybatis</groupId>
        <artifactId>mybatis-spring</artifactId>
        <version>${mybatis.spring.version}</version>
    </dependency>

    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>druid</artifactId>
        <version>${druid.version}</version>
    </dependency>

</dependencies>
```

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
