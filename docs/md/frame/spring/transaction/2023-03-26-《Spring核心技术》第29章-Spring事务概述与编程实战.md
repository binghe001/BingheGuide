---
title: 【付费】第29章：Spring事务概述与编程实战
pay: https://articles.zsxq.com/id_kq76kv1nwzoe.html
---

# 《Spring核心技术》第29章：Spring事务概述与编程实战

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-29)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★☆☆

* **本章重点**：进一步学习并掌握使用Spring实现事务编程的案例和流程。

------

本章目录如下所示：

* 学习指引
* Spring事务介绍
  * Spring事务概述
  * Spring事务分类
  * Spring事务超时
  * Spring事务回滚规则
* 使用案例
  * 案例程序开发
  * 无事务正常测试
  * 无事务异常测试
  * 有事务正常测试
  * 有事务异常测试
* 总结
* 思考
* VIP服务

## 一、学习指引

`相信很多小伙伴都使用过Spring中的事务进行项目开发吧？`

使用JDBC驱动也能够控制数据库中的事务，不过直接使用JDBC进行事务开发，就显得比较繁琐了。它需要如下几个步骤。

**（1）加载JDBC驱动**

```java
Class.forName("com.mysql.jdbc.Driver");
```

**（2）建立与数据库的连接，后两个参数分别为账号和密码**

```java
Connection conn = DriverManager.getConnection(url, "root", "root");
```

**（3）开启事务**

```java
conn.setAutoCommit(true/false);
```

**（4）执行数据库的CRUD操作**

```java
PreparedStatement ps = con.prepareStatement(sql); 
//新增、修改、删除
ps.executeUpdate();
//查询
ps.executeQuery()
```

**（5）提交或者回滚事务**

```java
//提交事务
conn.commit();
//回滚事务
conn.rollback();
```

**(6）关闭连接**

```java
ps.close();
conn.close();
```

如果在实际项目中，直接使用JDBC进行事务开发，则会将大量的精力放到事务本身的处理上，比如开启事务、提交事务和回滚事务上，并且需要手动编写大量的异常判断逻辑来实现事务的回滚功能，这无疑是大大加重了程序员的负担，好在Spring封装了开启事务、提交事务和回滚事务的功能，能够大大简化实际项目中对于事务编程的复杂度。

## 二、Spring事务介绍

`简单聊点Spring事务的基础知识~~`

使用Spring进行事务编程时，最核心的就是一个注解就能搞定开启事务、提交事务和回滚事务的功能，并且对原有逻辑代码零侵入，这简直是太简单，太方便了。

### 2.1 Spring事务概述

如果使用Spring的事务功能，则不必手动开启事务、提交事务和回滚事务，也就是不用再写使用JDBC进行事务编程时第3步和第5步中的代码。而开启事务、提交事务和回滚事务的操作全部交由Spring框架自动完成，那Spring是如何自动开启事务、提交事务和回滚事务的呢？

简单的说，就是在配置文件中或者项目的启动类上配置Spring事务相关的注解驱动，在相关的类或者方法上标识@Transactional注解，即可开启并且使用Spring的事务管理功能。

Spring框架在启动的时候会创建相关的bean实例对象，并且会扫描标注有相关注解的类和方法，为这些方法生成代理对象。如果扫描到标注有@Transactional注解的类或者方法时，则会根据@Transactional注解的相关参数进行配置注入，在代理对象中就会处理相应的事务，对事务进行管理，例如，在代理对象中开启事务、提交事务和回滚事务。而这些操作都是Spring框架通过AOP代理自动完成的，无须开发人员过多的关心其中的细节问题。

例如，如下方法就使用了Spring的@Transactional注解管理事务。

```java
@Transactional(rollbackFor=Exception)
Public void saveUser(User user){
	//省略保存用户的代码
}
```
## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码