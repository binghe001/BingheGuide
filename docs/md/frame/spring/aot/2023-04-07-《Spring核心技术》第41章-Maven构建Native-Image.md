---
title: 【付费】第41章：Maven构建Native Image
pay: https://articles.zsxq.com/id_ssa05mm62s0r.html
---

# 《Spring核心技术》第41章：Maven构建Native Image

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-41](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-41)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★☆☆

* **本章重点**：掌握使用Maven构建Native Image的环境搭建过程，掌握将Java代码通过Native Image构建成可执行的二进制文件的方式与过程。

------

本章目录如下所示：

* 学习指引
* 搭建项目环境
* 使用GraalVM SDK构建
  * 配置pom.xml文件
  * 编译项目
  * 测试可执行文件
* 使用GraalVM BuildTools构建
  * 配置pom.xml文件
  * 编译项目
  * 测试可执行文件
* 总结
* VIP服务

## 一、学习指引

`如何通过Maven直接将Java代码构建成二进制文件？`

在上一篇文章中，实现了通过手动的方式将Java代码构建成二进制日志，其中大部分内容都在安装GraalVM环境和C++编译环境。本章，就一起实现通过Maven直接将Java代码构建成二进制文件。

## 二、搭建项目环境

`完成Maven项目的搭建与开发~~`

本节，完成Maven测试项目的搭建与开发，项目开发比较简单，就是新建spring-annotation-chapter-41工程，并新增SpringNativeTest类。

SpringNativeTest类源码详见：spring-annotation-chapter-41工程下的io.binghe.spring.annotation.chapter41.SpringNativeTest。

```java
public class SpringNativeTest {
    public static void main(String[] args) {
        System.out.println("Hello Spring6");
    }
}
```

接下来，就以SpringNativeTest类为例，使用Maven直接构建二进制执行文件。

## 三、使用GraalVM SDK构建

`使用GraalVM SDK直接构建二进制文件~~`

GraalVM基于Maven提供了SDK，可以通过GraalVM SDK直接将Java代码构建成可执行的二进制文件，实现起来也比较简单，就是在Maven项目的pom.xml文件中进行简单的配置。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
