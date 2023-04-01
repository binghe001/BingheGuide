---
title: 【付费】第40章：手动构建Native Image
pay: https://articles.zsxq.com/id_rh08wot03ls8.html
---

# 《Spring核心技术》第40章：手动构建Native Image

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-40](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-40)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★☆☆

* **本章重点**：掌握构建Native Image的环境搭建过程，掌握将Java代码通过Native Image构建成可执行的二进制文件的方式与过程。

------

本章目录如下所示：

* 学习指引
* 安装GraalVM环境
  * 下载GraalVM
  * 配置环境变量
  * 安装native-image插件
* 安装C++编译环境
  * 下载Visual Studio
  * 安装Visual Studio
  * 配置环境变量
* 构建Native Image
  * 编写Java代码
  * 构建Native Image
* 总结
* VIP服务

## 一、学习指引

`一起将Java代码构建成本地可执行文件吧！`

学过Java的小伙伴都知道，运行Java程序前，我们写的Java代码会由Java编译器编译成字节码，运行在JVM中，由JVM将其翻译成机器码。整个过程是需要JVM参与的，也就是说，Java程序是需要运行在JVM之上的。

GraalVM提供了预编译技术，能够提前将Java代码直接编译成本机可执行的二进制文件，也就是使得Java程序在运行时能够摒弃JVM，和C/C++一样通过编译器直接将代码编译成机器代码，然直接后运行。

## 二、安装GraalVM环境

`一起安装GraalVM环境吧~~`

本节，一起安装GraalVM环境，用于后续将Java代码编译成二进制文件。

### 2.1 下载GraalVM

**（1）打开链接下载**

打开链接：[https://www.graalvm.org/downloads/](https://www.graalvm.org/downloads/)下载GraalVM，如图40-1所示。

![图40-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-04-06-001.png)

可以看到，这里下载的GraalVM是22.3社区版，点击“Download”。

**（2）选择版本**

选择Java版本和操作系统类型，这里是使用的JDK版本是17，操作系统是64位Windows，所以，选择的Java版本是17，操作系统是Windows(amd64)，如图40-2所示。

![图40-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-04-06-002.png)

### 2.2 配置环境变量

下载完成后解压，并配置系统环境变量。

**注意：本节假设你已经配置过Java环境，即配置过JAVA_HOME、CLASS_PATH和PATH环境变量。**

**（1）添加GRAALVM_HOME环境变量**

![图40-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-04-06-003.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码