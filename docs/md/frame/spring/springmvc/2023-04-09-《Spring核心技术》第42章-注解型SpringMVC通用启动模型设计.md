---
title: 【付费】第42章：注解型SpringMVC通用SpringBoot启动模型设计与实现
pay: https://articles.zsxq.com/id_rt2w9t6inv5j.html
---

# 《Spring核心技术》第42章：注解型SpringMVC通用SpringBoot启动模型设计与实现

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-42](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-42)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：掌握基于全注解开发SpringMVC的方法，掌握使用嵌入式Tomcat启动SpringMVC的方法（摒弃web.xml），对比思考SpringBoot。

------

本章目录如下所示：

* 学习指引
* 模型设计
  * Tomcat SPI 接口
  * Tomcat SPI 实现类
  * Tomcat SPI 扩展设计
* 模型实现
* 案例实现
* 案例测试
* 总结
* 思考
* VIP服务

## 一、学习指引

`你还在写大量配置文件来开发SpringMVC程序？`

很早前，冰河就说过，SpringBoot其实底层就是基于Spring和SpringMVC的一个快速开发脚手架，SpringBoot能做到的，使用Spring和SpringMVC一样能做到，SpringBoot其实并没有什么神秘的地方，学好Spring和SpringMVC，那SpringBoot根本就不用花费大量的时间和精力去学习，只要稍加理解就可以了。

为了让大家更好的体会如何利用Spring和SpringMVC按照SpringBoot的方式开发Web应用程序，本章，我们一起使用Spring+SpringMVC+嵌入式Tomcat开发一个简易版的SpringBoot应用。让你从根本上理解SpringBoot到底是如何运行的。还有一点需要说明的是：SpringBoot启动时，底层使用的是自动配置导入相关的类和资源，这个在《RPC手撸专栏》的整合SpringBoot篇章有实现。这里，为了简化实现逻辑，也为了更好的演示最核心的部分，省略了大量的自动配置，通过嵌入式Tomcat直接启动程序。

## 二、模型设计

`基于SpringMVC实现SpringBoot方式启动程序案例模型设计~~`

熟悉Tomcat的小伙伴都知道，Tomcat提供了一种SPI机制来加载配置类启动Spring IOC容器。所以，本章在实现注解型SpringMVC通用SpringBoot启动模型时，会基于Tomcat的SPI机制进行实现。

### 2.1 Tomcat SPI 接口

在Tomcat提供的SPI机制中，会对外暴露一个ServletContainerInitializer接口，ServletContainerInitializer接口的源码详见：jakarta.servlet.ServletContainerInitializer。

```java
public interface ServletContainerInitializer {
    void onStartup(Set<Class<?>> c, ServletContext ctx) throws ServletException;
}
```

可以看到，在ServletContainerInitializer接口中只提供了一个onStartup()方法，在Tomcat启动的过程中就会调用这个onStartup()方法。

在Tomcat启动的过程中，就会去加载ServletContainerInitializer接口的所有实现类，并且还会去解析@HandlersTypes注解，将解析到的结果信息封装到一个Set<Class<?>>集合中。

### 2.2 Tomcat SPI 实现类

在spring-web模块会实现ServletContainerInitializer接口，如图42-1所示。

![图42-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-04-09-001.png)

由图42-1可以看出，在spring-web模块中就实现了ServletContainerInitializer接口，打开jakarta.servlet.ServletContainerInitializer文件，内容如下所示。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码