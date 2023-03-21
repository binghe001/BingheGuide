---
title: 【付费】第23章：深度解析@EnableAspectJAutoProxy注解
pay: https://articles.zsxq.com/id_khq22od1cfhz.html
---

# 《Spring核心技术》第23章：深度解析@EnableAspectJAutoProxy注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-22](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-22)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：从源码级别彻底掌握@EnableAspectJAutoProxy注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 源码时序图
  * 注册AnnotationAwareAspectJAutoProxyCreator类
  * 解析AnnotationAwareAspectJAutoProxyCreator类
* 源码解析
  * 注册AnnotationAwareAspectJAutoProxyCreator类
  * 解析AnnotationAwareAspectJAutoProxyCreator类
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@EnableAspectJAutoProxy注解，你真的彻底了解过吗？`

@EnableAspectJAutoProxy注解是基于Spring注解开启AOP功能的注解，通常会将它标注到配置类上。那对于@EnableAspectJAutoProxy注解来说，你真的了解过Spring底层执行了哪些操作吗？

**注意：本章会以第22章的案例程序为基础分析@EnableAspectJAutoProxy注解的源码时序图和源码执行流程。**

## 二、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

通过@EnableAspectJAutoProxy注解的源码可以发现，在@EnableAspectJAutoProxy注解的源码上使用@Import注解导入了AspectJAutoProxyRegistrar类。在导入的AspectJAutoProxyRegistrar类后，最核心的逻辑就是解析了AnnotationAwareAspectJAutoProxyCreator类。所以，加载加载@EnableAspectJAutoProxy注解可以分成两部分进行解析，一部分是注册AnnotationAwareAspectJAutoProxyCreator类，一部分是解析AnnotationAwareAspectJAutoProxyCreator类。

本节，就介绍下@EnableAspectJAutoProxy注解在Spring底层的执行时序图。主要从注册AnnotationAwareAspectJAutoProxyCreator类和解析AnnotationAwareAspectJAutoProxyCreator类两个方面进行分析。

### 2.1 注册AnnotationAwareAspectJAutoProxyCreator类

注册AnnotationAwareAspectJAutoProxyCreator类的源码执行流程如图23-1~23-3所示。

![图23-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-19-001.png)



![图23-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-19-002.png)



![图23-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-19-003.png)

由图23-1~23-3可以看出，注册AnnotationAwareAspectJAutoProxyCreator类的源码执行流程会涉及AspectTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、ConfigurationClass类、ConfigurationClassBeanDefinitionReader类、ImportBeanDefinitionRegistrar接口和AspectJAutoProxyRegistrar类，具体的源码执行细节参见源码解析部分。 

### 2.2 解析AnnotationAwareAspectJAutoProxyCreator类

解析AnnotationAwareAspectJAutoProxyCreator类的源码执行流程如图23-4~23-6所示。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
