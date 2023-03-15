---
layout: post
category: binghe-code-spring
title: 第00章：开篇：我要带你一步步调试Spring6.0源码啦！
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第00章：开篇：我要带你一步步调试Spring6.0源码啦！
lock: need
---

# 《Spring核心技术》第00章：开篇：我要带你一步步调试Spring6.0源码啦！

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客1：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>博客2：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

提起Spring，可以这么说，Spring几乎是Java Web领域中必不可少的基础性开发框架，Spring中提供的IOC、DI、AOP以及声明式事务等技术极大的简化了开发人员的工作量。试问：在Java Web开发领域，有谁不知道Spring？又有多少人没有使用过Spring呢？如果你还没有使用过Spring，可以这么说，你就不是一个真正的Java Web开发人员，或者你还没有真正步入Java Web开发领域。

好了，闲话不多说了，我们开始今天的正文。

## 为何要写《Spring核心技术》

万事皆有因，先跟小伙伴们简单聊聊冰河为何要写《Spring核心技术》这个专栏。

其实，说起Spring，市面上有非常多的书籍，还有专栏和博客来系统的介绍Spring，有些是讲解如何使用Spring，也就是基于Spring开发项目，有些是专注讲解Spring源码。但是，冰河系统性的梳理了这些内容，发现很多书籍、专栏和博客，讲的挺多，也挺深入。但是总体看下来，发现多少会有一种云里雾里的感觉。

![spring-core-2022-12-02-001](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-02-001.jpg)

比如，看完如何使用Spring的书籍、专栏和文章，对Spring的底层原理和源码不太了解。看完专注讲解Spring底层原理和源码解析的书籍、专栏和文章吧，又是一脸懵逼，很多时候不知道这些源码是从哪个入口进来的，也不知道是触发了项目中使用的哪个注解，从而进入了书籍、专栏和文章中剖析的源码部分，反正就是一脸懵啊！

加上Spring迭代开发了很长时间，Spring本身的源码就东一坨西一坨的，并且条件分支代码很多，各种封装逻辑，很容易把人搞晕，看完后更懵逼了。

![spring-core-2022-12-02-002](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-02-002.jpg)

当然，Github上有很多牛人写的简易版的Spring，虽然实现了一些Spring的小功能，但是这毕竟不是Spring框架本身啊，谁项目里会用个简易版的Spring呢？我相信不是大部分人不会用，而是百分之百的人不会用。

![spring-core-2022-12-02-003](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-02-003.png)

所以，我们还是要把Spring本身学透才行。

为了让小伙伴们更轻松、更加清晰明了的学习Spring，也为了让小伙伴们对如何学习Spring有一个全新的认识（哇，学习Spring原理这么轻松？），也能够对Spring和SpringBoot做到融会贯通，冰河决定开始更新《Spring核心技术》专栏。

## 专栏的特点

《Spring核心技术》 专栏不是只讲案例的专栏，也不是一上来就陷入源码出不来那种，只讲Spring最核心的知识和技术：**整体专栏以最新的 Spring6 为基础，以Spring中的核心注解为入口，给出实用案例，通过对应注解在Spring源码层面执行的时序图，引导小伙伴们有针对性的去看源码，去分析源码，最后总结和思考，形成总体上的闭环。** 这样，小伙伴们在学完Spring的某项知识点时，印象才会更加深刻。

总之，我们的目标都是一样的：就是吃透Spring的核心技术。

![spring-core-2022-12-02-004](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-02-004.jpg)



**那么问题来了：**

**为何以Spring6作为基础呢？**

因为Spring官方发布了6.0，我们就以最新的版本为基础，不搞虚的，搞就搞最新版，就是这么任性。

**那为何又要以Spring中的核心注解为入口呢？**

试问现在谁使用Spring还去使用Spring的XML文件去配置Bean对象呢？即使有，也是非常老旧的项目在用吧。除了Spring，我们日常开发微服务程序使用的SpringBoot，不也是基于注解进行开发吗？XML那一套早就过时了。

以Spring中的核心注解为入口，另一个重要的原因就是，让小伙伴们有针对性的吃透Spring中最核心的技术，在学习Spring的道路上少走弯路。而且开发微服务应用使用最频繁的SpringBoot技术，本质上也是基于Spring进行封装实现的，而且在使用SpringBoot开发应用的过程中，会大量使用到Spring中的核心注解。吃透Spring中的核心注解，能够让小伙伴们将Spring和SpringBoot达到融会贯通。

很多小伙伴学完Spring还要去单独学习SpringBoot，其实，冰河告诉你的是：彻底吃透Spring，不是吃透网上或GitHub上那些个人写的简易版Spring，吃透那些没用，而是要吃透Spring本身，你其实不用花大量时间再去学习SpringBoot，SpringBoot只是在Spring的基础上做了一点点的封装，仅此而已。你只需要花少量的时间理解SpringBoot在Spring基础上的封装逻辑，那么，关于SpringBoot，你也就彻底掌握了。

## 专栏总体规划

我们先来看下宏观层面对于专栏的总体规划。《Spring核心技术》专栏整体以最新版本的 **Spring6** 为基础，以 **核心注解** 为入口，结合使用案例为小伙伴们彻底梳理清楚Spring的核心源码执行流程。总体上会分为IOC容器、AOP切面、声明式事务和SpringMVC四个大的篇章，各篇章会分为若干个章节来彻底梳理清楚对应的核心注解源码和流程。

![Spring核心技术](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-02-006.png)

总之，学就要有针对性的去学，学就要学Spring最核心的技术，学就要高效率的去学，学就要融会贯通！

## 章节布局

聊完宏观的总体规划，我们再来谈谈微观层面对每个章节具体内容的布局。其实，关于每个章节的布局，前面多少已经提到过了，就是 **以最新的Spring6为基础，以Spring中的核心注解为入口，给出实用案例，通过对应注解在Spring源码层面执行的时序图，引导小伙伴有针对性的去看源码，去分析源码，最后总结和思考，形成总体上的闭环。**

![spring-core-2022-12-02-005](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-02-005.png)

整个章节的布局旨在让小伙伴们彻底理解并吃透Spring中核心的技术点，不是为了面试，也不是为了简单的看看Spring，而是为了彻底吃透Spring核心技术，终极目标就是升职加薪！

## 总结

《Spring核心技术》专栏是一个对最新版 **Spring6**，以核心注解和使用案例为入口，彻底解剖Spring核心原理和源码运行流程的专栏，希望小伙伴们能够跟上节奏，跟着冰河彻底吃透Spring核心技术。

最后，我想说的是：学习《Spring核心技术》专栏一定要塌下心来，一步一个脚印，动手实践，认真思考，遇到不懂的问题，可以直接到**冰河技术** 知识星球发布主题进行提问，也可以在冰河的微信群里提问，还可以私信冰河微信。一定要记住：纸上得来终觉浅，绝知此事要躬行的道理。否则，一味的CP（Copy），或者光看不练，不仅失去了学习的意义，到头来更是一无所获。

接下来，就让我们一起开启《Spring核心技术》之旅吧！

## 八、VIP服务

**强烈推荐阅读：《[原来大厂面试官也会在这里偷偷学习！](https://mp.weixin.qq.com/s/Zp0nI2RyFb_UCYpSsUt2OQ)》，如果文中优惠券过期，可长按或扫码下面优惠券二维码加入星球。**

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-18-008.png?raw=true" width="70%">
    <div style="font-size: 18px;">星球优惠券</div>
    <br/>
</div>

**冰河技术** 知识星球 **《SpringCloud Alibaba实战》** 从零搭建并开发微服务项目已完结；**《RPC手撸专栏》** 已经更新120+篇文章，已提交120+项目工程，120+项目源码Tag分支；**《Spring核心技术》** 专栏以Spring的核心注解为突破口，通过源码执行的时序图带你详细分析Spring底层源码，让你学习Spring底层源码不再枯燥。并这些专栏已经将源码的获取方式放到了知识星球中，同时在微信上创建了专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

目前，星球群已形成良好的技术讨论氛围，后续也会像PRC项目一样全程手撸企业级中间件项目，**涉及分布式、高并发、高性能、高可靠、高可扩展，让大家知其然，更知其所以然，从手写企业级中间件项目的过程中，充分掌握分布式、高并发、高性能、高可靠、高可扩展的编程技巧。**

**更加值得一提的是：有超过30+的大厂面试官悄悄在这里提升核心竞争力！**

### 星球提供的服务

冰河整理了星球提供的一些服务，如下所示。

加入星球，你将获得：

1.学习从零开始手撸可用于实际场景的高性能、可扩展的RPC框架项目

2.学习SpringCloud Alibaba实战项目—从零开发微服务项目

3.学习高并发、大流量业务场景的解决方案，体验大厂真正的高并发、大流量的业务场景

4.学习进大厂必备技能：性能调优、并发编程、分布式、微服务、框架源码、中间件开发、项目实战

5.提供站点 https://binghe.gitcode.host 所有学习内容的指导、帮助

6.GitHub：https://github.com/binghe001/BingheGuide - 非常有价值的技术资料仓库，包括冰河所有的博客开放案例代码

7.提供技术问题、系统架构、学习成长、晋升答辩等各项内容的回答

8.定期的整理和分享出各类专属星球的技术小册、电子书、编程视频、PDF文件

9.定期组织技术直播分享，传道、授业、解惑，指导阶段瓶颈突破技巧

### 如何加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

**好了，今天就到这儿吧，我是冰河，我们下期见~~**



## 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`学习加群`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>





## 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>




## 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>





## 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>
