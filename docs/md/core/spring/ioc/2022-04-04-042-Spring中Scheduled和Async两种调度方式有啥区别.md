---
layout: post
category: binghe-spring-ioc
title: 第41章：Spring中Scheduled和Async两种调度方式
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 最近有小伙伴出去面试，回来跟我说：冰河，我去XXX公司面试，面试官竟然问了我一个关于Spring中Scheduled和Async调度的问题，我竟然没回答上来，你能不能写一篇关于这个问题的文章呢？我：可以，安排上！于是便有了这篇文章。
lock: need
---

# 《Spring注解驱动开发》第41章：Spring中Scheduled和Async两种调度方式

**大家好，我是冰河~~**

最近有小伙伴出去面试，回来跟我说：冰河，我去XXX公司面试，面试官竟然问了我一个关于Spring中Scheduled和Async调度的问题，我竟然没回答上来，你能不能写一篇关于这个问题的文章呢？我：可以，安排上！于是便有了这篇文章。

**好了，我们开始正文吧~~**

## Spring调度的两种方式

Spring提供了两种后台任务的方法,分别是:

* 调度任务，@Schedule
* 异步任务，@Async

当然，使用这两个是有条件的，需要在spring应用的上下文中声明`<task:annotation-driven/>`当然，如果我们是基于java配置的，需要在配置类上加`@EnableScheduling`和`@EnableAsync `注解，例如，下面的代码片段。

```java
@EnableScheduling
@EnableAsync
public class WebAppConfig {
   ....
｝
```

除此之外，还是有第三方库可以调用的，例如Quartz，文章最后我们再简单提下Quartz。

## @Schedule调度

先看下@Schedule怎么调用再说。

```java
public final static long ONE_DAY = 24 * 60 * 60 * 1000;
public final static long ONE_HOUR = 60 * 60 * 1000;
 
@Scheduled(fixedRate = ONE_DAY)
public void scheduledTask() {
   System.out.println(" 我是一个每隔一天就会执行一次的调度任务");
}
 
@Scheduled(fixedDelay = ONE_HOURS)
public void scheduleTask2() {
    System.out.println(" 我是一个执行完后，隔一小时就会执行的任务");
}
 
@Scheduled(initialDelay=1000, fixedRate=5000)
public void doSomething() {
    // something that should execute periodically
}
 
@Scheduled(cron = "0 0/1 * * * ? ")
public void ScheduledTask3() {
    System.out.println(" 我是一个每隔一分钟就就会执行的任务");
}
```

**需要注意的是：**

* 关于`@Scheduled`注解，里面使用的是Cron表达式，同时我们看到了两个不一样的面孔fixedDelay&  fixedRate，前者fixedDelay表示在指定间隔运行程序，例如这个程序在今晚九点运行程序，跑完这个方法后的一个小时，就会再执行一次，而后者fixedDelay者是指，这个函数每隔一段时间就会被调用（我们这里设置的是一天），不管再次调度的时候，这个方法是在运行还是结束了。而前者就要求是函数运行结束后开始计时的，这就是两者区别。

* 这个还有一个initialDelay的参数，是第一次调用前需要等待的时间，这里表示被调用后的，推迟一秒再执行，这适合一些特殊的情况。

*  我们在serviceImpl类写这些调度任务时候，也需要在ServiceInterface的借口中写多个接口，不然会抛出`but not found in any interface(s) for bean JDK proxy.Either pull the  method up to an interface or` 的异常。

## @Async调度

有时候我们会调用一些特殊的任务，任务会比较耗时，重要的是，我们不管他返回的后果。这时候我们就需要用这类的异步任务啦，调用后就让它去跑，不堵塞主线程，我们继续干别的。代码像下面这样:

```java
public void AsyncTask(){
    @Async
    public void doSomeHeavyBackgroundTask(int sleepTime) {
        try {
            Thread.sleep(sleepTime);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
    @Async
    public Future<String> doSomeHeavyBackgroundTask() {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }
     
    public void printLog() {
         System.out.println(" i print a log ,time=" + System.currentTimeMillis());
    }
 
}
```

我们写个简单的测试类来测试下

```java
@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = AsycnTaskConfig.class) //要声明@EnableASync
public class AsyncTaskTest {
    @Autowired
    AsyncTask asyncTask;
    @Test
    public void AsyncTaskTest() throws InterruptedException {
        if (asyncTask != null) {
            asyncTask.doSomeHeavyBackgroundTask(4000);
            asyncTask.printLog();
            Thread.sleep(5000);
        }
    }
}
```

这感觉比我们手动开线程方便多了，不想异步的话直接把@Async去掉就可以了，另外如果想要返回结果，需要使用Future<>接口。如果想修改Spring Boot的默认线程池配置，可以实现AsyncConfigurer。

**需要注意的是：**

* 相对于@scheduled，这个可以有参数和返回个结果，因为这个是我们调用的，而调度的任务是spring调用的。
* 异步方法不能内部调用，只能像上面那样，外部调用，否则就会变成阻塞主线程的同步任务啦！这里，给大家展示一个活生生的大坑！例如下面的代码案例。

```java
public void AsyncTask(){
    public void fakeAsyncTaskTest(){
        doSomeHeavyBackgroundTask(4000);
        printLog();
        //你会发现，当你像这样内部调用的时候，居然是同步执行的，不是异步的！！
    }
     
    @Async
    public void doSomeHeavyBackgroundTask(int sleepTime) {
        try {
            Thread.sleep(sleepTime);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
     
    public void printLog() {
        System.out.println(" i print a log ");
    }
}
```

另外一点就是不要重复的扫描，这也会导致异步无效，具体的可以看这个stackoveflow的[spring-async-not-working](http://stackoverflow.com/questions/6610563/spring-async-not-working) Issue。

关于异常处理，难免在这个异步执行过程中有异常发生，对于这个问题，Spring提供的解决方案如下,实现 `AsyncUncaughtExceptionHandler`接口。

```java
public class MyAsyncUncaughtExceptionHandler implements AsyncUncaughtExceptionHandler {
    @Override
    public void handleUncaughtException(Throwable ex, Method method, Object... params) {
        // handle exception
    }
}
```

写好我们的异常处理后，我们需要配置一下，告诉Spring，这个异常处理就是我们在运行异步任务时候，抛出错误时的异常终结者。

```java
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {
    @Bean
    public AsyncTask asyncBean() {
        return new AsyncTask();
    }
     
    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(7);
        executor.setMaxPoolSize(42);
        executor.setQueueCapacity(11);
        executor.setThreadNamePrefix("MyExecutor-");
        executor.initialize();
        return executor;
    }
     
    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
         return new MyAsyncUncaughtExceptionHandler();
    }
}
```

## 简单聊下Quartz登场

Sprin处了@Scheduled和@Async注解外，还有一个和Spring整合的第三方库叫Quartz，看了下官网的使用简介，也是挺逗的，现在都习惯用Maven，Gradle之类来关系这些依赖了，他还叫人下载，也是不知为何，详情点击－>
[http://quartz-scheduler.org/documentation/quartz-2.2.x/quick-start](http://quartz-scheduler.org/documentation/quartz-2.2.x/quick-start)

估计有可能是因为没再维护了的原因吧，看了下，最新版2.2居然是Sep, 2013更新的…

Quartz居然是停更了，不过Quartz作为一个企业级应用的任务调度框架，还是一个可以的候选项目，作为其他方案的兜底方案。

这里不铺开讲，有兴趣的小伙伴们就去官网看下吧。整体用起来感觉是没有Spring自己的后台任务方便，不过也可以接受，只需要简单的配置就可以使用了。

**你学会了吗？**

**好了，今天就到这儿吧，我是冰河，大家有啥问题可以在下方留言，也可以加我微信：sun_shine_lyz，我拉你进群，一起交流技术，一起进阶，一起进大厂~~**

![](https://img-blog.csdnimg.cn/20210403235249270.jpg)


## 星球服务

加入星球，你将获得：

1.项目学习：微服务入门必备的SpringCloud  Alibaba实战项目、手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】、Seckill秒杀系统项目—进大厂必备高并发、高性能和高可用技能。

2.框架源码：手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】。

3.硬核技术：深入理解高并发系列（全册）、深入理解JVM系列（全册）、深入浅出Java设计模式（全册）、MySQL核心知识（全册）。

4.技术小册：深入理解高并发编程（第1版）、深入理解高并发编程（第2版）、从零开始手写RPC框架、SpringCloud  Alibaba实战、冰河的渗透实战笔记、MySQL核心知识手册、Spring IOC核心技术、Nginx核心技术、面经手册等。

5.技术与就业指导：提供相关就业辅导和未来发展指引，冰河从初级程序员不断沉淀，成长，突破，一路成长为互联网资深技术专家，相信我的经历和经验对你有所帮助。

冰河的知识星球是一个简单、干净、纯粹交流技术的星球，不吹水，目前加入享5折优惠，价值远超门票。加入星球的用户，记得添加冰河微信：hacker_binghe，冰河拉你进星球专属VIP交流群。

## 星球重磅福利

跟冰河一起从根本上提升自己的技术能力，架构思维和设计思路，以及突破自身职场瓶颈，冰河特推出重大优惠活动，扫码领券进行星球，**直接立减149元，相当于5折，** 这已经是星球最大优惠力度！

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu_149.png?raw=true" width="80%">
    <br/>
</div>

领券加入星球，跟冰河一起学习《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》，更有已经上新的《大规模分布式Seckill秒杀系统》，从零开始介绍原理、设计架构、手撸代码。后续更有硬核中间件项目和业务项目，而这些都是你升职加薪必备的基础技能。

**100多元就能学这么多硬核技术、中间件项目和大厂秒杀系统，如果是我，我会买他个终身会员！**

## 其他方式加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

## 星球规划

后续冰河还会在星球更新大规模中间件项目和深度剖析核心技术的专栏，目前已经规划的专栏如下所示。

### 中间件项目

* 《大规模分布式定时调度中间件项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式IM（即时通讯）项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式网关项目实战（非Demo）》：全程手撸代码。
* 《手写Redis》：全程手撸代码。
* 《手写JVM》全程手撸代码。

### 超硬核项目

* 《从零落地秒杀系统项目》：全程手撸代码，在阿里云实现压测（**已上新**）。
* 《大规模电商系统商品详情页项目》：全程手撸代码，在阿里云实现压测。
* 其他待规划的实战项目，小伙伴们也可以提一些自己想学的，想一起手撸的实战项目。。。


既然星球规划了这么多内容，那么肯定就会有小伙伴们提出疑问：这么多内容，能更新完吗？我的回答就是：一个个攻破呗，咱这星球干就干真实中间件项目，剖析硬核技术和项目，不做Demo。初衷就是能够让小伙伴们学到真正的核心技术，不再只是简单的做CRUD开发。所以，每个专栏都会是硬核内容，像《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》就是很好的示例。后续的专栏只会比这些更加硬核，杜绝Demo开发。

小伙伴们跟着冰河认真学习，多动手，多思考，多分析，多总结，有问题及时在星球提问，相信在技术层面，都会有所提高。将学到的知识和技术及时运用到实际的工作当中，学以致用。星球中不少小伙伴都成为了公司的核心技术骨干，实现了升职加薪的目标。

## 联系冰河

### 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`星球编号`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>



### 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>


### 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>



### 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>