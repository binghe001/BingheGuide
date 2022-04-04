---
layout: post
category: binghe-spring-ioc
title: Spring中Scheduled和Async两种调度方式有啥区别？
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 最近有小伙伴出去面试，回来跟我说：冰河，我去XXX公司面试，面试官竟然问了我一个关于Spring中Scheduled和Async调度的问题，我竟然没回答上来，你能不能写一篇关于这个问题的文章呢？我：可以，安排上！于是便有了这篇文章。
lock: need
---

# Spring中Scheduled和Async两种调度方式有啥区别？

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


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)