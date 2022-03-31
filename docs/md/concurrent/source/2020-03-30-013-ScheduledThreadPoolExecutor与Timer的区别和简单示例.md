---
layout: post
category: binghe-code-concurrent
title: ScheduledThreadPoolExecutor与Timer的区别和简单示例
tagline: by 冰河
tag: [concurrent,binghe-code-concurrent]
excerpt: JDK 1.5开始提供ScheduledThreadPoolExecutor类，ScheduledThreadPoolExecutor类继承ThreadPoolExecutor类重用线程池实现了任务的周期性调度功能。在JDK 1.5之前，实现任务的周期性调度主要使用的是Timer类和TimerTask类。本文，就简单介绍下ScheduledThreadPoolExecutor类与Timer类的区别，ScheduledThreadPoolExecutor类相比于Timer类来说，究竟有哪些优势，以及二者分别实现任务调度的简单示例。
lock: need
---

# 【高并发】ScheduledThreadPoolExecutor与Timer的区别和简单示例

JDK 1.5开始提供ScheduledThreadPoolExecutor类，ScheduledThreadPoolExecutor类继承ThreadPoolExecutor类重用线程池实现了任务的周期性调度功能。在JDK 1.5之前，实现任务的周期性调度主要使用的是Timer类和TimerTask类。本文，就简单介绍下ScheduledThreadPoolExecutor类与Timer类的区别，ScheduledThreadPoolExecutor类相比于Timer类来说，究竟有哪些优势，以及二者分别实现任务调度的简单示例。

## 二者的区别

### 线程角度

- Timer是单线程模式，如果某个TimerTask任务的执行时间比较久，会影响到其他任务的调度执行。
- ScheduledThreadPoolExecutor是多线程模式，并且重用线程池，某个ScheduledFutureTask任务执行的时间比较久，不会影响到其他任务的调度执行。

### 系统时间敏感度

- Timer调度是基于操作系统的绝对时间的，对操作系统的时间敏感，一旦操作系统的时间改变，则Timer的调度不再精确。
- ScheduledThreadPoolExecutor调度是基于相对时间的，不受操作系统时间改变的影响。

### 是否捕获异常

- Timer不会捕获TimerTask抛出的异常，加上Timer又是单线程的。一旦某个调度任务出现异常，则整个线程就会终止，其他需要调度的任务也不再执行。
- ScheduledThreadPoolExecutor基于线程池来实现调度功能，某个任务抛出异常后，其他任务仍能正常执行。

### 任务是否具备优先级

- Timer中执行的TimerTask任务整体上没有优先级的概念，只是按照系统的绝对时间来执行任务。
- ScheduledThreadPoolExecutor中执行的ScheduledFutureTask类实现了java.lang.Comparable接口和java.util.concurrent.Delayed接口，这也就说明了ScheduledFutureTask类中实现了两个非常重要的方法，一个是java.lang.Comparable接口的compareTo方法，一个是java.util.concurrent.Delayed接口的getDelay方法。在ScheduledFutureTask类中compareTo方法方法实现了任务的比较，距离下次执行的时间间隔短的任务会排在前面，也就是说，距离下次执行的时间间隔短的任务的优先级比较高。而getDelay方法则能够返回距离下次任务执行的时间间隔。

### 是否支持对任务排序

- Timer不支持对任务的排序。
- ScheduledThreadPoolExecutor类中定义了一个静态内部类DelayedWorkQueue，DelayedWorkQueue类本质上是一个有序队列，为需要调度的每个任务按照距离下次执行时间间隔的大小来排序

### 能否获取返回的结果

- Timer中执行的TimerTask类只是实现了java.lang.Runnable接口，无法从TimerTask中获取返回的结果。
- ScheduledThreadPoolExecutor中执行的ScheduledFutureTask类继承了FutureTask类，能够通过Future来获取返回的结果。

通过以上对ScheduledThreadPoolExecutor类和Timer类的分析对比，相信在JDK 1.5之后，就没有使用Timer来实现定时任务调度的必要了。

## 二者简单的示例

这里，给出使用Timer和ScheduledThreadPoolExecutor实现定时调度的简单示例，为了简便，我这里就直接使用匿名内部类的形式来提交任务。

### Timer类简单示例

源代码示例如下所示。

```java
package io.binghe.concurrent.lab09;

import java.util.Timer;
import java.util.TimerTask;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试Timer
 */
public class TimerTest {

    public static void main(String[] args) throws InterruptedException {
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                System.out.println("测试Timer类");
            }
        }, 1000, 1000);
        Thread.sleep(10000);
        timer.cancel();
    }
}
```



运行结果如下所示。

```bash
测试Timer类
测试Timer类
测试Timer类
测试Timer类
测试Timer类
测试Timer类
测试Timer类
测试Timer类
测试Timer类
测试Timer类
```



### ScheduledThreadPoolExecutor类简单示例

源代码示例如下所示。

```java
package io.binghe.concurrent.lab09;

import java.util.concurrent.*;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试ScheduledThreadPoolExecutor
 */
public class ScheduledThreadPoolExecutorTest {
    public static void main(String[] args) throws  InterruptedException {
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(3);
        scheduledExecutorService.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                System.out.println("测试测试ScheduledThreadPoolExecutor");
            }
        }, 1, 1, TimeUnit.SECONDS);

        //主线程休眠10秒
        Thread.sleep(10000);

        System.out.println("正在关闭线程池...");
        // 关闭线程池
        scheduledExecutorService.shutdown();
        boolean isClosed;
        // 等待线程池终止
        do {
            isClosed = scheduledExecutorService.awaitTermination(1, TimeUnit.DAYS);
            System.out.println("正在等待线程池中的任务执行完成");
        } while(!isClosed);

        System.out.println("所有线程执行结束，线程池关闭");
    }
}
```



运行结果如下所示。

```bash
测试测试ScheduledThreadPoolExecutor
测试测试ScheduledThreadPoolExecutor
测试测试ScheduledThreadPoolExecutor
测试测试ScheduledThreadPoolExecutor
测试测试ScheduledThreadPoolExecutor
测试测试ScheduledThreadPoolExecutor
测试测试ScheduledThreadPoolExecutor
测试测试ScheduledThreadPoolExecutor
测试测试ScheduledThreadPoolExecutor
正在关闭线程池...
测试测试ScheduledThreadPoolExecutor
正在等待线程池中的任务执行完成
所有线程执行结束，线程池关闭
```



**注意：关于Timer和ScheduledThreadPoolExecutor还有其他的使用方法，这里，我就简单列出以上两个使用示例，更多的使用方法大家可以自行实现。**


## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发编程技术。


最后，附上并发编程需要掌握的核心技能知识图，祝大家在学习并发编程时，少走弯路。

![](https://img-blog.csdnimg.cn/20200322144644983.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2wxMDI4Mzg2ODA0,size_16,color_FFFFFF,t_70#pic_center)

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)

