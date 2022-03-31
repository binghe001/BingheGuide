---
layout: post
category: binghe-code-concurrent
title: 浅谈AQS中的CountDownLatch、Semaphore与CyclicBarrier
tagline: by 冰河
tag: [concurrent,binghe-code-concurrent]
excerpt: 今天，跟大家聊聊AQS中的CountDownLatch、Semaphore与CyclicBarrier，好了，进入今天的主题吧。
lock: need
---

# 【高并发】浅谈AQS中的CountDownLatch、Semaphore与CyclicBarrier

**大家好，我是冰河~~**

今天，跟大家聊聊AQS中的CountDownLatch、Semaphore与CyclicBarrier，好了，进入今天的主题吧。

## CountDownLatch

### 概述

同步辅助类，通过它可以阻塞当前线程。也就是说，能够实现一个线程或者多个线程一直等待，直到其他线程执行的操作完成。使用一个给定的计数器进行初始化，该计数器的操作是原子操作，即同时只能有一个线程操作该计数器。

调用该类await()方法的线程会一直阻塞，直到其他线程调用该类的countDown()方法，使当前计数器的值变为0为止。每次调用该类的countDown()方法，当前计数器的值就会减1。当计数器的值减为0的时候，所有因调用await()方法而处于等待状态的线程就会继续往下执行。这种操作只能出现一次，因为该类中的计数器不能被重置。如果需要一个可以重置计数次数的版本，可以考虑使用CyclicBarrier类。

CountDownLatch支持给定时间的等待，超过一定的时间不再等待，使用时只需要在await()方法中传入需要等待的时间即可。此时，await()方法的方法签名如下：

```java
public boolean await(long timeout, TimeUnit unit)
```

### 使用场景

在某些业务场景中，程序执行需要等待某个条件完成后才能继续执行后续的操作。典型的应用为并行计算：当某个处理的运算量很大时，可以将该运算任务拆分成多个子任务，等待所有的子任务都完成之后，父任务再拿到所有子任务的运算结果进行汇总。

### 代码示例

调用ExecutorService类的shutdown()方法，并不会第一时间内把所有线程全部都销毁掉，而是让当前已有的线程全部执行完，之后，再把线程池销毁掉。

示例代码如下：

```java
package io.binghe.concurrency.example.aqs;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
@Slf4j
public class CountDownLatchExample {
    private static final int threadCount = 200;
 
    public static void main(String[] args) throws InterruptedException {
 
        ExecutorService exec = Executors.newCachedThreadPool();
        final CountDownLatch countDownLatch = new CountDownLatch(threadCount);
        for (int i = 0; i < threadCount; i++){
            final int threadNum = i;
            exec.execute(() -> {
                try {
                    test(threadNum);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }finally {
                    countDownLatch.countDown();
                }
            });
        }
        countDownLatch.await();
        log.info("finish");
        exec.shutdown();
    }
 
    private static void test(int threadNum) throws InterruptedException {
        Thread.sleep(100);
        log.info("{}", threadNum);
        Thread.sleep(100);
    }
}
```

支持给定时间等待的示例代码如下：

```java
package io.binghe.concurrency.example.aqs;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
@Slf4j
public class CountDownLatchExample {
    private static final int threadCount = 200;
 
    public static void main(String[] args) throws InterruptedException {
        ExecutorService exec = Executors.newCachedThreadPool();
        final CountDownLatch countDownLatch = new CountDownLatch(threadCount);
        for (int i = 0; i < threadCount; i++){
            final int threadNum = i;
            exec.execute(() -> {
                try {
                    test(threadNum);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }finally {
                    countDownLatch.countDown();
                }
            });
        }
        countDownLatch.await(10, TimeUnit.MICROSECONDS);
        log.info("finish");
        exec.shutdown();
    }
 
    private static void test(int threadNum) throws InterruptedException {
        Thread.sleep(100);
        log.info("{}", threadNum);
    }
}
```

## Semaphore

### 概述

控制同一时间并发线程的数目。能够完成对于信号量的控制，可以控制某个资源可被同时访问的个数。

提供了两个核心方法——acquire()方法和release()方法。acquire()方法表示获取一个许可，如果没有则等待，release()方法则是在操作完成后释放对应的许可。Semaphore维护了当前访问的个数，通过提供同步机制来控制同时访问的个数。Semaphore可以实现有限大小的链表。

### 使用场景

Semaphore常用于仅能提供有限访问的资源，比如：数据库连接数。

### 代码示例

每次获取并释放一个许可，示例代码如下：

```java
package io.binghe.concurrency.example.aqs;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
@Slf4j
public class SemaphoreExample {
    private static final int threadCount = 200;
 
    public static void main(String[] args) throws InterruptedException {
 
        ExecutorService exec = Executors.newCachedThreadPool();
        final Semaphore semaphore  = new Semaphore(3);
 
        for (int i = 0; i < threadCount; i++){
            final int threadNum = i;
            exec.execute(() -> {
                try {
                    semaphore.acquire();  //获取一个许可
                    test(threadNum);
                    semaphore.release();  //释放一个许可
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            });
        }
        exec.shutdown();
    }
 
    private static void test(int threadNum) throws InterruptedException {
        log.info("{}", threadNum);
        Thread.sleep(1000);
    }
}
```

每次获取并释放多个许可，示例代码如下：

```java
package io.binghe.concurrency.example.aqs;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
@Slf4j
public class SemaphoreExample {
    private static final int threadCount = 200;
 
    public static void main(String[] args) throws InterruptedException {
 
        ExecutorService exec = Executors.newCachedThreadPool();
        final Semaphore semaphore  = new Semaphore(3);
 
        for (int i = 0; i < threadCount; i++){
            final int threadNum = i;
            exec.execute(() -> {
                try {
                    semaphore.acquire(3);  //获取多个许可
                    test(threadNum);
                    semaphore.release(3);  //释放多个许可
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            });
        }
        log.info("finish");
        exec.shutdown();
    }
 
    private static void test(int threadNum) throws InterruptedException {
        log.info("{}", threadNum);
        Thread.sleep(1000);
    }
}
```

假设有这样一个场景，并发太高了，即使使用Semaphore进行控制，处理起来也比较棘手。假设系统当前允许的最高并发数是3，超过3后就需要丢弃，使用Semaphore也能实现这样的场景，示例代码如下：

```java
package io.binghe.concurrency.example.aqs;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
@Slf4j
public class SemaphoreExample {
    private static final int threadCount = 200;
 
    public static void main(String[] args) throws InterruptedException {
 
        ExecutorService exec = Executors.newCachedThreadPool();
        final Semaphore semaphore  = new Semaphore(3);
 
        for (int i = 0; i < threadCount; i++){
            final int threadNum = i;
            exec.execute(() -> {
                try {
	            //尝试获取一个许可，也可以尝试获取多个许可，
                    //支持尝试获取许可超时设置，超时后不再等待后续线程的执行
                    //具体可以参见Semaphore的源码
                    if (semaphore.tryAcquire()) { 
                        test(threadNum);
                        semaphore.release();  //释放一个许可
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            });
        }
        log.info("finish");
        exec.shutdown();
    }
    private static void test(int threadNum) throws InterruptedException {
        log.info("{}", threadNum);
        Thread.sleep(1000);
    }
}
```

## CyclicBarrier

### 概述

是一个同步辅助类，允许一组线程相互等待，直到到达某个公共的屏障点，通过它可以完成多个线程之间相互等待，只有当每个线程都准备就绪后，才能各自继续往下执行后面的操作。

与CountDownLatch有相似的地方，都是使用计数器实现，当某个线程调用了CyclicBarrier的await()方法后，该线程就进入了等待状态，而且计数器执行加1操作，当计数器的值达到了设置的初始值，调用await()方法进入等待状态的线程会被唤醒，继续执行各自后续的操作。CyclicBarrier在释放等待线程后可以重用，所以，CyclicBarrier又被称为循环屏障。

### 使用场景

可以用于多线程计算数据，最后合并计算结果的场景

### CyclicBarrier与CountDownLatch的区别

* CountDownLatch的计数器只能使用一次，而CyclicBarrier的计数器可以使用reset()方法进行重置，并且可以循环使用
* CountDownLatch主要实现1个或n个线程需要等待其他线程完成某项操作之后，才能继续往下执行，描述的是1个或n个线程等待其他线程的关系。而CyclicBarrier主要实现了多个线程之间相互等待，直到所有的线程都满足了条件之后，才能继续执行后续的操作，描述的是各个线程内部相互等待的关系。
* CyclicBarrier能够处理更复杂的场景，如果计算发生错误，可以重置计数器让线程重新执行一次。
* CyclicBarrier中提供了很多有用的方法，比如：可以通过getNumberWaiting()方法获取阻塞的线程数量，通过isBroken()方法判断阻塞的线程是否被中断。

### 代码示例

示例代码如下。

```java
package io.binghe.concurrency.example.aqs;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
@Slf4j
public class CyclicBarrierExample {
 
    private static CyclicBarrier cyclicBarrier = new CyclicBarrier(5);
 
    public static void main(String[] args) throws Exception {
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < 10; i++){
            final int threadNum = i;
            Thread.sleep(1000);
            executorService.execute(() -> {
                try {
                    race(threadNum);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
		executorService.shutdown();
    }
    private static void race(int threadNum) throws Exception{
        Thread.sleep(1000);
        log.info("{} is ready", threadNum);
        cyclicBarrier.await();
        log.info("{} continue", threadNum);
    }
}
```

设置等待超时示例代码如下：

```java
package io.binghe.concurrency.example.aqs;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.*;
@Slf4j
public class CyclicBarrierExample {
 
    private static CyclicBarrier cyclicBarrier = new CyclicBarrier(5);
 
    public static void main(String[] args) throws Exception {
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < 10; i++){
            final int threadNum = i;
            Thread.sleep(1000);
            executorService.execute(() -> {
                try {
                    race(threadNum);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        executorService.shutdown();
    }
    private static void race(int threadNum) throws Exception{
        Thread.sleep(1000);
        log.info("{} is ready", threadNum);
        try{
            cyclicBarrier.await(2000, TimeUnit.MILLISECONDS);
        }catch (BrokenBarrierException | TimeoutException e){
            log.warn("BarrierException", e);
        }
        log.info("{} continue", threadNum);
    }
}
```

在声明CyclicBarrier的时候，还可以指定一个Runnable，当线程达到屏障的时候，可以优先执行Runnable中的方法。
 示例代码如下：

```java
package io.binghe.concurrency.example.aqs;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
@Slf4j
public class CyclicBarrierExample {
 
    private static CyclicBarrier cyclicBarrier = new CyclicBarrier(5, () -> {
        log.info("callback is running");
    });
 
    public static void main(String[] args) throws Exception {
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < 10; i++){
            final int threadNum = i;
            Thread.sleep(1000);
            executorService.execute(() -> {
                try {
                    race(threadNum);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        executorService.shutdown();
    }
    private static void race(int threadNum) throws Exception{
        Thread.sleep(1000);
        log.info("{} is ready", threadNum);
        cyclicBarrier.await();
        log.info("{} continue", threadNum);
    }
}
```

**好了，今天就到这儿吧，我是冰河，我们下期见~~**


## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发编程技术。


最后，附上并发编程需要掌握的核心技能知识图，祝大家在学习并发编程时，少走弯路。

![](https://img-blog.csdnimg.cn/20200322144644983.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2wxMDI4Mzg2ODA0,size_16,color_FFFFFF,t_70#pic_center)

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)

