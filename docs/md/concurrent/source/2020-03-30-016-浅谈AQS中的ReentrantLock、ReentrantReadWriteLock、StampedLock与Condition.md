---
layout: post
category: binghe-code-concurrent
title: 浅谈AQS中的ReentrantLock、ReentrantReadWriteLock、StampedLock与Condition
tagline: by 冰河
tag: [concurrent,binghe-code-concurrent]
excerpt: Java中主要分为两类锁，一类是synchronized修饰的锁，另外一类就是J.U.C中提供的锁。J.U.C中提供的核心锁就是ReentrantLock。
lock: need
---

# 浅谈AQS中的ReentrantLock、ReentrantReadWriteLock、StampedLock与Condition

## ReentrantLock

### 概述

Java中主要分为两类锁，一类是synchronized修饰的锁，另外一类就是J.U.C中提供的锁。J.U.C中提供的核心锁就是ReentrantLock。

##### ReentrantLock（可重入锁）与synchronized区别：

**（1）可重入性**
二者都是同一个线程进入1次，锁的计数器就自增1，需要等到锁的计数器下降为0时，才能释放锁。

**（2）锁的实现**
synchronized是基于JVM实现的，而ReentrantLock是JDK实现的。

**（3）性能的区别**
synchronized优化之前性能比ReentrantLock差很多，但是自从synchronized引入了偏向锁，轻量级锁也就是自旋锁后，性能就差不多了。

**（4）功能区别**

* 便利性

synchronized使用起来比较方便，并且由编译器保证加锁和释放锁；ReentrantLock需要手工声明加锁和释放锁，最好是在finally代码块中声明释放锁。

* 锁的灵活度和细粒度

在这点上ReentrantLock会优于synchronized。

##### ReentrantLock独有的功能

* ReentrantLock可指定是公平锁还是非公平锁。而synchronized只能是非公平锁。所谓的公平锁就是先等待的线程先获得锁。

* 提供了一个Condition类，可以分组唤醒需要唤醒的线程。而synchronized只能随机唤醒一个线程，或者唤醒全部的线程

* 提供能够中断等待锁的线程的机制，lock.lockInterruptibly()。ReentrantLock实现是一种自旋锁，通过循环调用CAS操作来实现加锁，性能上比较好是因为避免了使线程进入内核态的阻塞状态。

synchronized能做的事情ReentrantLock都能做，而ReentrantLock有些能做的事情，synchronized不能做。

在性能上，ReentrantLock不会比synchronized差。

##### synchronized的优势

* 不用手动释放锁，JVM自动处理，如果出现异常，JVM也会自动释放锁。

* JVM用synchronized进行管理锁定请求和释放时，JVM在生成线程转储时能够锁定信息，这些对调试非常有价值，因为它们能标识死锁或者其他异常行为的来源。而ReentrantLock只是普通的类，JVM不知道具体哪个线程拥有lock对象。

* synchronized可以在所有JVM版本中工作，ReentrantLock在某些1.5之前版本的JVM中可能不支持。

##### ReentrantLock中的部分方法说明

* boolean tryLock():仅在调用时锁定未被另一个线程保持的情况下才获取锁定。

* boolean tryLock(long, TimeUnit): 如果锁定在给定的等待时间内没有被另一个线程保持，且当前线程没有被中断，则获取这个锁定。

* void lockInterruptibly():如果当前线程没有被中断，就获取锁定；如果被中断，就抛出异常。

* boolean isLocked():查询此锁定是否由任意线程保持。

* boolean isHeldByCurrentThread(): 查询当前线程是否保持锁定状态。

* boolean isFair():判断是否是公平锁。

* boolean hasQueuedThread(Thread)：查询指定线程是否在等待获取此锁定。

* boolean hasQueuedThreads():查询是否有线程正在等待获取此锁定。

* boolean getHoldCount():查询当前线程保持锁定的个数。

### 代码示例

示例代码如下：

```java
package io.binghe.concurrency.example.lock;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
@Slf4j
public class LockExample {
    //请求总数
    public static int clientTotal = 5000;
    //同时并发执行的线程数
    public static int threadTotal = 200;
    public static int count = 0;
    private static final Lock lock = new ReentrantLock();
    public static void main(String[] args) throws InterruptedException {
        ExecutorService executorService = Executors.newCachedThreadPool();
        final Semaphore semaphore = new Semaphore(threadTotal);
        final CountDownLatch countDownLatch = new CountDownLatch(clientTotal);
        for(int i = 0; i < clientTotal; i++){
            executorService.execute(() -> {
                try{
                    semaphore.acquire();
                    add();
                    semaphore.release();
                }catch (Exception e){
                    log.error("exception", e);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        log.info("count:{}", count);
    }
    private static void add(){
        lock.lock();
        try{
            count ++;
        }finally {
            lock.unlock();
        }
    }
}
```

## ReentrantReadWriteLock

### 概述

在没有任何读写锁的时候，才可以取得写锁。如果一直有读锁存在，则无法执行写锁，这就会导致写锁饥饿。

### 代码示例

 示例代码如下：

```java
package io.binghe.concurrency.example.lock;
 
import lombok.extern.slf4j.Slf4j;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
@Slf4j
public class LockExample {
 
    private final Map<String, Data> map = new TreeMap<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final Lock readLock = lock.readLock();
    private final Lock writeLock = lock.writeLock();
 
    public Data get(String key){
        readLock.lock();
        try{
            return map.get(key);
        }finally {
            readLock.unlock();
        }
    }
 
    public Set<String> getAllKeys(){
        readLock.lock();
        try{
            return map.keySet();
        }finally {
            readLock.unlock();
        }
    }
 
    public Data put(String key, Data value){
        writeLock.lock();
        try{
            return map.put(key, value);
        }finally {
            writeLock.unlock();
        }
    }
 
    class Data{
 
    }
}
```

## StampedLock

### 概述

控制锁三种模式：写、读、乐观读。

StampedLock的状态由版本和模式两个部分组成，锁获取方法返回的是一个数字作为票据，用相应的锁状态来表示并控制相关的访问，数字0表示没有写锁被授权访问。

在读锁上分为悲观锁和乐观锁，乐观读就是在读操作很多，写操作很少的情况下，可以乐观的认为写入和读取同时发生的几率很小。因此，不悲观的使用完全的读取锁定。程序可以查看读取资料之后，是否遭到写入进行了变更，再采取后续的措施，这样的改进可以大幅度提升程序的吞吐量。

总之，在读线程越来越多的场景下，StampedLock大幅度提升了程序的吞吐量。

StampedLock源码中的案例如下，这里加上了注释。

```java
class Point {
	private double x, y;
	private final StampedLock sl = new StampedLock();
 
	void move(double deltaX, double deltaY) { // an exclusively locked method
		long stamp = sl.writeLock();
		try {
			x += deltaX;
			y += deltaY;
		} finally {
			sl.unlockWrite(stamp);
		}
	}
 
	//下面看看乐观读锁案例
	double distanceFromOrigin() { // A read-only method
		long stamp = sl.tryOptimisticRead(); //获得一个乐观读锁
		double currentX = x, currentY = y;  //将两个字段读入本地局部变量
		if (!sl.validate(stamp)) { //检查发出乐观读锁后同时是否有其他写锁发生？
			stamp = sl.readLock();  //如果没有，我们再次获得一个读悲观锁
			try {
				currentX = x; // 将两个字段读入本地局部变量
				currentY = y; // 将两个字段读入本地局部变量
			} finally {
				sl.unlockRead(stamp);
			}
		}
		return Math.sqrt(currentX * currentX + currentY * currentY);
	}
 
	//下面是悲观读锁案例
	void moveIfAtOrigin(double newX, double newY) { // upgrade
		// Could instead start with optimistic, not read mode
		long stamp = sl.readLock();
		try {
			while (x == 0.0 && y == 0.0) { //循环，检查当前状态是否符合
				long ws = sl.tryConvertToWriteLock(stamp); //将读锁转为写锁
				if (ws != 0L) { //这是确认转为写锁是否成功
					stamp = ws; //如果成功 替换票据
					x = newX; //进行状态改变
					y = newY;  //进行状态改变
					break;
				} else { //如果不能成功转换为写锁
					sl.unlockRead(stamp);  //我们显式释放读锁
					stamp = sl.writeLock();  //显式直接进行写锁 然后再通过循环再试
				}
			}
		} finally {
			sl.unlock(stamp); //释放读锁或写锁
		}
	}
}
```

### 代码示例

示例代码如下：

```java
package io.binghe.concurrency.example.lock;
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.StampedLock;
@Slf4j
public class LockExample {
    //请求总数
    public static int clientTotal = 5000;
    //同时并发执行的线程数
    public static int threadTotal = 200;
 
    public static int count = 0;
 
    private static final StampedLock lock = new StampedLock();
 
    public static void main(String[] args) throws InterruptedException {
        ExecutorService executorService = Executors.newCachedThreadPool();
        final Semaphore semaphore = new Semaphore(threadTotal);
        final CountDownLatch countDownLatch = new CountDownLatch(clientTotal);
        for(int i = 0; i < clientTotal; i++){
            executorService.execute(() -> {
                try{
                    semaphore.acquire();
                    add();
                    semaphore.release();
                }catch (Exception e){
                    log.error("exception", e);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        log.info("count:{}", count);
    }
 
    private static void add(){
	//加锁时返回一个long类型的票据
        long stamp = lock.writeLock();
        try{
            count ++;
        }finally {
	    //释放锁的时候带上加锁时返回的票据
            lock.unlock(stamp);
        }
    }
}
```

<font color="#FF0000">**我们可以这样选择使用synchronozed锁还是ReentrantLock锁：**</font>

* 当只有少量竞争者时，synchronized是一个很好的通用锁实现

* 竞争者不少，但是线程的增长趋势是可预估的，此时，ReentrantLock是一个很好的通用锁实现

* synchronized不会引发死锁，其他的锁使用不当可能会引发死锁。

## Condition

### 概述

Condition是一个多线程间协调通信的工具类，Condition除了实现wait和notify的功能以外，它的好处在于一个lock可以创建多个Condition，可以选择性的通知wait的线程

**特点：**

* Condition 的前提是Lock，由AQS中newCondition()方法 创建Condition的对象

* Condition await方法表示线程从AQS中移除，并释放线程获取的锁，并进入Condition等待队列中等待，等待被signal

* Condition signal方法表示唤醒对应Condition等待队列中的线程节点，并加入AQS中，准备去获取锁。

### 代码示例

示例代码如下

```java
package io.binghe.concurrency.example.lock;
 
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
@Slf4j
public class LockExample {
    public static void main(String[] args) {
        ReentrantLock reentrantLock = new ReentrantLock();
        Condition condition = reentrantLock.newCondition();
 
        new Thread(() -> {
            try {
                reentrantLock.lock();
                log.info("wait signal"); // 1
                condition.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            log.info("get signal"); // 4
            reentrantLock.unlock();
        }).start();
 
        new Thread(() -> {
            reentrantLock.lock();
            log.info("get lock"); // 2
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            condition.signalAll();
            log.info("send signal ~ "); // 3
            reentrantLock.unlock();
        }).start();
    }
}
```

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发编程技术。


最后，附上并发编程需要掌握的核心技能知识图，祝大家在学习并发编程时，少走弯路。

![](https://img-blog.csdnimg.cn/20200322144644983.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2wxMDI4Mzg2ODA0,size_16,color_FFFFFF,t_70#pic_center)

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)

