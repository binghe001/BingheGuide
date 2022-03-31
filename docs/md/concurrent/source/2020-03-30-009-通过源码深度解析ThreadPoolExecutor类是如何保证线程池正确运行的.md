---
layout: post
category: binghe-code-concurrent
title: 通过源码深度解析ThreadPoolExecutor类是如何保证线程池正确运行的
tagline: by 冰河
tag: [concurrent,binghe-code-concurrent]
excerpt: 对于线程池的核心类ThreadPoolExecutor来说，有哪些重要的属性和内部类为线程池的正确运行提供重要的保障呢？。
lock: need
---

# 【高并发】通过源码深度解析ThreadPoolExecutor类是如何保证线程池正确运行的

**大家好，我是冰河~~**

对于线程池的核心类ThreadPoolExecutor来说，有哪些重要的属性和内部类为线程池的正确运行提供重要的保障呢？

## ThreadPoolExecutor类中的重要属性

在ThreadPoolExecutor类中，存在几个非常重要的属性和方法，接下来，我们就介绍下这些重要的属性和方法。

### ctl相关的属性

AtomicInteger类型的常量ctl是贯穿线程池整个生命周期的重要属性，它是一个原子类对象，主要用来保存线程的数量和线程池的状态，我们看下与这个属性相关的代码如下所示。

```java
//主要用来保存线程数量和线程池的状态，高3位保存线程状态，低29位保存线程数量
private final AtomicInteger ctl = new AtomicInteger(ctlOf(RUNNING, 0));
//线程池中线程的数量的位数（32-3）
private static final int COUNT_BITS = Integer.SIZE - 3;
//表示线程池中的最大线程数量
//将数字1的二进制值向右移29位，再减去1
private static final int CAPACITY   = (1 << COUNT_BITS) - 1;
//线程池的运行状态
private static final int RUNNING    = -1 << COUNT_BITS;
private static final int SHUTDOWN   =  0 << COUNT_BITS;
private static final int STOP       =  1 << COUNT_BITS;
private static final int TIDYING    =  2 << COUNT_BITS;
private static final int TERMINATED =  3 << COUNT_BITS;
//获取线程状态
private static int runStateOf(int c)     { return c & ~CAPACITY; }
//获取线程数量
private static int workerCountOf(int c)  { return c & CAPACITY; }
private static int ctlOf(int rs, int wc) { return rs | wc; }
private static boolean runStateLessThan(int c, int s) {
	return c < s;
}
private static boolean runStateAtLeast(int c, int s) {
	return c >= s;
}
private static boolean isRunning(int c) {
	return c < SHUTDOWN;
}
private boolean compareAndIncrementWorkerCount(int expect) {
	return ctl.compareAndSet(expect, expect + 1);
}
private boolean compareAndDecrementWorkerCount(int expect) {
	return ctl.compareAndSet(expect, expect - 1);
}
private void decrementWorkerCount() {
	do {} while (! compareAndDecrementWorkerCount(ctl.get()));
}
```



对于线程池的各状态说明如下所示。

- RUNNING:运行状态，能接收新提交的任务，并且也能处理阻塞队列中的任务
- SHUTDOWN: 关闭状态，不能再接收新提交的任务，但是可以处理阻塞队列中已经保存的任务，当线程池处于RUNNING状态时，调用shutdown()方法会使线程池进入该状态
- STOP: 不能接收新任务，也不能处理阻塞队列中已经保存的任务，会中断正在处理任务的线程，如果线程池处于RUNNING或SHUTDOWN状态，调用shutdownNow()方法，会使线程池进入该状态
- TIDYING: 如果所有的任务都已经终止，有效线程数为0（阻塞队列为空，线程池中的工作线程数量为0），线程池就会进入该状态。
- TERMINATED: 处于TIDYING状态的线程池调用terminated ()方法，会使用线程池进入该状态

也可以按照ThreadPoolExecutor类的注释，将线程池的各状态之间的转化总结成如下图所示。

![](https://img-blog.csdnimg.cn/20200224000305768.png)



- RUNNING -> SHUTDOWN：显式调用shutdown()方法, 或者隐式调用了finalize()方法
- (RUNNING or SHUTDOWN) -> STOP：显式调用shutdownNow()方法
- SHUTDOWN -> TIDYING：当线程池和任务队列都为空的时候
- STOP -> TIDYING：当线程池为空的时候
- TIDYING -> TERMINATED：当 terminated() hook 方法执行完成时候

### 其他重要属性

除了ctl相关的属性外，ThreadPoolExecutor类中其他一些重要的属性如下所示。

```java
//用于存放任务的阻塞队列  
private final BlockingQueue<Runnable> workQueue;
//可重入锁
private final ReentrantLock mainLock = new ReentrantLock();
//存放线程池中线程的集合，访问这个集合时，必须获得mainLock锁
private final HashSet<Worker> workers = new HashSet<Worker>();
//在锁内部阻塞等待条件完成
private final Condition termination = mainLock.newCondition();
//线程工厂，以此来创建新线程
private volatile ThreadFactory threadFactory;
//拒绝策略
private volatile RejectedExecutionHandler handler;
//默认的拒绝策略
private static final RejectedExecutionHandler defaultHandler = new AbortPolicy();
```



## ThreadPoolExecutor类中的重要内部类

在ThreadPoolExecutor类中存在对于线程池的执行至关重要的内部类，Worker内部类和拒绝策略内部类。接下来，我们分别看这些内部类。

### Worker内部类

Worker类从源代码上来看，实现了Runnable接口，说明其本质上是一个用来执行任务的线程，接下来，我们看下Worker类的源代码，如下所示。

```java
private final class Worker extends AbstractQueuedSynchronizer implements Runnable{
	private static final long serialVersionUID = 6138294804551838833L;
	//真正执行任务的线程
	final Thread thread;
	//第一个Runnable任务，如果在创建线程时指定了需要执行的第一个任务
	//则第一个任务会存放在此变量中，此变量也可以为null
	//如果为null，则线程启动后，通过getTask方法到BlockingQueue队列中获取任务
	Runnable firstTask;
	//用于存放此线程完全的任务数，注意：使用了volatile关键字
	volatile long completedTasks;
	
	//Worker类唯一的构造放大，传递的firstTask可以为null
	Worker(Runnable firstTask) {
		//防止在调用runWorker之前被中断
		setState(-1);
		this.firstTask = firstTask;
		//使用ThreadFactory 来创建一个新的执行任务的线程
		this.thread = getThreadFactory().newThread(this);
	}
	//调用外部ThreadPoolExecutor类的runWorker方法执行任务
	public void run() {
		runWorker(this);
	}

	//是否获取到锁 
	//state=0表示锁未被获取
	//state=1表示锁被获取
	protected boolean isHeldExclusively() {
		return getState() != 0;
	}

	protected boolean tryAcquire(int unused) {
		if (compareAndSetState(0, 1)) {
			setExclusiveOwnerThread(Thread.currentThread());
			return true;
		}
		return false;
	}

	protected boolean tryRelease(int unused) {
		setExclusiveOwnerThread(null);
		setState(0);
		return true;
	}

	public void lock()        { acquire(1); }
	public boolean tryLock()  { return tryAcquire(1); }
	public void unlock()      { release(1); }
	public boolean isLocked() { return isHeldExclusively(); }

	void interruptIfStarted() {
		Thread t;
		if (getState() >= 0 && (t = thread) != null && !t.isInterrupted()) {
			try {
				t.interrupt();
			} catch (SecurityException ignore) {
			}
		}
	}
}
```



在Worker类的构造方法中，可以看出，首先将同步状态state设置为-1，设置为-1是为了防止runWorker方法运行之前被中断。这是因为如果其他线程调用线程池的shutdownNow()方法时，如果Worker类中的state状态的值大于0，则会中断线程，如果state状态的值为-1，则不会中断线程。

Worker类实现了Runnable接口，需要重写run方法，而Worker的run方法本质上调用的是ThreadPoolExecutor类的runWorker方法，在runWorker方法中，会首先调用unlock方法，该方法会将state置为0，所以这个时候调用shutDownNow方法就会中断当前线程，而这个时候已经进入了runWork方法，就不会在还没有执行runWorker方法的时候就中断线程。

**注意：大家需要重点理解****Worker****类的实现。**

### 拒绝策略内部类

在线程池中，如果workQueue阻塞队列满了，并且没有空闲的线程池，此时，继续提交任务，需要采取一种策略来处理这个任务。而线程池总共提供了四种策略，如下所示。

- 直接抛出异常，这也是默认的策略。实现类为AbortPolicy。
- 用调用者所在的线程来执行任务。实现类为CallerRunsPolicy。
- 丢弃队列中最靠前的任务并执行当前任务。实现类为DiscardOldestPolicy。
- 直接丢弃当前任务。实现类为DiscardPolicy。

在ThreadPoolExecutor类中提供了4个内部类来默认实现对应的策略，如下所示。

```java
public static class CallerRunsPolicy implements RejectedExecutionHandler {

	public CallerRunsPolicy() { }

	public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
		if (!e.isShutdown()) {
			r.run();
		}
	}
}

public static class AbortPolicy implements RejectedExecutionHandler {

	public AbortPolicy() { }

	public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
		throw new RejectedExecutionException("Task " + r.toString() + " rejected from " + e.toString());
	}
}

public static class DiscardPolicy implements RejectedExecutionHandler {

	public DiscardPolicy() { }

	public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
	}
}

public static class DiscardOldestPolicy implements RejectedExecutionHandler {

	public DiscardOldestPolicy() { }


	public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
		if (!e.isShutdown()) {
			e.getQueue().poll();
			e.execute(r);
		}
	}
}
```



我们也可以通过实现RejectedExecutionHandler接口，并重写RejectedExecutionHandler接口的rejectedExecution方法来自定义拒绝策略，在创建线程池时，调用ThreadPoolExecutor的构造方法，传入我们自己写的拒绝策略。

例如，自定义的拒绝策略如下所示。

```java
public class CustomPolicy implements RejectedExecutionHandler {

	public CustomPolicy() { }

	public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
		if (!e.isShutdown()) {
			System.out.println("使用调用者所在的线程来执行任务")
			r.run();
		}
	}
}
```



使用自定义拒绝策略创建线程池。

```java
new ThreadPoolExecutor(0, Integer.MAX_VALUE,
                       60L, TimeUnit.SECONDS,
                       new SynchronousQueue<Runnable>(),
                       Executors.defaultThreadFactory(),
		       new CustomPolicy());
```

**好了，今天就到这儿吧，我是冰河，我们下期见~~**

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发编程技术。


最后，附上并发编程需要掌握的核心技能知识图，祝大家在学习并发编程时，少走弯路。

![](https://img-blog.csdnimg.cn/20200322144644983.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2wxMDI4Mzg2ODA0,size_16,color_FFFFFF,t_70#pic_center)

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)

