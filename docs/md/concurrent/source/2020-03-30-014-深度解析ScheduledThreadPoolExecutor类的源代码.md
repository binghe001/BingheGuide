---
layout: post
category: binghe-code-concurrent
title: 深度解析ScheduledThreadPoolExecutor类的源代码
tagline: by 冰河
tag: [concurrent,binghe-code-concurrent]
excerpt: 在【高并发专题】的专栏中，我们深度分析了ThreadPoolExecutor类的源代码，而ScheduledThreadPoolExecutor类是ThreadPoolExecutor类的子类。今天我们就来一起手撕ScheduledThreadPoolExecutor类的源代码。
lock: need
---

# 【高并发】深度解析ScheduledThreadPoolExecutor类的源代码

**大家好，我是冰河~~**

在【高并发专题】的专栏中，我们深度分析了ThreadPoolExecutor类的源代码，而ScheduledThreadPoolExecutor类是ThreadPoolExecutor类的子类。今天我们就来一起手撕ScheduledThreadPoolExecutor类的源代码。

### 构造方法

我们先来看下ScheduledThreadPoolExecutor的构造方法，源代码如下所示。

```java
public ScheduledThreadPoolExecutor(int corePoolSize) {
	super(corePoolSize, Integer.MAX_VALUE, 0, NANOSECONDS, new DelayedWorkQueue());
}

public ScheduledThreadPoolExecutor(int corePoolSize, ThreadFactory threadFactory) {
	super(corePoolSize, Integer.MAX_VALUE, 0, NANOSECONDS,
		  new DelayedWorkQueue(), threadFactory);
}

public ScheduledThreadPoolExecutor(int corePoolSize, RejectedExecutionHandler handler) {
	super(corePoolSize, Integer.MAX_VALUE, 0, NANOSECONDS,
		  new DelayedWorkQueue(), handler);
}

public ScheduledThreadPoolExecutor(int corePoolSize, ThreadFactory threadFactory, RejectedExecutionHandler handler) {
	super(corePoolSize, Integer.MAX_VALUE, 0, NANOSECONDS,
		  new DelayedWorkQueue(), threadFactory, handler);
}
```



从代码结构上来看，ScheduledThreadPoolExecutor类是ThreadPoolExecutor类的子类，ScheduledThreadPoolExecutor类的构造方法实际上调用的是ThreadPoolExecutor类的构造方法。

### schedule方法

接下来，我们看一下ScheduledThreadPoolExecutor类的schedule方法，源代码如下所示。

```java
public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
	//如果传递的Runnable对象和TimeUnit时间单位为空
	//抛出空指针异常
	if (command == null || unit == null)
		throw new NullPointerException();
	//封装任务对象，在decorateTask方法中直接返回ScheduledFutureTask对象
	RunnableScheduledFuture<?> t = decorateTask(command, new ScheduledFutureTask<Void>(command, null, triggerTime(delay, unit)));
	//执行延时任务
	delayedExecute(t);
	//返回任务
	return t;
}

public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) 
	//如果传递的Callable对象和TimeUnit时间单位为空
	//抛出空指针异常
	if (callable == null || unit == null)
		throw new NullPointerException();
	//封装任务对象，在decorateTask方法中直接返回ScheduledFutureTask对象
	RunnableScheduledFuture<V> t = decorateTask(callable,
		new ScheduledFutureTask<V>(callable, triggerTime(delay, unit)));
	//执行延时任务
	delayedExecute(t);
	//返回任务
	return t;
}
```



从源代码可以看出，ScheduledThreadPoolExecutor类提供了两个重载的schedule方法，两个schedule方法的第一个参数不同。可以传递Runnable接口对象，也可以传递Callable接口对象。在方法内部，会将Runnable接口对象和Callable接口对象封装成RunnableScheduledFuture对象，本质上就是封装成ScheduledFutureTask对象。并通过delayedExecute方法来执行延时任务。

在源代码中，我们看到两个schedule都调用了decorateTask方法，接下来，我们就看看decorateTask方法。

### decorateTask方法

decorateTask方法源代码如下所示。

```java
protected <V> RunnableScheduledFuture<V> decorateTask(Runnable runnable, RunnableScheduledFuture<V> task) {
	return task;
}

protected <V> RunnableScheduledFuture<V> decorateTask(Callable<V> callable, RunnableScheduledFuture<V> task) {
	return task;
}
```



通过源码可以看出decorateTask方法的实现比较简单，接收一个Runnable接口对象或者Callable接口对象和封装的RunnableScheduledFuture任务，两个方法都是将RunnableScheduledFuture任务直接返回。在ScheduledThreadPoolExecutor类的子类中可以重写这两个方法。

接下来，我们继续看下scheduleAtFixedRate方法。

### scheduleAtFixedRate方法

scheduleAtFixedRate方法源代码如下所示。

```java
public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
	//传入的Runnable对象和TimeUnit为空，则抛出空指针异常
	if (command == null || unit == null)
		throw new NullPointerException();
	//如果执行周期period传入的数值小于或者等于0
	//抛出非法参数异常
	if (period <= 0)
		throw new IllegalArgumentException();
	//将Runnable对象封装成ScheduledFutureTask任务，
	//并设置执行周期
	ScheduledFutureTask<Void> sft =
		new ScheduledFutureTask<Void>(command, null, triggerTime(initialDelay, unit), unit.toNanos(period));
	//调用decorateTask方法，本质上还是直接返回ScheduledFutureTask对象
	RunnableScheduledFuture<Void> t = decorateTask(command, sft);
	//设置执行的任务
	sft.outerTask = t;
	//执行延时任务
	delayedExecute(t);
	//返回执行的任务
	return t;
}
```



通过源码可以看出，scheduleAtFixedRate方法将传递的Runnable对象封装成ScheduledFutureTask任务对象，并设置了执行周期，下一次的执行时间相对于上一次的执行时间来说，加上了period时长，时长的具体单位由TimeUnit决定。采用固定的频率来执行定时任务。

ScheduledThreadPoolExecutor类中另一个定时调度任务的方法是scheduleWithFixedDelay方法，接下来，我们就一起看看scheduleWithFixedDelay方法。

### scheduleWithFixedDelay方法

scheduleWithFixedDelay方法的源代码如下所示。

```java
public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
	//传入的Runnable对象和TimeUnit为空，则抛出空指针异常
	if (command == null || unit == null)
		throw new NullPointerException();
	//任务延时时长小于或者等于0，则抛出非法参数异常
	if (delay <= 0)
		throw new IllegalArgumentException();
	//将Runnable对象封装成ScheduledFutureTask任务
	//并设置固定的执行周期来执行任务
	ScheduledFutureTask<Void> sft =
		new ScheduledFutureTask<Void>(command, null,triggerTime(initialDelay, unit), unit.toNanos(-delay));
	//调用decorateTask方法，本质上直接返回ScheduledFutureTask任务
	RunnableScheduledFuture<Void> t = decorateTask(command, sft);
	//设置执行的任务
	sft.outerTask = t;
	//执行延时任务
	delayedExecute(t);
	//返回任务
	return t;
}
```



从scheduleWithFixedDelay方法的源代码，我们可以看出在将Runnable对象封装成ScheduledFutureTask时，设置了执行周期，但是此时设置的执行周期与scheduleAtFixedRate方法设置的执行周期不同。此时设置的执行周期规则为：下一次任务执行的时间是上一次任务完成的时间加上delay时长，时长单位由TimeUnit决定。也就是说，具体的执行时间不是固定的，但是执行的周期是固定的，整体采用的是相对固定的延迟来执行定时任务。

如果大家细心的话，会发现在scheduleWithFixedDelay方法中设置执行周期时，传递的delay值为负数，如下所示。

```java
ScheduledFutureTask<Void> sft =
		new ScheduledFutureTask<Void>(command, null, triggerTime(initialDelay, unit), unit.toNanos(-delay));
```



这里的负数表示的是相对固定的延迟。

在ScheduledFutureTask类中，存在一个setNextRunTime方法，这个方法会在run方法执行完任务后调用，这个方法更能体现scheduleAtFixedRate方法和scheduleWithFixedDelay方法的不同，setNextRunTime方法的源码如下所示。

```java
private void setNextRunTime() {
	//距离下次执行任务的时长
	long p = period;
	//固定频率执行，
	//上次执行任务的时间
	//加上任务的执行周期
	if (p > 0)
		time += p;
	//相对固定的延迟
	//使用的是系统当前时间
	//加上任务的执行周期
	else
		time = triggerTime(-p);
}
```



在setNextRunTime方法中通过对下次执行任务的时长进行判断来确定是固定频率执行还是相对固定的延迟。

### triggerTime方法

在ScheduledThreadPoolExecutor类中提供了两个triggerTime方法，用于获取下一次执行任务的具体时间。triggerTime方法的源码如下所示。

```java
private long triggerTime(long delay, TimeUnit unit) {
	return triggerTime(unit.toNanos((delay < 0) ? 0 : delay));
}

long triggerTime(long delay) {
	return now() +
		((delay < (Long.MAX_VALUE >> 1)) ? delay : overflowFree(delay));
}
```



这两个triggerTime方法的代码比较简单，就是获取下一次执行任务的具体时间。有一点需要注意的是：delay < (Long.MAX_VALUE >> 1判断delay的值是否小于Long.MAX_VALUE的一半，如果小于Long.MAX_VALUE值的一半，则直接返回delay，否则需要处理溢出的情况。

我们看到在triggerTime方法中处理防止溢出的逻辑使用了overflowFree方法，接下来，我们就看看overflowFree方法的实现。

### overflowFree方法

overflowFree方法的源代码如下所示。

```java
private long overflowFree(long delay) {
	//获取队列中的节点
	Delayed head = (Delayed) super.getQueue().peek();
	//获取的节点不为空，则进行后续处理
	if (head != null) {
		//从队列节点中获取延迟时间
		long headDelay = head.getDelay(NANOSECONDS);
		//如果从队列中获取的延迟时间小于0，并且传递的delay
		//值减去从队列节点中获取延迟时间小于0
		if (headDelay < 0 && (delay - headDelay < 0))
			//将delay的值设置为Long.MAX_VALUE + headDelay
			delay = Long.MAX_VALUE + headDelay;
	}
	//返回延迟时间
	return delay;
}
```



通过对overflowFree方法的源码分析，可以看出overflowFree方法本质上就是为了限制队列中的所有节点的延迟时间在Long.MAX_VALUE值之内，防止在ScheduledFutureTask类中的compareTo方法中溢出。

ScheduledFutureTask类中的compareTo方法的源码如下所示。

```java
public int compareTo(Delayed other) {
	if (other == this) // compare zero if same object
		return 0;
	if (other instanceof ScheduledFutureTask) {
		ScheduledFutureTask<?> x = (ScheduledFutureTask<?>)other;
		long diff = time - x.time;
		if (diff < 0)
			return -1;
		else if (diff > 0)
			return 1;
		else if (sequenceNumber < x.sequenceNumber)
			return -1;
		else
			return 1;
	}
	long diff = getDelay(NANOSECONDS) - other.getDelay(NANOSECONDS);
	return (diff < 0) ? -1 : (diff > 0) ? 1 : 0;
}
```



compareTo方法的主要作用就是对各延迟任务进行排序，距离下次执行时间靠前的任务就排在前面。

### delayedExecute方法

delayedExecute方法是ScheduledThreadPoolExecutor类中延迟执行任务的方法，源代码如下所示。

```java
private void delayedExecute(RunnableScheduledFuture<?> task) {
	//如果当前线程池已经关闭
	//则执行线程池的拒绝策略
	if (isShutdown())
		reject(task);
	//线程池没有关闭
	else {
		//将任务添加到阻塞队列中
		super.getQueue().add(task);
		//如果当前线程池是SHUTDOWN状态
		//并且当前线程池状态下不能执行任务
		//并且成功从阻塞队列中移除任务
		if (isShutdown() &&
			!canRunInCurrentRunState(task.isPeriodic()) &&
			remove(task))
			//取消任务的执行，但不会中断执行中的任务
			task.cancel(false);
		else
			//调用ThreadPoolExecutor类中的ensurePrestart()方法
			ensurePrestart();
	}
}
```



可以看到在delayedExecute方法内部调用了canRunInCurrentRunState方法，canRunInCurrentRunState方法的源码实现如下所示。

```java
boolean canRunInCurrentRunState(boolean periodic) {
	return isRunningOrShutdown(periodic ? continueExistingPeriodicTasksAfterShutdown : executeExistingDelayedTasksAfterShutdown);
}
```



可以看到canRunInCurrentRunState方法的逻辑比较简单，就是判断线程池当前状态下能够执行任务。

另外，在delayedExecute方法内部还调用了ThreadPoolExecutor类中的ensurePrestart()方法，接下来，我们看下ThreadPoolExecutor类中的ensurePrestart()方法的实现，如下所示。

```java
void ensurePrestart() {
	int wc = workerCountOf(ctl.get());
	if (wc < corePoolSize)
		addWorker(null, true);
	else if (wc == 0)
		addWorker(null, false);
}
```



在ThreadPoolExecutor类中的ensurePrestart()方法中，首先获取当前线程池中线程的数量，如果线程数量小于corePoolSize则调用addWorker方法传递null和true，如果线程数量为0，则调用addWorker方法传递null和false。

关于addWork()方法的源码解析，大家可以参考【高并发专题】中的《[高并发之——通过ThreadPoolExecutor类的源码深度解析线程池执行任务的核心流程](/md/concurrent/source/2020-03-30-010-通过ThreadPoolExecutor类的源码深度解析线程池执行任务的核心流程.md)》一文，这里，不再赘述。

### reExecutePeriodic方法

reExecutePeriodic方法的源代码如下所示。

```java
void reExecutePeriodic(RunnableScheduledFuture<?> task) {
	//线程池当前状态下能够执行任务
	if (canRunInCurrentRunState(true)) {
		//将任务放入队列
		super.getQueue().add(task);
		//线程池当前状态下不能执行任务，并且成功移除任务
		if (!canRunInCurrentRunState(true) && remove(task))
			//取消任务
			task.cancel(false);
		else
			//调用ThreadPoolExecutor类的ensurePrestart()方法
			ensurePrestart();
	}
}
```



总体来说reExecutePeriodic方法的逻辑比较简单，但是，这里需要注意和delayedExecute方法的不同点：调用reExecutePeriodic方法的时候已经执行过一次任务，所以，并不会触发线程池的拒绝策略；传入reExecutePeriodic方法的任务一定是周期性的任务。

### onShutdown方法

onShutdown方法是ThreadPoolExecutor类中的钩子函数，它是在ThreadPoolExecutor类中的shutdown方法中调用的，而在ThreadPoolExecutor类中的onShutdown方法是一个空方法，如下所示。

```java
void onShutdown() {
}
```



ThreadPoolExecutor类中的onShutdown方法交由子类实现，所以ScheduledThreadPoolExecutor类覆写了onShutdown方法，实现了具体的逻辑，ScheduledThreadPoolExecutor类中的onShutdown方法的源码实现如下所示。

```java
@Override
void onShutdown() {
	//获取队列
	BlockingQueue<Runnable> q = super.getQueue();
	//在线程池已经调用shutdown方法后，是否继续执行现有延迟任务
	boolean keepDelayed = getExecuteExistingDelayedTasksAfterShutdownPolicy();
	//在线程池已经调用shutdown方法后，是否继续执行现有定时任务
	boolean keepPeriodic = getContinueExistingPeriodicTasksAfterShutdownPolicy();
	//在线程池已经调用shutdown方法后，不继续执行现有延迟任务和定时任务
	if (!keepDelayed && !keepPeriodic) {
		//遍历队列中的所有任务
		for (Object e : q.toArray())
			//取消任务的执行
			if (e instanceof RunnableScheduledFuture<?>)
				((RunnableScheduledFuture<?>) e).cancel(false);
		//清空队列
		q.clear();
	}
	//在线程池已经调用shutdown方法后，继续执行现有延迟任务和定时任务
	else {
		//遍历队列中的所有任务
		for (Object e : q.toArray()) {
			//当前任务是RunnableScheduledFuture类型
			if (e instanceof RunnableScheduledFuture) {
				//将任务强转为RunnableScheduledFuture类型
				RunnableScheduledFuture<?> t = (RunnableScheduledFuture<?>)e;
				//在线程池调用shutdown方法后不继续的延迟任务或周期任务
				//则从队列中删除并取消任务
				if ((t.isPeriodic() ? !keepPeriodic : !keepDelayed) ||
					t.isCancelled()) {
					if (q.remove(t))
						t.cancel(false);
				}
			}
		}
	}
	//最终调用tryTerminate()方法
	tryTerminate();
}
```



ScheduledThreadPoolExecutor类中的onShutdown方法的主要逻辑就是先判断线程池调用shutdown方法后，是否继续执行现有的延迟任务和定时任务，如果不再执行，则取消任务并清空队列；如果继续执行，将队列中的任务强转为RunnableScheduledFuture对象之后，从队列中删除并取消任务。大家需要好好理解这两种处理方式。最后调用ThreadPoolExecutor类的tryTerminate方法。有关ThreadPoolExecutor类的tryTerminate方法的源码解析，大家可以参考【高并发专题】中的《[高并发之——通过源码深度分析线程池中Worker线程的执行流程](/md/concurrent/source/2020-03-30-011-通过源码深度分析线程池中Worker线程的执行流程.md)》一文，这里不再赘述。

至此，ScheduledThreadPoolExecutor类中的核心方法的源代码，我们就分析完了。

**好了，今天就到这儿吧，我是冰河，我们下期见~~**

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发编程技术。


最后，附上并发编程需要掌握的核心技能知识图，祝大家在学习并发编程时，少走弯路。

![](https://img-blog.csdnimg.cn/20200322144644983.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2wxMDI4Mzg2ODA0,size_16,color_FFFFFF,t_70#pic_center)

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)

