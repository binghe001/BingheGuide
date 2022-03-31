---
layout: post
category: binghe-code-concurrent
title: 一文秒懂Happens-Before原则
tagline: by 冰河
tag: [concurrent,binghe-code-concurrent]
excerpt: 在并发编程中，Happens-Before原则是我们必须要掌握的，今天我们就一起来详细聊聊并发编程中的Happens-Before原则。
lock: need
---

# 【高并发】一文秒懂Happens-Before原则

**大家好，我是冰河~~**

在并发编程中，Happens-Before原则是我们必须要掌握的，今天我们就一起来详细聊聊并发编程中的Happens-Before原则。

在正式介绍Happens-Before原则之前，我们先来看一段代码。
**【示例一】**

```java
class VolatileExample {
  int x = 0;
  volatile boolean v = false;
  public void writer() {
    x = 42;
    v = true;
  }

  public void reader() {
    if (v == true) {
      //x的值是多少呢？
    }
  }
}
```

以上示例来源于：[http://www.cs.umd.edu/~pugh/java/memoryModel/jsr-133-faq.html#finalWrong](http://www.cs.umd.edu/~pugh/java/memoryModel/jsr-133-faq.html#finalWrong)

这里，假设线程A执行writer()方法，按照volatile会将v=true写入内存；线程B执行reader()方法，按照volatile，线程B会从内存中读取变量v，如果线程B读取到的变量v为true，那么，此时的变量x的值是多少呢？？

这个示例程序给人的直觉就是x的值为42，其实，x的值具体是多少和JDK的版本有关，如果使用的JDK版本低于1.5，则x的值可能为42，也可能为0。如果使用1.5及1.5以上版本的JDK，则x的值就是42。

看到这个，就会有人提出问题了？这是为什么呢？其实，答案就是在JDK1.5版本中的Java内存模型中引入了Happens-Before原则。

接下来，我们就结合案例程序来说明Java内存模型中的Happens-Before原则。

### 【原则一】程序次序规则

**在一个线程中，按照代码的顺序，前面的操作Happens-Before于后面的任意操作。**

例如【示例一】中的程序x=42会在v=true之前执行。这个规则比较符合单线程的思维：在同一个线程中，程序在前面对某个变量的修改一定是对后续操作可见的。

### 【原则二】volatile变量规则

**对一个volatile变量的写操作，Happens-Before于后续对这个变量的读操作。**

也就是说，对一个使用了volatile变量的写操作，先行发生于后面对这个变量的读操作。这个需要大家重点理解。

### 【原则三】传递规则

**如果A Happens-Before B，并且B Happens-Before C，则A Happens-Before C。**

我们结合【原则一】、【原则二】和【原则三】再来看【示例一】程序，此时，我们可以得出如下结论：

（1）x = 42 Happens-Before 写变量v = true，符合【原则一】程序次序规则。

（2）写变量v = true Happens-Before 读变量v = true，符合【原则二】volatile变量规则。

再根据【原则三】传递规则，我们可以得出结论：x = 42 Happens-Before 读变量v=true。

也就是说，如果线程B读取到了v=true，那么，线程A设置的x = 42对线程B就是可见的。换句话说，就是此时的线程B能够访问到x=42。

其实，Java 1.5版本的 java.util.concurrent并发工具就是靠volatile语义来实现可见性的。

### 【原则四】锁定规则

**对一个锁的解锁操作 Happens-Before于后续对这个锁的加锁操作。**

例如，下面的代码，在进入synchronized代码块之前，会自动加锁，在代码块执行完毕后，会自动释放锁。

**【示例二】**

```java
public class Test{
    private int x = 0;
    public void initX{
        synchronized(this){ //自动加锁
            if(this.x < 10){
                this.x = 10;
            }
        } //自动释放锁
    }
}
```

我们可以这样理解这段程序：假设变量x的值为10，线程A执行完synchronized代码块之后将x变量的值修改为10，并释放synchronized锁。当线程B进入synchronized代码块时，能够获取到线程A对x变量的写操作，也就是说，线程B访问到的x变量的值为10。

### 【原则五】线程启动规则

**如果线程A调用线程B的start()方法来启动线程B，则start()操作Happens-Before于线程B中的任意操作。**

我们也可以这样理解线程启动规则：线程A启动线程B之后，线程B能够看到线程A在启动线程B之前的操作。

我们来看下面的代码。

**【示例三】**

```java
//在线程A中初始化线程B
Thread threadB = new Thread(()->{
    //此处的变量x的值是多少呢？答案是100
});
//线程A在启动线程B之前将共享变量x的值修改为100
x = 100;
//启动线程B
threadB.start();
```

上述代码是在线程A中执行的一个代码片段，根据【原则五】线程的启动规则，线程A启动线程B之后，线程B能够看到线程A在启动线程B之前的操作，在线程B中访问到的x变量的值为100。

### 【原则六】线程终结规则

**线程A等待线程B完成（在线程A中调用线程B的join()方法实现），当线程B完成后（线程A调用线程B的join()方法返回），则线程A能够访问到线程B对共享变量的操作。**

例如，在线程A中进行的如下操作。

**【示例四】**

```java
Thread threadB = new Thread(()-{
    //在线程B中，将共享变量x的值修改为100
    x = 100;
});
//在线程A中启动线程B
threadB.start();
//在线程A中等待线程B执行完成
threadB.join();
//此处访问共享变量x的值为100
```

### 【原则七】线程中断规则

**对线程interrupt()方法的调用Happens-Before于被中断线程的代码检测到中断事件的发生。**

例如，下面的程序代码。在线程A中中断线程B之前，将共享变量x的值修改为100，则当线程B检测到中断事件时，访问到的x变量的值为100。

**【示例五】**

```java
    //在线程A中将x变量的值初始化为0
    private int x = 0;

    public void execute(){
        //在线程A中初始化线程B
        Thread threadB = new Thread(()->{
            //线程B检测自己是否被中断
            if (Thread.currentThread().isInterrupted()){
                //如果线程B被中断，则此时X的值为100
                System.out.println(x);
            }
        });
        //在线程A中启动线程B
        threadB.start();
        //在线程A中将共享变量X的值修改为100
        x = 100;
        //在线程A中中断线程B
        threadB.interrupt();
    }
```

### 【原则八】对象终结原则

**一个对象的初始化完成Happens-Before于它的finalize()方法的开始。**

例如，下面的程序代码。

**【示例六】**

```java
public class TestThread {

   public TestThread(){
       System.out.println("构造方法");
   }

    @Override
    protected void finalize() throws Throwable {
        System.out.println("对象销毁");
    }

    public static void main(String[] args){
        new TestThread();
        System.gc();
    }
}
```

运行结果如下所示。

```java
构造方法
对象销毁
```

**好了，今天就到这儿吧，我是冰河，我们下期见~~**

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)