---
layout: post
category: binghe-code-life
title: 关于Java8的Stream API，看这一篇就够了！！
tagline: by 冰河
tag: [java8,binghe-code-java8]
excerpt: Java8中有两大最为重要的改变。第一个是 Lambda 表达式；另外一个则是 Stream API(java.util.stream.*)  ，那什么是Stream API呢？Java8中的Stream又该如何使用呢？
lock: need
---

# 关于Java8的Stream API，看这一篇就够了！！

## 写在前面

> Java8中有两大最为重要的改变。第一个是 Lambda 表达式；另外一个则是 Stream API(java.util.stream.*)  ，那什么是Stream API呢？Java8中的Stream又该如何使用呢？

## 什么是Stream?

Java8中有两大最为重要的改变。第一个是 Lambda 表达式；另外一个则是 Stream API(java.util.stream.*)。

Stream 是 Java8 中处理集合的关键抽象概念，它可以指定你希望对集合进行的操作，可以执行非常复杂的查找、过滤和映射数据等操作。使用Stream API 对集合数据进行操作，就类似于使用 SQL 执行的数据库查询。也可以使用 Stream API 来并行执行操作。简而言之，Stream API 提供了一种高效且易于使用的处理数据的方式  

> 流是数据渠道，用于操作数据源（集合、数组等）所生成的元素序列。“集合讲的是数据，流讲的是计算！ ”  

**注意：**
① Stream 自己不会存储元素。
② Stream 不会改变源对象。相反，他们会返回一个持有结果的新Stream。
③ Stream 操作是延迟执行的。这意味着他们会等到需要结果的时候才执行。  

## Stream操作的三个步骤

* 创建 Stream

一个数据源（如： 集合、数组）， 获取一个流。

* 中间操作

一个中间操作链，对数据源的数据进行处理。

* 终止操作(终端操作)

一个终止操作，执行中间操作链，并产生结果 。

![](/images/java/java8/2022-03-31-008-001.jpg)

## 如何创建Stream?

Java8 中的 Collection 接口被扩展，提供了两个获取流的方法：

### 1.获取Stream

* default Stream<E> stream() : 返回一个顺序流

* default Stream<E> parallelStream() : 返回一个并行流  

### 2.由数组创建Stream

Java8 中的 Arrays 的静态方法 stream() 可以获取数组流：  

* static <T> Stream<T> stream(T[] array): 返回一个流  

重载形式，能够处理对应基本类型的数组：

* public static IntStream stream(int[] array)

* public static LongStream stream(long[] array)

* public static DoubleStream stream(double[] array)  

### 3.由值创建流

可以使用静态方法 Stream.of(), 通过显示值创建一个流。它可以接收任意数量的参数。  

* public static<T> Stream<T> of(T... values) : 返回一个流  

### 4.由函数创建流  

由函数创建流可以创建无限流。

可以使用静态方法 Stream.iterate() 和Stream.generate(), 创建无限流 。

* 迭代

public static<T> Stream<T> iterate(final T seed, final UnaryOperator<T> f)

* 生成

public static<T> Stream<T> generate(Supplier<T> s)  

## Stream的中间操作  

多个中间操作可以连接起来形成一个流水线，除非流水线上触发终止操作，否则中间操作不会执行任何的处理！而在终止操作时一次性全部处理，称为“惰性求值” 

### 1.筛选与切片  

![](/images/java/java8/2022-03-31-008-002.jpg)

### 2.映射  

![](/images/java/java8/2022-03-31-008-003.jpg)

### 3.排序  

![](/images/java/java8/2022-03-31-008-004.jpg)

## Stream 的终止操作  

终端操作会从流的流水线生成结果。其结果可以是任何不是流的值，例如： List、 Integer，甚至是 void 。  

### 1.查找与匹配

![](/images/java/java8/2022-03-31-008-005.jpg)

![](/images/java/java8/2022-03-31-008-006.jpg)

### 2.规约

![](/images/java/java8/2022-03-31-008-007.jpg)

### 3.收集

![](/images/java/java8/2022-03-31-008-008.jpg)

Collector 接口中方法的实现决定了如何对流执行收集操作(如收集到 List、 Set、 Map)。但是 Collectors 实用类提供了很多静态方法，可以方便地创建常见收集器实例， 具体方法与实例如下表  

![](/images/java/java8/2022-03-31-008-009.jpg)

![](/images/java/java8/2022-03-31-008-010.jpg)

## 并行流与串行流  

并行流就是把一个内容分成多个数据块，并用不同的线程分别处理每个数据块的流。

Java 8 中将并行进行了优化，我们可以很容易的对数据进行并行操作。 Stream API 可以声明性地通过 parallel() 与
sequential() 在并行流与顺序流之间进行切换  

## Fork/Join 框架  

### 1.简单概述

> Fork/Join 框架： 就是在必要的情况下，将一个大任务，进行拆分(fork)成若干个小任务（拆到不可再拆时），再将一个个的小任务运算的结果进行 join 汇总.  

![](/images/java/java8/2022-03-31-008-011.jpg)

### 2.Fork/Join 框架与传统线程池的区别  

采用 “工作窃取”模式（work-stealing）：
当执行新的任务时它可以将其拆分分成更小的任务执行，并将小任务加到线程队列中，然后再从一个随机线程的队列中偷一个并把它放在自己的队列中。

相对于一般的线程池实现,fork/join框架的优势体现在对其中包含的任务的处理方式上.在一般的线程池中,如果一个线程正在执行的任务由于某些原因无法继续运行,那么该线程会处于等待状态.而在fork/join框架实现中,如果某个子问题由于等待另外一个子问题的完成而无法继续运行.那么处理该子问题的线程会主动寻找其他尚未运行的子问题来执行.这种方式减少了线程的等待时间,提高了性能。  


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！

![](https://img-blog.csdnimg.cn/20200906013715889.png)








