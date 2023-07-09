---
layout: post
category: binghe-code-life
title: 第11章：Stream API的终止操作
tagline: by 冰河
tag: [java8,binghe-code-java8]
excerpt: 如果你出去面试，面试官问了你关于Java8 Stream API的一些问题，比如：Java8中创建Stream流有哪几种方式？（可以参见：《[强大的Stream API，你了解吗](/md/java/java8/2022-03-31-009-强大的Stream API，你了解吗.md)》）Java8中的Stream API有哪些中间操作？（可以参见：《[Stream API有哪些中间操作,看完你也可以吊打面试官](/md/java/java8/2022-03-31-010-Stream API有哪些中间操作,看完你也可以吊打面试官.md)》）如果你都很好的回答了这些问题，那么，面试官可能又会问你：Java8中的Stream API有哪些终止操作呢？没错，这就是Java8中有关Stream API的灵魂三问！不要觉得是面试官在为难你，只有你掌握了这些细节，你就可以反过来吊打面试官了！
lock: need
---



# 《Java8新特性》第11章：Stream API的终止操作

## 写在前面

> 如果你出去面试，面试官问了你关于Java8 Stream API的一些问题，比如：Java8中创建Stream流有哪几种方式？（可以参见：《[强大的Stream API，你了解吗](/md/java/java8/2022-03-31-009-强大的Stream API，你了解吗.md)》）Java8中的Stream API有哪些中间操作？（可以参见：《[Stream API有哪些中间操作,看完你也可以吊打面试官](/md/java/java8/2022-03-31-010-Stream API有哪些中间操作,看完你也可以吊打面试官.md)》）如果你都很好的回答了这些问题，那么，面试官可能又会问你：Java8中的Stream API有哪些终止操作呢？没错，这就是Java8中有关Stream API的灵魂三问！不要觉得是面试官在为难你，只有你掌握了这些细节，你就可以反过来吊打面试官了！

## Stream的终止操作

终端操作会从流的流水线生成结果。其结果可以是任何不是流的值，例如： List、 Integer、Double、String等等，甚至是 void 。  

在Java8中，Stream的终止操作可以分为：查找与匹配、规约和收集。接下来，我们就分别简单说明下这些终止操作。

## 查找与匹配

Stream API中有关查找与匹配的方法如下表所示。

| 方法                   | 描述                                                         |
| ---------------------- | ------------------------------------------------------------ |
| allMatch(Predicate p)  | 检查是否匹配所有元素                                         |
| anyMatch(Predicate p)  | 检查是否至少匹配一个元素                                     |
| noneMatch(Predicate p) | 检查是否没有匹配所有元素                                     |
| findFirst()            | 返回第一个元素                                               |
| findAny()              | 返回当前流中的任意元素                                       |
| count()                | 返回流中元素总数                                             |
| max(Comparator c)      | 返回流中最大值                                               |
| min(Comparator c)      | 返回流中最小值                                               |
| forEach(Consumer c)    | 内部迭代(使用 Collection 接口需要用户去做迭代，称为外部迭代。相反， Stream API 使用内部迭代) |

同样的，我们对每个重要的方法进行简单的示例说明，这里，我们首先建立一个Employee类，Employee类的定义如下所示。

```java
@Data
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Employee implements Serializable {
    private static final long serialVersionUID = -9079722457749166858L;
    private String name;
    private Integer age;
    private Double salary;
    private Stauts stauts;
    public enum Stauts{
        WORKING,
        SLEEPING,
        VOCATION
    }
}
```

接下来，我们在测试类中定义一个用于测试的集合employees，如下所示。

```java
protected List<Employee> employees = Arrays.asList(
    new Employee("张三", 18, 9999.99, Employee.Stauts.SLEEPING),
    new Employee("李四", 38, 5555.55, Employee.Stauts.WORKING),
    new Employee("王五", 60, 6666.66, Employee.Stauts.WORKING),
    new Employee("赵六", 8, 7777.77, Employee.Stauts.SLEEPING),
    new Employee("田七", 58, 3333.33, Employee.Stauts.VOCATION)
);
```

好了，准备工作就绪了。接下来，我们就开始测试Stream的每个终止方法。

### 1.allMatch()

allMatch()方法表示检查是否匹配所有元素。其在Stream接口中的定义如下所示。

```java
boolean allMatch(Predicate<? super T> predicate);
```

我们可以通过类似如下示例来使用allMatch()方法。

```java
boolean match = employees.stream().allMatch((e) -> Employee.Stauts.SLEEPING.equals(e.getStauts()));
System.out.println(match);
```

**注意：使用allMatch()方法时，只有所有的元素都匹配条件时，allMatch()方法才会返回true。**

### 2.anyMatch()方法

anyMatch方法表示检查是否至少匹配一个元素。其在Stream接口中的定义如下所示。

```java
boolean anyMatch(Predicate<? super T> predicate);
```

我们可以通过类似如下示例来使用anyMatch()方法。

```java
boolean match = employees.stream().anyMatch((e) -> Employee.Stauts.SLEEPING.equals(e.getStauts()));
System.out.println(match);
```

**注意：使用anyMatch()方法时，只要有任意一个元素符合条件，anyMatch()方法就会返回true。**

### 3.noneMatch()方法

noneMatch()方法表示检查是否没有匹配所有元素。其在Stream接口中的定义如下所示。

```java
boolean noneMatch(Predicate<? super T> predicate);
```

我们可以通过类似如下示例来使用noneMatch()方法。

```java
boolean match = employees.stream().noneMatch((e) -> Employee.Stauts.SLEEPING.equals(e.getStauts()));
System.out.println(match);
```

**注意：使用noneMatch()方法时，只有所有的元素都不符合条件时，noneMatch()方法才会返回true。**

### 4.findFirst()方法

findFirst()方法表示返回第一个元素。其在Stream接口中的定义如下所示。

```java
Optional<T> findFirst();
```

我们可以通过类似如下示例来使用findFirst()方法。

```java
Optional<Employee> op = employees.stream().sorted((e1, e2) -> Double.compare(e1.getSalary(), e2.getSalary())).findFirst();
System.out.println(op.get());
```

### 5.findAny()方法

findAny()方法表示返回当前流中的任意元素。其在Stream接口中的定义如下所示。

```java
Optional<T> findAny();
```

我们可以通过类似如下示例来使用findAny()方法。

```java
Optional<Employee> op = employees.stream().filter((e) -> Employee.Stauts.WORKING.equals(e.getStauts())).findFirst();
System.out.println(op.get());
```

### 6.count()方法

count()方法表示返回流中元素总数。其在Stream接口中的定义如下所示。

```java
long count();
```

我们可以通过类似如下示例来使用count()方法。

```java
long count = employees.stream().count();
System.out.println(count);
```

### 7.max()方法

max()方法表示返回流中最大值。其在Stream接口中的定义如下所示。

```java
Optional<T> max(Comparator<? super T> comparator);
```

我们可以通过类似如下示例来使用max()方法。

```java
Optional<Employee> op = employees.stream().max((e1, e2) -> Double.compare(e1.getSalary(), e2.getSalary()));
System.out.println(op.get());
```

### 8.min()方法

min()方法表示返回流中最小值。其在Stream接口中的定义如下所示。

```java
Optional<T> min(Comparator<? super T> comparator);
```

我们可以通过类似如下示例来使用min()方法。

```java
Optional<Double> op = employees.stream().map(Employee::getSalary).min(Double::compare);
System.out.println(op.get());
```

### 9.forEach()方法

forEach()方法表示内部迭代(使用 Collection 接口需要用户去做迭代，称为外部迭代。相反， Stream API 使用内部迭代)。其在Stream接口内部的定义如下所示。

```java
void forEach(Consumer<? super T> action);
```

我们可以通过类似如下示例来使用forEach()方法。

```java
employees.stream().forEach(System.out::println);
```

## 规约

Stream API中有关规约的方法如下表所示。

| 方法                             | 描述                                                      |
| -------------------------------- | --------------------------------------------------------- |
| reduce(T iden, BinaryOperator b) | 可以将流中元素反复结合起来，得到一个值。 返回 T           |
| reduce(BinaryOperator b)         | 可以将流中元素反复结合起来，得到一个值。 返回 Optional<T> |

reduce()方法在Stream接口中的定义如下所示。

```java
T reduce(T identity, BinaryOperator<T> accumulator);
Optional<T> reduce(BinaryOperator<T> accumulator);
<U> U reduce(U identity, BiFunction<U, ? super T, U> accumulator, BinaryOperator<U> combiner);
```

我们可以通过类似如下示例来使用reduce方法。

```java
List<Integer> list = Arrays.asList(1,2,3,4,5,6,7,8,9,10);
Integer sum = list.stream().reduce(0, (x, y) -> x + y);
System.out.println(sum);
System.out.println("----------------------------------------");
Optional<Double> op = employees.stream().map(Employee::getSalary).reduce(Double::sum);
System.out.println(op.get());
```

我们也可以搜索employees列表中“张”出现的次数。

```java
 Optional<Integer> sum = employees.stream()
   .map(Employee::getName)
   .flatMap(TestStreamAPI1::filterCharacter)
   .map((ch) -> {
    if(ch.equals('六'))
     return 1;
    else
     return 0;
   }).reduce(Integer::sum);
  System.out.println(sum.get());
```

**注意：上述例子使用了硬编码的方式来累加某个具体值，大家在实际工作中再优化代码。**

## 收集

| 方法                 | 描述                                                         |
| -------------------- | ------------------------------------------------------------ |
| collect(Collector c) | 将流转换为其他形式。接收一个 Collector接口的实现，用于给Stream中元素做汇总的方法 |

collect()方法在Stream接口中的定义如下所示。

```java
<R> R collect(Supplier<R> supplier,
              BiConsumer<R, ? super T> accumulator,
              BiConsumer<R, R> combiner);

<R, A> R collect(Collector<? super T, A, R> collector);
```

我们可以通过类似如下示例来使用collect方法。

```java
Optional<Double> max = employees.stream()
   .map(Employee::getSalary)
   .collect(Collectors.maxBy(Double::compare));
  System.out.println(max.get());
  Optional<Employee> op = employees.stream()
   .collect(Collectors.minBy((e1, e2) -> Double.compare(e1.getSalary(), e2.getSalary())));
  System.out.println(op.get());
  Double sum = employees.stream().collect(Collectors.summingDouble(Employee::getSalary));
  System.out.println(sum);
  Double avg = employees.stream().collect(Collectors.averagingDouble(Employee::getSalary));
  System.out.println(avg);
  Long count = employees.stream().collect(Collectors.counting());
  System.out.println(count);
  System.out.println("--------------------------------------------");
  DoubleSummaryStatistics dss = employees.stream()
   .collect(Collectors.summarizingDouble(Employee::getSalary));
  System.out.println(dss.getMax());
```





## 如何收集Stream流？

Collector接口中方法的实现决定了如何对流执行收集操作(如收集到 List、 Set、 Map)。 Collectors实用类提供了很多静态方法，可以方便地创建常见收集器实例， 具体方法与实例如下表：  

| 方法              | 返回类型              | 作用                                                         |
| ----------------- | --------------------- | ------------------------------------------------------------ |
| toList            | List<T>               | 把流中元素收集到List                                         |
| toSet             | Set<T>                | 把流中元素收集到Set                                          |
| toCollection      | Collection<T>         | 把流中元素收集到创建的集合                                   |
| counting          | Long                  | 计算流中元素的个数                                           |
| summingInt        | Integer               | 对流中元素的整数属性求和                                     |
| averagingInt      | Double                | 计算流中元素Integer属性的平均 值                             |
| summarizingInt    | IntSummaryStatistics  | 收集流中Integer属性的统计值。 如：平均值                     |
| joining           | String                | 连接流中每个字符串                                           |
| maxBy             | Optional<T>           | 根据比较器选择最大值                                         |
| minBy             | Optional<T>           | 根据比较器选择最小值                                         |
| reducing          | 归约产生的类型        | 从一个作为累加器的初始值 开始，利用BinaryOperator与 流中元素逐个结合，从而归 约成单个值 |
| collectingAndThen | 转换函数返回的类型    | 包裹另一个收集器，对其结 果转换函数                          |
| groupingBy        | Map<K, List<T>>       | 根据某属性值对流分组，属 性为K，结果为V                      |
| partitioningBy    | Map<Boolean, List<T>> | 根据true或false进行分区                                      |

每个方法对应的使用示例如下表所示。

| 方法              | 使用示例                                                     |
| ----------------- | ------------------------------------------------------------ |
| toList            | List<Employee> employees= list.stream().collect(Collectors.toList()); |
| toSet             | Set<Employee> employees= list.stream().collect(Collectors.toSet()); |
| toCollection      | Collection<Employee> employees=list.stream().collect(Collectors.toCollection(ArrayList::new)); |
| counting          | long count = list.stream().collect(Collectors.counting());   |
| summingInt        | int total=list.stream().collect(Collectors.summingInt(Employee::getSalary)); |
| averagingInt      | double avg= list.stream().collect(Collectors.averagingInt(Employee::getSalary)) |
| summarizingInt    | IntSummaryStatistics iss= list.stream().collect(Collectors.summarizingInt(Employee::getSalary)); |
| Collectors        | String str= list.stream().map(Employee::getName).collect(Collectors.joining()); |
| maxBy             | Optional<Emp>max= list.stream().collect(Collectors.maxBy(comparingInt(Employee::getSalary)))； |
| minBy             | Optional<Emp> min = list.stream().collect(Collectors.minBy(comparingInt(Employee::getSalary))); |
| reducing          | int total=list.stream().collect(Collectors.reducing(0, Employee::getSalar, Integer::sum)); |
| collectingAndThen | int how= list.stream().collect(Collectors.collectingAndThen(Collectors.toList(), List::size)); |
| groupingBy        | Map<Emp.Status, List<Emp>> map= list.stream() .collect(Collectors.groupingBy(Employee::getStatus)); |
| partitioningBy    | Map<Boolean,List<Emp>>vd= list.stream().collect(Collectors.partitioningBy(Employee::getManage)); |

```java
public void test4(){
    Optional<Double> max = emps.stream()
        .map(Employee::getSalary)
        .collect(Collectors.maxBy(Double::compare));
    System.out.println(max.get());

    Optional<Employee> op = emps.stream()
        .collect(Collectors.minBy((e1, e2) -> Double.compare(e1.getSalary(), e2.getSalary())));

    System.out.println(op.get());

    Double sum = emps.stream()
        .collect(Collectors.summingDouble(Employee::getSalary));

    System.out.println(sum);

    Double avg = emps.stream()
        .collect(Collecors.averagingDouble(Employee::getSalary));
    System.out.println(avg);
    Long count = emps.stream()
        .collect(Collectors.counting());

    DoubleSummaryStatistics dss = emps.stream()
        .collect(Collectors.summarizingDouble(Employee::getSalary));
    System.out.println(dss.getMax());
 
```


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