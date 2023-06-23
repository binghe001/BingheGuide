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


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！

![](https://img-blog.csdnimg.cn/20200906013715889.png)