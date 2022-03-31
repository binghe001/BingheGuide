---
layout: post
category: binghe-code-concurrent
title: SimpleDateFormat类到底为啥不是线程安全的？
tagline: by 冰河
tag: [concurrent,binghe-code-concurrent]
excerpt: 首先问下大家：你使用的SimpleDateFormat类还安全吗？为什么说SimpleDateFormat类不是线程安全的？带着问题从本文中寻求答案。
lock: need
---

# SimpleDateFormat类到底为啥不是线程安全的？（附六种解决方案，建议收藏）

**大家好，我是冰河~~**

**首先问下大家：你使用的SimpleDateFormat类还安全吗？为什么说SimpleDateFormat类不是线程安全的？带着问题从本文中寻求答案。**

提起SimpleDateFormat类，想必做过Java开发的童鞋都不会感到陌生。没错，它就是Java中提供的日期时间的转化类。这里，为什么说SimpleDateFormat类有线程安全问题呢？有些小伙伴可能会提出疑问：我们生产环境上一直在使用SimpleDateFormat类来解析和格式化日期和时间类型的数据，一直都没有问题啊！我的回答是：没错，那是因为你们的系统达不到SimpleDateFormat类出现问题的并发量，也就是说你们的系统没啥负载！

接下来，我们就一起看下在高并发下SimpleDateFormat类为何会出现安全问题，以及如何解决SimpleDateFormat类的安全问题。

## 重现SimpleDateFormat类的线程安全问题 

为了重现SimpleDateFormat类的线程安全问题，一种比较简单的方式就是使用线程池结合Java并发包中的CountDownLatch类和Semaphore类来重现线程安全问题。

**有关CountDownLatch类和Semaphore类的具体用法和底层原理与源码解析在【高并发专题】后文会深度分析。这里，大家只需要知道CountDownLatch类可以使一个线程等待其他线程各自执行完毕后再执行。而Semaphore类可以理解为一个计数信号量，必须由获取它的线程释放，经常用来限制访问某些资源的线程数量，例如限流等。**

好了，先来看下重现SimpleDateFormat类的线程安全问题的代码，如下所示。

```java
package io.binghe.concurrent.lab06;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * @author binghe
 * @version 1.0.0
 * @description 测试SimpleDateFormat的线程不安全问题
 */
public class SimpleDateFormatTest01 {
    //执行总次数
    private static final int EXECUTE_COUNT = 1000;
    //同时运行的线程数量
    private static final int THREAD_COUNT = 20;
    //SimpleDateFormat对象
    private static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    public static void main(String[] args) throws InterruptedException {
        final Semaphore semaphore = new Semaphore(THREAD_COUNT);
        final CountDownLatch countDownLatch = new CountDownLatch(EXECUTE_COUNT);
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < EXECUTE_COUNT; i++){
            executorService.execute(() -> {
                try {
                    semaphore.acquire();
                    try {
                        simpleDateFormat.parse("2020-01-01");
                    } catch (ParseException e) {
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }catch (NumberFormatException e){
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }
                    semaphore.release();
                } catch (InterruptedException e) {
                    System.out.println("信号量发生错误");
                    e.printStackTrace();
                    System.exit(1);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        System.out.println("所有线程格式化日期成功");
    }
}
```

可以看到，在SimpleDateFormatTest01类中，首先定义了两个常量，一个是程序执行的总次数，一个是同时运行的线程数量。程序中结合线程池和CountDownLatch类与Semaphore类来模拟高并发的业务场景。其中，有关日期转化的代码只有如下一行。

```java
simpleDateFormat.parse("2020-01-01");
```

当程序捕获到异常时，打印相关的信息，并退出整个程序的运行。当程序正确运行后，会打印“所有线程格式化日期成功”。

运行程序输出的结果信息如下所示。

```bash
Exception in thread "pool-1-thread-4" Exception in thread "pool-1-thread-1" Exception in thread "pool-1-thread-2" 线程：pool-1-thread-7 格式化日期失败
线程：pool-1-thread-9 格式化日期失败
线程：pool-1-thread-10 格式化日期失败
Exception in thread "pool-1-thread-3" Exception in thread "pool-1-thread-5" Exception in thread "pool-1-thread-6" 线程：pool-1-thread-15 格式化日期失败
线程：pool-1-thread-21 格式化日期失败
Exception in thread "pool-1-thread-23" 线程：pool-1-thread-16 格式化日期失败
线程：pool-1-thread-11 格式化日期失败
java.lang.ArrayIndexOutOfBoundsException
线程：pool-1-thread-27 格式化日期失败
	at java.lang.System.arraycopy(Native Method)
	at java.lang.AbstractStringBuilder.append(AbstractStringBuilder.java:597)
	at java.lang.StringBuffer.append(StringBuffer.java:367)
	at java.text.DigitList.getLong(DigitList.java:191)线程：pool-1-thread-25 格式化日期失败

	at java.text.DecimalFormat.parse(DecimalFormat.java:2084)
	at java.text.SimpleDateFormat.subParse(SimpleDateFormat.java:1869)
	at java.text.SimpleDateFormat.parse(SimpleDateFormat.java:1514)
线程：pool-1-thread-14 格式化日期失败
	at java.text.DateFormat.parse(DateFormat.java:364)
	at io.binghe.concurrent.lab06.SimpleDateFormatTest01.lambda$main$0(SimpleDateFormatTest01.java:47)
线程：pool-1-thread-13 格式化日期失败	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)

	at java.lang.Thread.run(Thread.java:748)
java.lang.NumberFormatException: For input string: ""
	at java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
线程：pool-1-thread-20 格式化日期失败	at java.lang.Long.parseLong(Long.java:601)
	at java.lang.Long.parseLong(Long.java:631)

	at java.text.DigitList.getLong(DigitList.java:195)
	at java.text.DecimalFormat.parse(DecimalFormat.java:2084)
	at java.text.SimpleDateFormat.subParse(SimpleDateFormat.java:2162)
	at java.text.SimpleDateFormat.parse(SimpleDateFormat.java:1514)
	at java.text.DateFormat.parse(DateFormat.java:364)
	at io.binghe.concurrent.lab06.SimpleDateFormatTest01.lambda$main$0(SimpleDateFormatTest01.java:47)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
	at java.lang.Thread.run(Thread.java:748)
java.lang.NumberFormatException: For input string: ""
	at java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
	at java.lang.Long.parseLong(Long.java:601)
	at java.lang.Long.parseLong(Long.java:631)
	at java.text.DigitList.getLong(DigitList.java:195)
	at java.text.DecimalFormat.parse(DecimalFormat.java:2084)
	at java.text.SimpleDateFormat.subParse(SimpleDateFormat.java:1869)
	at java.text.SimpleDateFormat.parse(SimpleDateFormat.java:1514)
	at java.text.DateFormat.parse(DateFormat.java:364)

Process finished with exit code 1
```

说明，在高并发下使用SimpleDateFormat类格式化日期时抛出了异常，SimpleDateFormat类不是线程安全的！！！

接下来，我们就看下，SimpleDateFormat类为何不是线程安全的。

## SimpleDateFormat类为何不是线程安全的？

那么，接下来，我们就一起来看看真正引起SimpleDateFormat类线程不安全的根本原因。

通过查看SimpleDateFormat类的源码，我们得知：SimpleDateFormat是继承自DateFormat类，DateFormat类中维护了一个全局的Calendar变量，如下所示。

```java
/**
  * The {@link Calendar} instance used for calculating the date-time fields
  * and the instant of time. This field is used for both formatting and
  * parsing.
  *
  * <p>Subclasses should initialize this field to a {@link Calendar}
  * appropriate for the {@link Locale} associated with this
  * <code>DateFormat</code>.
  * @serial
  */
protected Calendar calendar;
```

从注释可以看出，这个Calendar对象既用于格式化也用于解析日期时间。接下来，我们再查看parse()方法接近最后的部分。

```java
@Override
public Date parse(String text, ParsePosition pos){
    ################此处省略N行代码##################
    Date parsedDate;
    try {
        parsedDate = calb.establish(calendar).getTime();
        // If the year value is ambiguous,
        // then the two-digit year == the default start year
        if (ambiguousYear[0]) {
            if (parsedDate.before(defaultCenturyStart)) {
                parsedDate = calb.addYear(100).establish(calendar).getTime();
            }
        }
    }
    // An IllegalArgumentException will be thrown by Calendar.getTime()
    // if any fields are out of range, e.g., MONTH == 17.
    catch (IllegalArgumentException e) {
        pos.errorIndex = start;
        pos.index = oldStart;
        return null;
    }
    return parsedDate;
}
```

可见，最后的返回值是通过调用CalendarBuilder.establish()方法获得的，而这个方法的参数正好就是前面的Calendar对象。

接下来，我们再来看看CalendarBuilder.establish()方法，如下所示。

```java
Calendar establish(Calendar cal) {
    boolean weekDate = isSet(WEEK_YEAR)
        && field[WEEK_YEAR] > field[YEAR];
    if (weekDate && !cal.isWeekDateSupported()) {
        // Use YEAR instead
        if (!isSet(YEAR)) {
            set(YEAR, field[MAX_FIELD + WEEK_YEAR]);
        }
        weekDate = false;
    }

    cal.clear();
    // Set the fields from the min stamp to the max stamp so that
    // the field resolution works in the Calendar.
    for (int stamp = MINIMUM_USER_STAMP; stamp < nextStamp; stamp++) {
        for (int index = 0; index <= maxFieldIndex; index++) {
            if (field[index] == stamp) {
                cal.set(index, field[MAX_FIELD + index]);
                break;
            }
        }
    }

    if (weekDate) {
        int weekOfYear = isSet(WEEK_OF_YEAR) ? field[MAX_FIELD + WEEK_OF_YEAR] : 1;
        int dayOfWeek = isSet(DAY_OF_WEEK) ?
            field[MAX_FIELD + DAY_OF_WEEK] : cal.getFirstDayOfWeek();
        if (!isValidDayOfWeek(dayOfWeek) && cal.isLenient()) {
            if (dayOfWeek >= 8) {
                dayOfWeek--;
                weekOfYear += dayOfWeek / 7;
                dayOfWeek = (dayOfWeek % 7) + 1;
            } else {
                while (dayOfWeek <= 0) {
                    dayOfWeek += 7;
                    weekOfYear--;
                }
            }
            dayOfWeek = toCalendarDayOfWeek(dayOfWeek);
        }
        cal.setWeekDate(field[MAX_FIELD + WEEK_YEAR], weekOfYear, dayOfWeek);
    }
    return cal;
}
```

在CalendarBuilder.establish()方法中先后调用了cal.clear()与cal.set()，也就是先清除cal对象中设置的值，再重新设置新的值。由于Calendar内部并没有线程安全机制，并且这两个操作也都不是原子性的，所以当多个线程同时操作一个SimpleDateFormat时就会引起cal的值混乱。类似地， **format()方法也存在同样的问题。**

因此， SimpleDateFormat类不是线程安全的根本原因是：**DateFormat类中的Calendar对象被多线程共享，而Calendar对象本身不支持线程安全。**

那么，得知了SimpleDateFormat类不是线程安全的，以及造成SimpleDateFormat类不是线程安全的原因，那么如何解决这个问题呢？接下来，我们就一起探讨下如何解决SimpleDateFormat类在高并发场景下的线程安全问题。

## 解决SimpleDateFormat类的线程安全问题

解决SimpleDateFormat类在高并发场景下的线程安全问题可以有多种方式，这里，就列举几个常用的方式供参考，**大家也可以在评论区给出更多的解决方案。**

### 1.局部变量法

最简单的一种方式就是将SimpleDateFormat类对象定义成局部变量，如下所示的代码，将SimpleDateFormat类对象定义在parse(String)方法的上面，即可解决问题。

```java
package io.binghe.concurrent.lab06;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * @author binghe
 * @version 1.0.0
 * @description 局部变量法解决SimpleDateFormat类的线程安全问题
 */
public class SimpleDateFormatTest02 {
    //执行总次数
    private static final int EXECUTE_COUNT = 1000;
    //同时运行的线程数量
    private static final int THREAD_COUNT = 20;

    public static void main(String[] args) throws InterruptedException {
        final Semaphore semaphore = new Semaphore(THREAD_COUNT);
        final CountDownLatch countDownLatch = new CountDownLatch(EXECUTE_COUNT);
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < EXECUTE_COUNT; i++){
            executorService.execute(() -> {
                try {
                    semaphore.acquire();
                    try {
                        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
                        simpleDateFormat.parse("2020-01-01");
                    } catch (ParseException e) {
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }catch (NumberFormatException e){
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }
                    semaphore.release();
                } catch (InterruptedException e) {
                    System.out.println("信号量发生错误");
                    e.printStackTrace();
                    System.exit(1);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        System.out.println("所有线程格式化日期成功");
    }
}
```

此时运行修改后的程序，输出结果如下所示。

```bash
所有线程格式化日期成功
```

至于在高并发场景下使用局部变量为何能解决线程的安全问题，会在【JVM专题】的JVM内存模式相关内容中深入剖析，这里不做过多的介绍了。

当然，这种方式在高并发下会创建大量的SimpleDateFormat类对象，影响程序的性能，所以，**这种方式在实际生产环境不太被推荐。**

### 2.synchronized锁方式

将SimpleDateFormat类对象定义成全局静态变量，此时所有线程共享SimpleDateFormat类对象，此时在调用格式化时间的方法时，对SimpleDateFormat对象进行同步即可，代码如下所示。

```java
package io.binghe.concurrent.lab06;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * @author binghe
 * @version 1.0.0
 * @description 通过Synchronized锁解决SimpleDateFormat类的线程安全问题
 */
public class SimpleDateFormatTest03 {
    //执行总次数
    private static final int EXECUTE_COUNT = 1000;
    //同时运行的线程数量
    private static final int THREAD_COUNT = 20;
    //SimpleDateFormat对象
    private static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    public static void main(String[] args) throws InterruptedException {
        final Semaphore semaphore = new Semaphore(THREAD_COUNT);
        final CountDownLatch countDownLatch = new CountDownLatch(EXECUTE_COUNT);
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < EXECUTE_COUNT; i++){
            executorService.execute(() -> {
                try {
                    semaphore.acquire();
                    try {
                        synchronized (simpleDateFormat){
                            simpleDateFormat.parse("2020-01-01");
                        }
                    } catch (ParseException e) {
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }catch (NumberFormatException e){
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }
                    semaphore.release();
                } catch (InterruptedException e) {
                    System.out.println("信号量发生错误");
                    e.printStackTrace();
                    System.exit(1);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        System.out.println("所有线程格式化日期成功");
    }
}
```

此时，解决问题的关键代码如下所示。

```java
synchronized (simpleDateFormat){
	simpleDateFormat.parse("2020-01-01");
}
```

运行程序，输出结果如下所示。

```java
所有线程格式化日期成功
```

需要注意的是，虽然这种方式能够解决SimpleDateFormat类的线程安全问题，但是由于在程序的执行过程中，为SimpleDateFormat类对象加上了synchronized锁，导致同一时刻只能有一个线程执行parse(String)方法。此时，会影响程序的执行性能，在要求高并发的生产环境下，**此种方式也是不太推荐使用的。**

### 3.Lock锁方式

Lock锁方式与synchronized锁方式实现原理相同，都是在高并发下通过JVM的锁机制来保证程序的线程安全。通过Lock锁方式解决问题的代码如下所示。

```java
package io.binghe.concurrent.lab06;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author binghe
 * @version 1.0.0
 * @description 通过Lock锁解决SimpleDateFormat类的线程安全问题
 */
public class SimpleDateFormatTest04 {
    //执行总次数
    private static final int EXECUTE_COUNT = 1000;
    //同时运行的线程数量
    private static final int THREAD_COUNT = 20;
    //SimpleDateFormat对象
    private static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
    //Lock对象
    private static Lock lock = new ReentrantLock();

    public static void main(String[] args) throws InterruptedException {
        final Semaphore semaphore = new Semaphore(THREAD_COUNT);
        final CountDownLatch countDownLatch = new CountDownLatch(EXECUTE_COUNT);
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < EXECUTE_COUNT; i++){
            executorService.execute(() -> {
                try {
                    semaphore.acquire();
                    try {
                        lock.lock();
                        simpleDateFormat.parse("2020-01-01");
                    } catch (ParseException e) {
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }catch (NumberFormatException e){
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }finally {
                        lock.unlock();
                    }
                    semaphore.release();
                } catch (InterruptedException e) {
                    System.out.println("信号量发生错误");
                    e.printStackTrace();
                    System.exit(1);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        System.out.println("所有线程格式化日期成功");
    }
}
```

通过代码可以得知，首先，定义了一个Lock类型的全局静态变量作为加锁和释放锁的句柄。然后在simpleDateFormat.parse(String)代码之前通过lock.lock()加锁。这里需要注意的一点是：为防止程序抛出异常而导致锁不能被释放，一定要将释放锁的操作放到finally代码块中，如下所示。

```java
finally {
	lock.unlock();
}
```

运行程序，输出结果如下所示。

```bash
所有线程格式化日期成功
```

此种方式同样会影响高并发场景下的性能，**不太建议在高并发的生产环境使用。**

### 4.ThreadLocal方式

使用ThreadLocal存储每个线程拥有的SimpleDateFormat对象的副本，能够有效的避免多线程造成的线程安全问题，使用ThreadLocal解决线程安全问题的代码如下所示。

```java
package io.binghe.concurrent.lab06;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * @author binghe
 * @version 1.0.0
 * @description 通过ThreadLocal解决SimpleDateFormat类的线程安全问题
 */
public class SimpleDateFormatTest05 {
    //执行总次数
    private static final int EXECUTE_COUNT = 1000;
    //同时运行的线程数量
    private static final int THREAD_COUNT = 20;

    private static ThreadLocal<DateFormat> threadLocal = new ThreadLocal<DateFormat>(){
        @Override
        protected DateFormat initialValue() {
            return new SimpleDateFormat("yyyy-MM-dd");
        }
    };

    public static void main(String[] args) throws InterruptedException {
        final Semaphore semaphore = new Semaphore(THREAD_COUNT);
        final CountDownLatch countDownLatch = new CountDownLatch(EXECUTE_COUNT);
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < EXECUTE_COUNT; i++){
            executorService.execute(() -> {
                try {
                    semaphore.acquire();
                    try {
                        threadLocal.get().parse("2020-01-01");
                    } catch (ParseException e) {
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }catch (NumberFormatException e){
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }
                    semaphore.release();
                } catch (InterruptedException e) {
                    System.out.println("信号量发生错误");
                    e.printStackTrace();
                    System.exit(1);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        System.out.println("所有线程格式化日期成功");
    }
}
```

通过代码可以得知，将每个线程使用的SimpleDateFormat副本保存在ThreadLocal中，各个线程在使用时互不干扰，从而解决了线程安全问题。

运行程序，输出结果如下所示。

```bash
所有线程格式化日期成功
```

此种方式运行效率比较高，**推荐在高并发业务场景的生产环境使用。**

另外，使用ThreadLocal也可以写成如下形式的代码，效果是一样的。

```java
package io.binghe.concurrent.lab06;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * @author binghe
 * @version 1.0.0
 * @description 通过ThreadLocal解决SimpleDateFormat类的线程安全问题
 */
public class SimpleDateFormatTest06 {
    //执行总次数
    private static final int EXECUTE_COUNT = 1000;
    //同时运行的线程数量
    private static final int THREAD_COUNT = 20;

    private static ThreadLocal<DateFormat> threadLocal = new ThreadLocal<DateFormat>();

    private static DateFormat getDateFormat(){
        DateFormat dateFormat = threadLocal.get();
        if(dateFormat == null){
            dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            threadLocal.set(dateFormat);
        }
        return dateFormat;
    }

    public static void main(String[] args) throws InterruptedException {
        final Semaphore semaphore = new Semaphore(THREAD_COUNT);
        final CountDownLatch countDownLatch = new CountDownLatch(EXECUTE_COUNT);
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < EXECUTE_COUNT; i++){
            executorService.execute(() -> {
                try {
                    semaphore.acquire();
                    try {
                        getDateFormat().parse("2020-01-01");
                    } catch (ParseException e) {
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }catch (NumberFormatException e){
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }
                    semaphore.release();
                } catch (InterruptedException e) {
                    System.out.println("信号量发生错误");
                    e.printStackTrace();
                    System.exit(1);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        System.out.println("所有线程格式化日期成功");
    }
}
```

### 5.DateTimeFormatter方式

DateTimeFormatter是Java8提供的新的日期时间API中的类，DateTimeFormatter类是线程安全的，可以在高并发场景下直接使用DateTimeFormatter类来处理日期的格式化操作。代码如下所示。

```java
package io.binghe.concurrent.lab06;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * @author binghe
 * @version 1.0.0
 * @description 通过DateTimeFormatter类解决线程安全问题
 */
public class SimpleDateFormatTest07 {
    //执行总次数
    private static final int EXECUTE_COUNT = 1000;
    //同时运行的线程数量
    private static final int THREAD_COUNT = 20;

   private static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    public static void main(String[] args) throws InterruptedException {
        final Semaphore semaphore = new Semaphore(THREAD_COUNT);
        final CountDownLatch countDownLatch = new CountDownLatch(EXECUTE_COUNT);
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < EXECUTE_COUNT; i++){
            executorService.execute(() -> {
                try {
                    semaphore.acquire();
                    try {
                        LocalDate.parse("2020-01-01", formatter);
                    }catch (Exception e){
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }
                    semaphore.release();
                } catch (InterruptedException e) {
                    System.out.println("信号量发生错误");
                    e.printStackTrace();
                    System.exit(1);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        System.out.println("所有线程格式化日期成功");
    }
}
```

可以看到，DateTimeFormatter类是线程安全的，可以在高并发场景下直接使用DateTimeFormatter类来处理日期的格式化操作。

运行程序，输出结果如下所示。

```java
所有线程格式化日期成功
```

使用DateTimeFormatter类来处理日期的格式化操作运行效率比较高，**推荐在高并发业务场景的生产环境使用**。

### 6.joda-time方式

joda-time是第三方处理日期时间格式化的类库，是线程安全的。如果使用joda-time来处理日期和时间的格式化，则需要引入第三方类库。这里，以Maven为例，如下所示引入joda-time库。

```html
<dependency>
	<groupId>joda-time</groupId>
	<artifactId>joda-time</artifactId>
	<version>2.9.9</version>
</dependency>
```

引入joda-time库后，实现的程序代码如下所示。

```java
package io.binghe.concurrent.lab06;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * @author binghe
 * @version 1.0.0
 * @description 通过DateTimeFormatter类解决线程安全问题
 */
public class SimpleDateFormatTest08 {
    //执行总次数
    private static final int EXECUTE_COUNT = 1000;
    //同时运行的线程数量
    private static final int THREAD_COUNT = 20;

    private static DateTimeFormatter dateTimeFormatter = DateTimeFormat.forPattern("yyyy-MM-dd");

    public static void main(String[] args) throws InterruptedException {
        final Semaphore semaphore = new Semaphore(THREAD_COUNT);
        final CountDownLatch countDownLatch = new CountDownLatch(EXECUTE_COUNT);
        ExecutorService executorService = Executors.newCachedThreadPool();
        for (int i = 0; i < EXECUTE_COUNT; i++){
            executorService.execute(() -> {
                try {
                    semaphore.acquire();
                    try {
                        DateTime.parse("2020-01-01", dateTimeFormatter).toDate();
                    }catch (Exception e){
                        System.out.println("线程：" + Thread.currentThread().getName() + " 格式化日期失败");
                        e.printStackTrace();
                        System.exit(1);
                    }
                    semaphore.release();
                } catch (InterruptedException e) {
                    System.out.println("信号量发生错误");
                    e.printStackTrace();
                    System.exit(1);
                }
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        executorService.shutdown();
        System.out.println("所有线程格式化日期成功");
    }
}
```

这里，需要注意的是：DateTime类是org.joda.time包下的类，DateTimeFormat类和DateTimeFormatter类都是org.joda.time.format包下的类，如下所示。

```java
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
```

运行程序，输出结果如下所示。

```java
所有线程格式化日期成功
```

使用joda-time库来处理日期的格式化操作运行效率比较高，**推荐在高并发业务场景的生产环境使用。**

### 解决SimpleDateFormat类的线程安全问题的方案总结

综上所示：在解决解决SimpleDateFormat类的线程安全问题的几种方案中，局部变量法由于线程每次执行格式化时间时，都会创建SimpleDateFormat类的对象，这会导致创建大量的SimpleDateFormat对象，浪费运行空间和消耗服务器的性能，因为JVM创建和销毁对象是要耗费性能的。所以，**不推荐在高并发要求的生产环境使用**。

synchronized锁方式和Lock锁方式在处理问题的本质上是一致的，通过加锁的方式，使同一时刻只能有一个线程执行格式化日期和时间的操作。这种方式虽然减少了SimpleDateFormat对象的创建，但是由于同步锁的存在，导致性能下降，所以，**不推荐在高并发要求的生产环境使用。**

ThreadLocal通过保存各个线程的SimpleDateFormat类对象的副本，使每个线程在运行时，各自使用自身绑定的SimpleDateFormat对象，互不干扰，执行性能比较高，**推荐在高并发的生产环境使用。**

DateTimeFormatter是Java 8中提供的处理日期和时间的类，DateTimeFormatter类本身就是线程安全的，经压测，DateTimeFormatter类处理日期和时间的性能效果还不错（**后文单独写一篇关于高并发下性能压测的文章**）。所以，**推荐在高并发场景下的生产环境使用。**

joda-time是第三方处理日期和时间的类库，线程安全，性能经过高并发的考验，**推荐在高并发场景下的生产环境使用**。

**好了，今天就到这儿吧，小伙伴们点赞、收藏、评论，一键三连走起呀，我是冰河，我们下期见~~**


## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发编程技术。


最后，附上并发编程需要掌握的核心技能知识图，祝大家在学习并发编程时，少走弯路。

![](https://img-blog.csdnimg.cn/20200322144644983.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2wxMDI4Mzg2ODA0,size_16,color_FFFFFF,t_70#pic_center)

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)

