---
layout: post
category: binghe-code-bytecode
title: 字节码编程 | 使用Javassist动态生成Hello World
tagline: by 冰河
tag: [bytecode,binghe-code-bytecode]
excerpt: 字节码编程在实际的业务开发（CRUD）中并不常用，但是随着网络编程，RPC、动态字节码增强技术和自动化测试以及零侵入APM监控的不断发展与大量使用，越来越多的技术需要使用到字节码编程。
lock: need
---

# 字节码编程 | 使用Javassist动态生成Hello World

**大家好，我是冰河~~**

字节码编程在实际的业务开发（CRUD）中并不常用，但是随着网络编程，RPC、动态字节码增强技术和自动化测试以及零侵入APM监控的不断发展与大量使用，越来越多的技术需要使用到字节码编程。

好了，我们今天就使用Javassist动态生成一个HelloWorld案例，相关的程序案例代码可以关注公众号：**冰河技术** 获取，也可以直接到Github和Gitee获取。

> Github：https://github.com/binghe001/bytecode
>
> Gitee：https://gitee.com/binghe001/bytecode

## 开发环境

- JDK 1.8
- IDEA 2018.03
- Maven 3.6.0

## Maven依赖

在项目的pom.xml文件中添加如下环境依赖。

```xml
<properties>
    <javassist.version>3.20.0-GA</javassist.version>
</properties>

<dependencies>
    <dependency>
        <groupId>org.javassist</groupId>
        <artifactId>javassist</artifactId>
        <version>${javassist.version}</version>
    </dependency>
</dependencies>
```

## 案例效果

整体案例效果其实也是很简单的，学习Java语言时，我们会在命令行打印第一个Hello World程序。今天，我们学习Javassist字节码编程时，也来实现一个HelloWorld程序。

案例的效果就是要生成如下的程序代码。

```java
package io.binghe.bytecode.javassist.test;

public class HelloWorld {
    public static void main(String[] var0) {
        System.out.println("Javassist Hello World by 冰河（公众号：冰河技术）");
    }

    public HelloWorld() {
    }
}
```

看看这个效果，像不像我们自己在IDEA中写的Java代码呢？就让我们一起使用Javassist来实现它吧。

## 案例实现

这个案例其实还是蛮简单的，这里就先直接给出源代码了。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 测试使用Javassist生成第一个类HelloWorld
 */
public class GenerateHelloWorldClass {

    /**
     * 创建HelloWorld的类，并返回HelloWorld的Class实例
     */
    public static Class createHelloWorld()throws Exception{
        //使用默认的ClassPool
        ClassPool pool = ClassPool.getDefault();
        //创建一个空类
        CtClass ctClass = pool.makeClass("io.binghe.bytecode.javassist.test.HelloWorld");
        //添加一个main方法
        CtMethod ctMethod = new CtMethod(CtClass.voidType, "main", new CtClass[]{pool.get(String[].class.getName())}, ctClass);
        //将main方法声明为public static类型
        ctMethod.setModifiers(Modifier.PUBLIC + Modifier.STATIC);
        //设置方法体
        ctMethod.setBody("{" +
                "System.out.println(\"Javassist Hello World by 冰河（公众号：冰河技术）\");" +
                "}");
        ctClass.addMethod(ctMethod);

        //将生成的类的class文件输出的磁盘
        ctClass.writeFile();

        //返回HelloWorld的Class实例
        return ctClass.toClass();

    }

    public static void main(String[] args) throws Exception {
        Class clazz = createHelloWorld();
        Object obj = clazz.newInstance();
        Method mainMethod = clazz.getMethod("main", new Class[]{String[].class});
        mainMethod.invoke(obj, new String[1]);
    }
}
```

接下来，我们根据上述代码来看看Javassist是如何生成完整字节码的。

(1) 在createHelloWorld()方法中创建一个ClassPool，ClassPool本质上就是个CtClass对象容器。

(2) 调用ClassPool的makeClass()方法，传入完整的包名+类名生成一个空的类信息。这里传入的完整的包名+类名是`io.binghe.bytecode.javassist.test.HelloWorld`。

(3) 给类添加方法，并设置方法的返回类型、方法名称、参数名（入参和出参）、访问修饰符以及方法体。这里设置的完整方法体如下：

```java
public static void main(String[] var0) {
    System.out.println("Javassist Hello World by 冰河（公众号：冰河技术）");
}
```

(4) 尽管我们在上述代码中没有显示的创建无参构造函数，但是在编译时，Javassist会自动创建一个HelloWorld类的无参构造函数。

(5) 通过 CtClass的writeFile()方法将内存中的类信息输出到磁盘，这样我们就可以通过IDEA清晰的看到Javassist生成的HelloWorld类了。

(6) 最终在createHelloWorld()方法中调用CtClass的toClass()方法返回Class对象。

(7) 在main()方法中调用createHelloWorld()方法获取Class对象。

(8) 通过反射实例化对象，并通过反射调用生成的HelloWorld类的main()方法。

## 效果演示

运行GenerateHelloWorldClass类的main()方法，会在顶级工程目录下的`io/binghe/bytecode/javassist/test` 目录下生成HelloWorld.class文件，具体如下所示。

![图片](https://img-blog.csdnimg.cn/img_convert/83bcf5bfa3e8396a41c62c90d641d58e.png)



查看IDEA的输出信息时，发现会输出如下内容。

```bash
Javassist Hello World by 冰河（公众号：冰河技术）

Process finished with exit code 0
```

## 案例总结

我们使用Javassist实现了创建一个HelloWorld类的功能，字节码编程听起来貌似挺难的，但是在Javassist强大的API下，实现起来还是蛮简单的。

在接下来的一段时间里，冰河会持续输出关于字节码编程的文章，让我们一起精通字节码编程。

**好了，今天就到这儿吧，我是冰河，我们下期见~~**
## 写在最后

**如果你想进大厂，想升职加薪，或者对自己现有的工作比较迷茫，都可以私信我交流，希望我的一些经历能够帮助到大家~~**

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)