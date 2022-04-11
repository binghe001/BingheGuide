---
layout: post
category: binghe-code-bytecode
title: 字节码编程 | 使用Javassist生成JavaBean
tagline: by 冰河
tag: [bytecode,binghe-code-bytecode]
excerpt: 在实际工作过程中，我们可以通过对Java的字节码进行插桩，以便拦截我们需要拦截的类和方法，对这些类和方法进行改造或者直接动态生成相应的类来实现拦截的逻辑。
lock: need
---

# 字节码编程 | 使用Javassist生成JavaBean

**大家好，我是冰河~~**

在实际工作过程中，我们可以通过对Java的字节码进行插桩，以便拦截我们需要拦截的类和方法，对这些类和方法进行改造或者直接动态生成相应的类来实现拦截的逻辑。

这种方式几乎不需要修改源程序就能够达到我们想要的效果。今天，我们就一起使用Javassist来动态生成JavaBean对象。

掌握这个知识点后以便后续我们在手撸DAPM（分布式性能管理系统）时能够动态生成JavaBean对象来反序列化客户端发送的数据，或者从服务端响应回来的数据。

相关的案例程序代码可以关注公众号：**冰河技术** 获取，也可以直接到Github和Gitee获取。

> Github：https://github.com/sunshinelyz/bytecode
>
> Gitee：https://gitee.com/binghe001/bytecode

注：本文的源代码对应着 `bytecode-javassist-03` 的程序源代码。

## 开发环境

- JDK 1.8
- IDEA 2018.03
- Maven 3.6.0

## Maven依赖

在项目的pom.xml文件中添加如下环境依赖。

```java
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

整体案例的效果比较简单，就是通过运行我们写的程序，能够动态生成User类的class字节码。如下所示。

```java
package io.binghe.bytecode.javassist.bean;

public class User {
    private String name = "binghe";

    public User() {
        this.name = "binghe";
    }

    public User(String var1) {
        this.name = var1;
    }

    public void setName(String var1) {
        this.name = var1;
    }

    public String getName() {
        return this.name;
    }

    public void printName() {
        System.out.println(this.name);
    }
}
```

- 在这个User类中，有一个成员变量name，默认值为binghe。
- 分别有一个无参构造方法和有参构造方法。
- 成员变量name的get/set方法。
- 打印成员变量name的方法printName()。

了解完案例的效果后，我们就开始动手实现如何动态生成这个User类。

## 案例实现

具体的案例实现，我们可以参考案例的效果一步步完成，这里，我们可以将整个User类的动态生成过程分为6个步骤，分别为：

- 创建User类。
- 添加name字段。
- 添加无参构造方法。
- 添加有参构造方法。
- 添加get/set方法。
- 添加printName()方法。

好了，说干就干，接下来就按照这5个步骤动态生成User类。

### 创建User类

```java
//使用默认的ClassPool
ClassPool pool = ClassPool.getDefault();

//1.创建一个空类
CtClass ctClass = pool.makeClass("io.binghe.bytecode.javassist.bean.User");
```

User类的创建方法和我们之前创建HelloWorld的类是相同的，首先是获取一个ClassPool对象，通过调用ClassPool对象的makeClass方法创建User类。

### 添加name字段

```java
//2.新增一个字段 private String name; 字段的名称为name
CtField param = new CtField(pool.get("java.lang.String"), "name", ctClass);
//设置访问修饰符为private
param.setModifiers(Modifier.PRIVATE);
//设置字段的初始值为binghe
ctClass.addField(param, CtField.Initializer.constant("binghe"));
```

为User类添加成员变量name时，使用了Javassist中的CtField类。这里，我们使用的CtField的构造方法的第一个参数是成员变量的类型，第二个参数是变量的名称，第三个字段表示将这个变量添加到哪个类。

创建完CtField对象param后，我们调用了param的setModifiers()方法设置访问修饰符，这里将其设置为private。

接下来，为成员变量name赋默认值binghe。上述代码生成的效果如下所示。

```java
private String name = "binghe";
```

### 添加无参构造方法

```java
//3.添加无参的构造函数
CtConstructor constructor = new CtConstructor(new CtClass[]{}, ctClass);
constructor.setBody("{" +
                    " $0.name = \"binghe\"; " +
                    "}");
ctClass.addConstructor(constructor);
```

添加无参构造方法时，使用了Javassist中的CtConstructor类，第一个参数是动态生成的目标类的构造方法的参数类型数组，第二个参数表示将构造方法添加到哪个类中。

接下来，通过调用CtConstructor的setBody()方法设置无参构造方法的方法体。这里需要注意的是方法体中只有一行代码时，可以省略`{}`,  但是为了防止出错，冰河强烈建议无论方法是否只有一行代码，都不要省略 `{}`。

细心的小伙伴肯定会发现在方法体中通过`$0`引用了成员变量name，估计小伙伴们也猜到了这个 `$0` 是干啥的。没错，它在生成User类后会被编译成`this`。

**在Javassist中，还会有一些其他具有特定含义的符号，这个我们在文章的最后统一说明。**

这段代码的效果如下所示。

```java
public User() {
    this.name = "binghe";
}
```

接下来，就是调用CtClass的addConstructor()方法为User类添加无参构造方法。

### 添加有参构造方法

```java
//4.添加有参构造函数
constructor = new CtConstructor(new CtClass[]{pool.get("java.lang.String")}, ctClass);
constructor.setBody("{" +
                    "$0.name = $1;" +
                    "}");
ctClass.addConstructor(constructor);
```

添加有参构造方法的整体流程和添加无参构造方法的整体流程相同，只是在创建CtConstructor对象时，在CtConstructor的构造方法的第一个参数类型数组中使用`pool.get("java.lang.String")`添加了一个数组元素，表示生成的目标类的构造方法存在一个String类型的参数。

另外，在设置方法体时，使用了如下代码。

```java
$0.name = $1;
```

表示将构造方法的第一个参数赋值给成员变量name。这里，`$0` 表示 `this`, `$1` 表示第一个参数，`$2`表示第二个参数，以此类推。

这段代码的效果如下所示。

```java
public User(String var1) {
    this.name = var1;
}
```

### 添加get/set方法

```java
//5.添加getter和setter方法
ctClass.addMethod(CtNewMethod.setter("setName", param));
ctClass.addMethod(CtNewMethod.getter("getName", param));
```

添加get/set方法就比较简单了，直接使用CtClass的addMethod()添加，使用CtNewMethod的setter()方法生成set方法，其中，第一个参数为生成的方法的名称setName，第二个参数表示是为哪个字段生成setName方法。

使用CtNewMethod的getter()方法生成get()方法，第一个参数为生成的方法的名称getName，第二个参数表示是为哪个字段生成getName方法。

这段代码的效果如下所示。

```java
public void setName(String var1) {
    this.name = var1;
}

public String getName() {
    return this.name;
}
```

### 添加printName()方法

```java
//6.创建一个输出name的方法
CtMethod ctMethod = new CtMethod(CtClass.voidType, "printName", new CtClass[]{}, ctClass);
ctMethod.setModifiers(Modifier.PUBLIC);
ctMethod.setBody("{" +
        "System.out.println(name);" +
        "}");
ctClass.addMethod(ctMethod);
```

添加printName()方法使用了Javassist中的CtMethod类，创建CtMethod类的对象时，第一个参数为方法的返回类型，第二个参数为方法的名称printName，第三个参数为方法的参数类型数组，第四个参数表示将生成的方法添加到哪个类。

接下来，调用CtMethod的setModifiers()方法来设置printName()方法的访问修饰符，这里将其设置为public。紧接着为printName()方法设置方法体，在方法体中简单的在命令行打印成员变量name。

最后通过CtClass的addMethod()方法将生成的printName方法添加到User类中。

这段代码的效果如下所示。

```java
public void printName() {
    System.out.println(this.name);
}
```

## 完整案例

为了方便小伙伴们更加清晰的看到完整的源代码，这里我也将完整的源代码贴出来，如下所示。

```java
/**
 * @author binghe (公众号：冰河技术)
 * @version 1.0.0
 * @description 使用Javassist生成一个User类, 并测试
 */
public class CreateUserClass {

    /**
     * 使用Javassist创建一个User对象
     */
    public static void createUser() throws Exception{
        //使用默认的ClassPool
        ClassPool pool = ClassPool.getDefault();

        //1.创建一个空类
        CtClass ctClass = pool.makeClass("io.binghe.bytecode.javassist.bean.User");

        //2.新增一个字段 private String name; 字段的名称为name
        CtField param = new CtField(pool.get("java.lang.String"), "name", ctClass);
        //设置访问修饰符为private
        param.setModifiers(Modifier.PRIVATE);
        //设置字段的初始值为binghe
        ctClass.addField(param, CtField.Initializer.constant("binghe"));

        //3.添加无参的构造函数
        CtConstructor constructor = new CtConstructor(new CtClass[]{}, ctClass);
        constructor.setBody("{" +
                " $0.name = \"binghe\"; " +
                "}");
        ctClass.addConstructor(constructor);

        //4.添加有参构造函数
        constructor = new CtConstructor(new CtClass[]{pool.get("java.lang.String")}, ctClass);
        constructor.setBody("{" +
                "$0.name = $1;" +
                "}");
        ctClass.addConstructor(constructor);

        //5.添加getter和setter方法
        ctClass.addMethod(CtNewMethod.setter("setName", param));
        ctClass.addMethod(CtNewMethod.getter("getName", param));

        //6.创建一个输出name的方法
        CtMethod ctMethod = new CtMethod(CtClass.voidType, "printName", new CtClass[]{}, ctClass);
        ctMethod.setModifiers(Modifier.PUBLIC);
        ctMethod.setBody("{" +
                "System.out.println(name);" +
                "}");
        ctClass.addMethod(ctMethod);

        ctClass.writeFile();
    }
}
```

## 效果演示

编写main方法，直接调用CreateUserClass类的createUser()方法，如下所示。

```java
public static void main(String[] args) throws Exception {
    CreateUserClass.createUser();
}
```

运行main()方法后，生成了我们想要的User类的字节码，如下所示。

![图片](https://img-blog.csdnimg.cn/img_convert/68dde8cf21386ea83a1a23c198d32404.png)



效果符合我们的预期。

## 案例总结

我们使用Javassist动态生成了符合预期的User类对象，通过本文的学习，我们掌握了如何使用Javassist生成JavaBean对象。是不是很简单呢？小伙伴们赶紧打开IDEA搞起来吧。

## 附录

文中涉及到了Javassist中方法内部的引用变量`$0`和 `$1` ， 在Javassist中，还有一些其他的方法内部引用变量，冰河将其进行了总结，以方便大家学习。

![图片](https://img-blog.csdnimg.cn/img_convert/07cd1d45841adc37caccaa370e78084c.png)



**好了，今天就到这儿吧，我是冰河，我们下期见~~**
## 写在最后

**如果你想进大厂，想升职加薪，或者对自己现有的工作比较迷茫，都可以私信我交流，希望我的一些经历能够帮助到大家~~**

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)