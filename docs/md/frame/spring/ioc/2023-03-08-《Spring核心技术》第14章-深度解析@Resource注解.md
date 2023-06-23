---
title: 【付费】 第14章：深度解析@Resource注解
pay: https://articles.zsxq.com/id_v9wd5237pgu6.html
---

# 《Spring核心技术》第14章-注入数据型注解：深度解析@Resource注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-14](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-14)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Resource注解注入Bean的案例和流程，从源码级别彻底掌握@Resource注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 解析并获取@Resource修饰的属性
  * 为@Resource修饰属性赋值
* 源码解析
  * 解析并获取@Resource修饰的属性
  * 为@Resource修饰属性赋值
* 总结
* 思考

## 一、学习指引

`Spring中的@Resource注解，你真的彻底了解过吗？`

@Resource注解是JSR250规范中提供的注解，主要作用就是通过JNDI技术查找依赖的组件并注入到类、字段和方法中来。

**注意：在Spring6中，需要额外导入@Resource注解所在的包**

## 二、注解说明

`关于@Resource注解的一点点说明~~`

@Resource注解是JSR250规范中提供的注解，主要作用就是通过JNDI技术查找依赖的组件并注入到类、字段和方法中来。默认情况下，不指定注解的任何属性时，会默认按照byName的方式装配Bean对象。如果指定了name属性，没有指定type属性，则采用byName的方式装配Bean对象。如果没有指定name属性，而是指定了type属性，则按照byType的方式装配bean对象。当同时指定了type属性和name属性，则两个属性都会校验，任何一个不符合条件就会报错。

当存在多个类型相同的Bean时，可以指定@Resource注解的name属性明确指定装配哪个Bean对象。相当于@Autowired注解与@Qualifier注解的组合。@Resource注解与@Qualifier注解也可以搭配使用，通过@Qualifier注解明确指定装配哪个Bean。

@Resource注解与@Autowired的主要区别如下所示。

（1）@Resource注解是JSR250规范中提供的注解，如果使用的JDK8版本，则无需额外导入依赖，如果使用的JDK版本低于8或者高于11，则需要额外导入依赖。@Autowired注解是Spring框架提供的注解。

（2）@Resource注解默认通过byName的方式装配Bean，找不到Bean的话，就通过byType的方式装配Bean。@Autowired注解默认根据byType的方式装配Bean，如果需要根据名称装配Bean，则需要结合@Qualifier注解一起使用。

（3）@Resource注解标注到类、字段和方法上。@Autowired注解标注到构造方法、方法、参数、字段、其他注解上。

### 2.1 注解源码

在Spring6中，使用@Resource注解需要额外在Maven中加入如下依赖。

```xml
<dependency>
    <groupId>jakarta.annotation</groupId>
    <artifactId>jakarta.annotation-api</artifactId>
    <version>2.1.1</version>
</dependency>
```

@Resource注解的源码详见：jakarta.annotation.Resource。

```java
@Target({TYPE, FIELD, METHOD})
@Retention(RUNTIME)
@Repeatable(Resources.class)
public @interface Resource {
    String name() default "";
    String lookup() default "";
    Class<?> type() default java.lang.Object.class;
    enum AuthenticationType {
	    CONTAINER,
	    APPLICATION
    }
    AuthenticationType authenticationType() default AuthenticationType.CONTAINER;
    boolean shareable() default true;
    String mappedName() default "";
    String description() default "";
}
```

@Resource注解中属性的具体含义如下所示。

* name：资源的JNDI名称，装配指定名称的Bean。
* type：装配指定类型的Bean。
* lookup：引用指向的资源名称，可以使用JNDI名称指向任何兼容的资源。
* AuthenticationType：指定身份验证类型。
* shareable：指定当前Bean是否可以在多个组件之间共享。
* mappedName：指定资源的映射名称。
* description：指定资源的描述。

### 2.2 使用场景

@Resource通过名称装配Bean对象时，相当于@Autowired注解+@Qualifier注解。所以，当在IOC容器中存在多个类型相同的Bean时，就可以使用@Resource注解或者@Autowired注解+@Qualifier注解，明确指定要装配的Bean的名称。

**注意：@Resource注解也可以和@Qualifier注解搭配使用。**

## 三、使用案例

`@Resource的使用案例，我们一起实现吧~~`

本节，就简单介绍下当Spring中存在多个类型相同的Bean时，使用@Resource注解明确指定注入的Bean的案例。在案例的实现过程中，同样采用简单的MVC架构模式实现。具体案例实现步骤如下所示。

**（1）新增ResourceDao接口**

ResourceDao接口的源码详见：spring-annotation-chapter-14工程下的io.binghe.spring.annotation.chapter14.dao.ResourceDao。

```java
public interface ResourceDao {
}
```

可以看到，ResourceDao接口就是普通的dao接口。

**（2）新增ResourceDao1类**

ResourceDao1类的源码详见：spring-annotation-chapter-14工程下的io.binghe.spring.annotation.chapter14.dao.impl.ResourceDao1。

```java
@Repository("resourceDao1")
public class ResourceDao1 implements ResourceDao {
}
```

可以看到，ResourceDao1类实现了ResourceDao接口，并在类上通过@Repository注解指定Bean的名称为resourceDao1。

**（3）新增ResourceDao2类**

ResourceDao2类的源码详见：spring-annotation-chapter-14工程下的io.binghe.spring.annotation.chapter14.dao.impl.ResourceDao2。

```java
@Repository("resourceDao2")
public class ResourceDao2 implements ResourceDao {
}
```

可以看到，ResourceDao2类实现了ResourceDao接口，并在类上通过@Repository注解指定Bean的名称为resourceDao2。

**（4）新增ResourceService类**

ResourceService类的源码详见：spring-annotation-chapter-14工程下的io.binghe.spring.annotation.chapter14.service.ResourceService。

```java
@Service
public class ResourceService {
    @Resource(name = "resourceDao1")
    private ResourceDao resourceDao;
    @Override
    public String toString() {
        return "ResourceService{" +
                "resourceDao=" + resourceDao +
                '}';
    }
}
```

可以看到，在ResourceService类中通过@Resource注解向成员变量resourceDao中注入了名称为resourceDao1的Bean。

**（5）新增ResourceConfig类**

ResourceConfig类的源码详见：spring-annotation-chapter-14工程下的io.binghe.spring.annotation.chapter14.config.ResourceConfig。

```java
@Configuration
@ComponentScan(value = {"io.binghe.spring.annotation.chapter14"})
public class ResourceConfig {
}
```

可以看到，在ResourceConfig类上标注了@Configuration注解，说明ResourceConfig类是Spring的配置类。并且使用@ComponentScan注解指定了要扫描的包名。

**（6）新增ResourceTest类**

ResourceTest类的源码详见：spring-annotation-chapter-14工程下的io.binghe.spring.annotation.chapter14.ResourceTest。

```java
public class ResourceTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ResourceConfig.class);
        ResourceService resourceService = context.getBean(ResourceService.class);
        System.out.println(resourceService);
    }
}
```

可以看到，在ResourceTest类的main()方法中，从IOC容器中获取ResourceService对象，并进行打印。

**（7）运行ResourceTest类**

运行ResourceTest类的main()方法，输出的结果信息如下所示。

```bash
ResourceService{resourceDao=io.binghe.spring.annotation.chapter14.dao.impl.ResourceDao1@ea6147e}
```

从输出的结果信息可以看出，正确打印了ResourceService中装配的ResourceDao1类型的Bean对象。

**说明：当存在多个类型相同的Bean时，可以通过@Resource注解明确指定要注入的Bean。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本节，就以源码时序图的方式，直观的感受下@Resource注解在Spring源码层面的执行流程。本节，会从解析并获取 @Resource修饰的属性、为@Resource修饰属性赋值两个方面分析源码时序图。

### 4.1 解析并获取@Resource修饰的属性

解析并获取@Resource修饰的属性的源码时序图总体上与解析并获取@Autowired修饰的属性的源码时序图相同，只是部分细节略有差异。本节，就简单介绍下解析并获取@Resource修饰的属性的源码时序图，整体如图14-1~14-2所示。

![图14-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-08-001.png)

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码