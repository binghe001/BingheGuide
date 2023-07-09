---
layout: post
category: binghe-code-spring
title: 第09章：深度解析@Lazy注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第09章：深度解析@Lazy注解
lock: need
---

# 《Spring核心技术》第09章-条件型注解：深度解析@Lazy注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-09](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-09)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★☆☆

* **本章重点**：进一步学习并掌握@Lazy注解延迟创建Bean的案例和流程，从源码级别彻底掌握@Lazy注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
  * 创建单例Bean
  * 添加@Lazy注解
  * 获取单例Bean
* 源码时序图
  * 注册Bean的源码时序图
  * 调用Bean后置处理器的源码时序图
  * 创建单例Bean的源码时序图
* 源码解析
  * 注册Bean的源码流程
  * 调用Bean的后置处理器的源码流程
  * 创建单例Bean的源码流程
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Lazy注解真的可以实现Bean的延迟创建吗？`

平时工作过程中，不知道大家有没有遇到过这样一种场景：应用程序可能会在启动的时候创建大量的对象，加载大量的配置文件来进行初始化工作。但是在程序运行的过程中，这些对象或者配置文件使用的频率并不是很频繁，甚至是只有个别很少使用的功能在使用这些配置文件。此时，为了优化应用的启动性能，我们就可以对这些对象的创建和配置文件的加载进行延迟处理。也就是说，在应用启动的时候不去创建这些对象和加载配置文件，而是到触发某些功能操作时，再去创建这些对象和加载配置文件，这就是一种延迟处理的操作。

在设计模式的单例模式中，会分为懒汉模式和饿汉模式，其中，懒汉模式就是一种延迟创建对象的模式。

## 二、注解说明

`关于@Lazy注解的一点点说明~~`

对于单例Bean来说，如果不想在IOC容器启动的时候就创建Bean对象，而是在第一次使用时创建Bean对象，就可以使用@Lazy注解进行处理。

### 2.1 注解源码

@Lazy注解可以标注到类、方法、构造方法、参数和属性字段上，能够实现在启动IOC容器时，不创建单例Bean，而是在第一次使用时创建单例Bean对象。源码详见：org.springframework.context.annotation.Lazy。

```java
/**
 * @author Chris Beams
 * @author Juergen Hoeller
 * @since 3.0
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.CONSTRUCTOR, ElementType.PARAMETER, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Lazy {
	boolean value() default true;
}
```

从源码可以看出，@Lazy注解是从Spring3.0版本开始提供的注解，其中，只提供了一个boolean类型的value属性，具体含义如下所示。

* value：boolean类型的属性，表示是否延迟创建单例Bean，默认值为true。
  * true：表示延迟创建单例Bean，此时在IOC启动时不会创建Bean对象，而是在第一次使用时创建单例Bean对象。
  * false：表示不延迟创建单例Bean对象，IOC容器启动时，就会创建单例Bean对象。

**注意：使用@Lazy直接延迟创建单例Bean，不是延迟加载思想，因为不是每次使用时都创建，只是改变了第一次创建单例Bean的时机。**

### 2.2 使用场景

在实际开发过程中，如果使用Spring创建的Bean是单例对象时，有时并不是每个单例Bean对象都需要在IOC容器启动时就创建，有些单例Bean可以在使用的时候再创建。此时，就可以使用@Lazy注解实现这样的场景。

**注意：@Lazy注解只对单例Bean对象起作用，如果使用@Scope注解指定为多例Bean对象，则@Lazy注解将不起作用。**

## 三、使用案例

`@Lazy的实现案例，我们一起实现吧~~`

本节，就使用@Lazy注解实现延迟创建Bean的案例。本节主要从创建单例Bean、添加@Lazy注解和获取单例Bean三个方面实现案例程序。

### 3.1 创建单例Bean

本小节，完成创建单例Bean的案例部分，具体步骤如下所示。

**（1）新增LazyBean类**

LazyBean类的源码详见：spring-annotation-chapter-09工程下的io.binghe.spring.annotation.chapter09.bean.LazyBean。

```java
public class LazyBean {
    public LazyBean(){
        System.out.println("执行LazyBean类的构造方法...");
    }
}
```

可以看到，LazyBean类就是一个普通的实体类对象，在LazyBean类的构造方法中，打印了`执行LazyBean类的构造方法...`的日志。

**（2）新增LazyConfig类**

LazyConfig类的源码详见：spring-annotation-chapter-09工程下的io.binghe.spring.annotation.chapter09.config.LazyConfig。

```java
@Configuration
public class LazyConfig {
    @Bean
    public LazyBean lazyBean(){
        return new LazyBean();
    }
}
```

可以看到，LazyConfig类是Spring中的配置类，在LazyConfig类中使用@Bean注解创建了LazyBean类的单例Bean对象，同时在lazyBean()方法上并没有标注@Lazy注解。

**（3）新增LazyTest类**

LazyTest类的源码详见：spring-annotation-chapter-09工程下的io.binghe.spring.annotation.chapter09.LazyTest。

```java
public class LazyTest {
    public static void main(String[] args) {
        System.out.println("创建IOC容器开始...");
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(LazyConfig.class);
        System.out.println("创建IOC容器结束");
    }
}
```

可以看到，LazyTest类主要是测试案例程序，在main()方法中，创建了IOC容器，并在创建IOC容器前后打印了相关的日志信息。

**（4）运行LazyTest类**

运行LazyTest类中的main()方法，输出的结果信息如下所示。

```bash
创建IOC容器开始...
执行LazyBean类的构造方法...
创建IOC容器结束...
```

从输出的结果信息可以看出，打印了LazyBean类的构造方法中输出的日志信息。

**说明：Spring会在IOC容器启动时，创建单例Bean。**

### 3.2 添加@Lazy注解

本小节在3.1小节的基础上，完成案例添加@Lazy注解的部分，具体实现步骤如下所示。

**（1）修改LazyConfig类**

在LazyConfig类的lazyBean()方法上添加@Lazy注解，如下所示。

```java
@Bean
@Lazy
public LazyBean lazyBean(){
    return new LazyBean();
}
```

**（2）运行LazyTest类**

运行LazyTest类中的main()方法，输出的结果信息如下所示。

```bash
创建IOC容器开始...
创建IOC容器结束...
```

可以看到，输出的结果信息中并没有打印LazyBean类的构造方法中输出的日志信息。

**说明：在创建单实例Bean的方法上添加@Lazy注解时，当IOC容器启动时，并不会创建单例Bean。**

### 3.3 获取单例Bean

本小节在3.2小节的基础上，完成案例获取单例Bean的部分，具体实现步骤如下所示。

**（1）修改LazyTest类**

在LazyTest类的main()方法中，创建完IOC容器，从IOC容器中多次获取LazyBean类的Bean对象，如下所示。

```java
public class LazyTest {
    public static void main(String[] args) {
        System.out.println("创建IOC容器开始...");
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(LazyConfig.class);
        System.out.println("创建IOC容器结束...");
        System.out.println("从IOC容器中获取Bean开始...");
        LazyBean lazyBean1 = context.getBean(LazyBean.class);
        LazyBean lazyBean2 = context.getBean(LazyBean.class);
        System.out.println("(lazyBean1 是否等于 lazyBean2) ===>>> " + (lazyBean1 == lazyBean2));
        System.out.println("从IOC容器中获取Bean结束...");
    }
}
```

可以看到，在LazyTest类的构造方法中，创建完IOC容器中，从IOC容器中连续获取两次LazyBean类的Bean对象，并打印两次获取的Bean对象是否相等。

**（2）运行LazyTest类**

运行LazyTest类中的main()方法，输出的结果信息如下所示。

```bash
创建IOC容器开始...
创建IOC容器结束...
从IOC容器中获取Bean开始...
执行LazyBean类的构造方法...
(lazyBean1 是否等于 lazyBean2) ===>>> true
从IOC容器中获取Bean结束...
```

从输出的结果信息可以看出，从第一次从IOC容器中获取Bean对象时，打印了LazyBean类的构造方法中输出的日志信息，并且两次从IOC容器中获取到的Bean对象相同。

**说明：当在创建单例Bean的方法上标注@Lazy注解时，启动IOC容器并不会创建对应的单例Bean对象，而是在第一次获取Bean对象时才会创建，同时，由于Spring创建的是单例Bean对象，所以，无论从IOC容器中获取多少次对象，每次获取到的Bean对象都是相同的。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本节，就以源码时序图的方式，直观的感受下@Lazy注解在Spring源码层面的执行流程。本节，主要从注册Bean、调用Bean工厂后置处理器和创建单例Bean三个方面分析源码时序图。

### 4.1 注册Bean的源码时序图

@Lazy注解涉及到的注册Bean的源码时序图如图9-1所示。

![图9-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-01-001.png)

由图9-1可以看出，@Lazy注解在注册Bean的流程中涉及到LazyTest类、AnnotationConfigApplicationContext类、AnnotatedBeanDefinitionReader类、AnnotationConfigUtils类、BeanDefinitionReaderUtils类和DefaultListableBeanFactory类。具体的源码执行细节参见源码解析部分。 

### 4.2 调用Bean后置处理器的源码时序图

@Lazy注解涉及到的调用Bean工厂后置处理器的源码时序图如图9-2~9-4所示。

![图9-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-01-002.png)

![图9-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-01-003.png)

![图9-4](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-01-004.png)



由图9-2~9-4可以看出，@Lazy注解涉及到的调用Bean工厂后置处理器的流程涉及到LazyTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、ComponentScanAnnotationParser类、ClassPathBeanDefinitionScanner类、AnnotationConfigUtils类、BeanDefinitionReaderUtils类和DefaultListableBeanFactory类。具体的源码执行细节参见源码解析部分。 

### 4.3  创建单例Bean的源码时序图

@Lazy注解涉及到的创建Bean的源码时序图如图9-5所示。

![图9-5](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-01-005.png)

由图9-5可以看出，@Lazy注解涉及到的创建Bean的流程涉及到LazyTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类和AbstractBeanFactory类。具体的源码执行细节参见源码解析部分。 

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

本节，主要分析@Lazy注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻。本节，同样会从注册Bean、调用Bean工厂后置处理器和创建单例Bean三个方面分析源码的执行流程。

### 5.1 注册Bean的源码流程

@Lazy注解在Spring源码层面注册Bean的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图9-1进行理解。

@Lazy注解涉及到的注册Bean的源码流程与第7章5.1小节@DependsOn注解涉及到的注册Bean的源码流程大体相同，只是在解析AnnotatedBeanDefinitionReader类的doRegisterBean()方法时，略有不同。本小节，就从AnnotatedBeanDefinitionReader类的doRegisterBean()方法开始解析。

（1）解析AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)。重点关注如下代码片段。

```java
private <T> void doRegisterBean(Class<T> beanClass, @Nullable String name, @Nullable Class<? extends Annotation>[] qualifiers, @Nullable Supplier<T> supplier, @Nullable BeanDefinitionCustomizer[] customizers) {
	/***********省略其他代码************/
    AnnotationConfigUtils.processCommonDefinitionAnnotations(abd);
    if (qualifiers != null) {
        for (Class<? extends Annotation> qualifier : qualifiers) {
            if (Primary.class == qualifier) {
                abd.setPrimary(true);
            }
            else if (Lazy.class == qualifier) {
                abd.setLazyInit(true);
            }
            else {
                abd.addQualifier(new AutowireCandidateQualifier(qualifier));
            }
        }
    }
    /**********省略其他代码************/
    BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(abd, beanName);
    definitionHolder = AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
    BeanDefinitionReaderUtils.registerBeanDefinition(definitionHolder, this.registry);
}
```

可以看到，在AnnotatedBeanDefinitionReader类的doRegisterBean()方法中，调用了AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法。

（2）解析AnnotationConfigUtils类的processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd)方法

源码详见：org.springframework.context.annotation.AnnotationConfigUtils#processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd)。

```java
public static void processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd) {
    processCommonDefinitionAnnotations(abd, abd.getMetadata());
}
```

可以看到，在AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法中，直接调用了另一个重载的processCommonDefinitionAnnotations()方法。

（3）解析AnnotationConfigUtils类的processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata)方法

源码详见：org.springframework.context.annotation.AnnotationConfigUtils#processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata)。

```java
static void processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata) {
    AnnotationAttributes lazy = attributesFor(metadata, Lazy.class);
    if (lazy != null) {
        abd.setLazyInit(lazy.getBoolean("value"));
    }
    else if (abd.getMetadata() != metadata) {
        lazy = attributesFor(abd.getMetadata(), Lazy.class);
        if (lazy != null) {
            abd.setLazyInit(lazy.getBoolean("value"));
        }
    }
	/**********省略其他代码***********/
}
```

可以看到，在AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法中，会解析@Lazy注解中的value属性，并将属性值存入abd对象的lazyInit字段中。

（4）回到AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法。

可以看到，在方法中遍历qualifiers数组，如果Lazy.class的值与遍历出的qualifier对象相等，就会将abd对象的lazyInit字段设置为true。如果abd对象的lazyInit字段为true，则后续在启动IOC容器的过程中，就不会创建单例Bean对象。

**后续的执行流程就与第7章5.1小节的执行流程相同，不再赘述。**

至此，@Lazy注解涉及到的注册Bean的源码流程分析完毕。

### 5.2 调用Bean后置处理器的源码流程

@Lazy注解在Spring源码层面调用Bean工厂后置处理器的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图9-2~9-4进行理解。

@Lazy注解涉及到的调用Bean后置处理器的源码流程，与第7章5.2小节@DependsOn注解涉及到的调用Bean后置处理器的源码流程大体相同，只是在解析ComponentScanAnnotationParser类的parse()方法和AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法时，略有不同。

（1）解析ComponentScanAnnotationParser类的parse(AnnotationAttributes componentScan, String declaringClass)方法

源码详见：org.springframework.context.annotation.ComponentScanAnnotationParser#parse(AnnotationAttributes componentScan, String declaringClass)。重点关注如下代码片段。

```java
public Set<BeanDefinitionHolder> parse(AnnotationAttributes componentScan, String declaringClass) {
    /**********省略其他代码**********/
    boolean lazyInit = componentScan.getBoolean("lazyInit");
    if (lazyInit) {
        scanner.getBeanDefinitionDefaults().setLazyInit(true);
    }
	/**********省略其他代码**********/
    return scanner.doScan(StringUtils.toStringArray(basePackages));
}
```

可以看到，在ComponentScanAnnotationParser类的parse()方法中，会获取componentScan中的lazyInit属性，如果属性的值为true，会将scanner对象中beanDefinitionDefaults对象的lazyInit属性设置为true。

（2）解析AnnotationConfigUtils类的processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata)方法

此时，与本章5.1节注册Bean的源码流程中解析AnnotationConfigUtils类的processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata)方法的流程相同。不再赘述。

后续源码的解析流程与第7章5.2小节解析源码的流程相同，这里不再赘述。

至此，@Lazy注解涉及到的调用Bean后置处理器的源码流程分析完毕。

### 5.3 创建单例Bean的源码流程

@Lazy注解在Spring源码层面创建单例Bean的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图9-5进行理解。

本节@Lazy注解创建单例Bean的源码流程，与第7章中5.3小节中@DependsOn注解创建单例Bean的源码流程大体相同，只是在DefaultListableBeanFactory类的preInstantiateSingletons()方法中略有差异。

DefaultListableBeanFactory类的preInstantiateSingletons()方法的源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#preInstantiateSingletons()。重点关注如下代码片段。

```java
@Override
public void preInstantiateSingletons() throws BeansException {
    /************省略其他代码**************/
    for (String beanName : beanNames) {
        RootBeanDefinition bd = getMergedLocalBeanDefinition(beanName);
        if (!bd.isAbstract() && bd.isSingleton() && !bd.isLazyInit()) {
            if (isFactoryBean(beanName)) {
                Object bean = getBean(FACTORY_BEAN_PREFIX + beanName);
                if (bean instanceof SmartFactoryBean<?> smartFactoryBean && smartFactoryBean.isEagerInit()) {
                    getBean(beanName);
                }
            }
            else {
                getBean(beanName);
            }
        }
    }
	/************省略其他代码**************/
}
```

可以看到，在preInstantiateSingletons()方法中，会循环遍历解析出的Bean名称，在循环中，会根据遍历出的Bean名称获取RootBeanDefinition对象。接下来会进行如下判断。

```java
if (!bd.isAbstract() && bd.isSingleton() && !bd.isLazyInit()) {
    /*************省略其他代码*************/
}
```

可以看到，在preInstantiateSingletons()方法中，会判断每次遍历获取出的RootBeanDefinition对象中如果标记的不是抽象类，并且是单实例对象，并且没有设置延迟创建Bean。同时满足这些条件后，参会调用getbean()方法创建对应的Bean对象，并注入到IOC容器中。

所以，使用@Lazy注解指定延迟创建对象后，启动IOC容器时并不会创建对应的单例Bean，而是在第一次使用对应的Bean对象时，才会创建对应的单例Bean对象。

后续的源码执行流程与第7章5.3小节的源码执行流程相同，这里不再赘述。

至此，@Lazy注解在Spring源码层面创建单例Bean的执行流程分析完毕。

## 六、总结

`@Lazy注解介绍完了，我们一起总结下吧！`

本章，首先介绍了@Lazy注解的源码和使用场景，随后介绍了@Lazy的使用案例。接下来，详细介绍了@Lazy在Spring中执行的源码时序图和源码流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Lazy注解，通常会有如下几个经典面试题：

* @Lazy注解的作用是什么？
* @Lazy注解有哪些使用场景？
* @Lazy注解延迟创建Bean是如何实现的？
* @Lazy注解在Spring内部的执行流程？
* 你在平时工作中，会在哪些场景下使用@Lazy注解？
* 你从@Lazy注解的设计中得到了哪些启发？

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