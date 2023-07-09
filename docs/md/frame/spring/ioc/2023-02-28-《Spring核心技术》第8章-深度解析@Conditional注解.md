---
layout: post
category: binghe-code-spring
title: 第08章：深度解析@Conditional注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第08章：深度解析@Conditional注解
lock: need
---

# 《Spring核心技术》第08章-条件型注解：深度解析@Conditional注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-08](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-08)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Conditional注解指定创建Bean条件的案例和流程，从源码级别彻底掌握@Conditional注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
  * 无条件案例
  * 标注到方法上的案例
  * 标注到类上的案例
  * 同时标注到类和方法上的案例
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring是如何根据条件创建Bean的？`

日常工作过程中，相信这种情况是最常见的：根据某个或某些条件来执行相应的逻辑。换句话说，会通过`if-else`语句来执行一定的业务逻辑功能。

在Spring中，就有这样一个注解，它支持根据一定的条件来创建对应的Bean对象，并将Bean对象注册到IOC容器中。满足条件的Bean就会被注册到IOC容器中，不满足条件的Bean就不会被注册到IOC容器中。这个注解就是@Conditional注解，本章，就对@Conditional注解进行简单的介绍。

## 二、注解说明

`关于@Conditional注解的一点点说明~~`

Spring提供的@Conditional注解支持按照条件向IOC容器中注册Bean，满足条件的Bean就会被注册到IOC容器中，不满足条件的Bean就不会被注册到IOC容器中。

### 2.1 注解源码

@Conditional注解可以标注到类或方法上，能够实现按照条件向IOC容器中注册Bean。源码详见：org.springframework.context.annotation.Conditional。

```java
/**
 * @author Phillip Webb
 * @author Sam Brannen
 * @since 4.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Conditional {
	Class<? extends Condition>[] value();
}
```

从@Conditional注解的源码可以看出，@Conditional注解是从Spring 4.0版本开始提供的注解。在@Conditional注解注解中只提供了一个Class数组类型的value属性，具体含义如下所示。

* value：指定Condition接口的实现类，Condition接口的实现类中需要编写具体代码实现向Spring中注入Bean的条件。

### 2.2 使用场景

如果使用Spring开发的应用程序需要根据不同的运行环境来读取不同的配置信息，例如在Windows操作系统上需要读取Windows操作系统的环境信息，在MacOS操作系统上需要读取MacOS操作系统的环境信息。此时，就可以使用@Conditional注解实现。

另外，@Conditional注解还有如下一些使用场景：

- 可以作为类级别的注解直接或者间接的与@Component相关联，包括@Configuration类。
- 可以作为元注解，用于自动编写构造性注解。
- 作为方法级别的注解，作用在任何@Bean的方法上。

## 三、使用案例

`@Conditional注解案例实战~~`

Spring的@Conditional注解可以标注到类或方法上，并且会实现按照一定的条件将对应的Bean注入到IOC容器中。所以，本节，会列举无条件（不加@Conditional注解）、@Conditional注解标注到方法上和@Conditional注解标注到类上以及将@Conditional注解同时标注到类上和方法上等四个主要案例。

### 3.1 无条件案例

本节，主要实现不使用@Conditional注解时，向IOC容器中注入Bean的案例，具体实现步骤如下所示。

**（1）新增Founder类**

Founder类的源码详见：spring-annotation-chapter-08工程下的io.binghe.spring.annotation.chapter08.bean.Founder。

```java
public class Founder {
    private String name;
    public Founder(String name) {
        this.name = name;
    }
    @Override
    public String toString() {
        return "Person{" +  "name='" + name + '\'' + '}';
    }
}
```

可以看到，Founder类就是Java中的一个普通实体类。

**（2）新增ConditionalConfig类**

ConditionalConfig类的源码详见：spring-annotation-chapter-08工程下的io.binghe.spring.annotation.chapter08.config.ConditionalConfig。

```java
@Configuration
public class ConditionalConfig {
    @Bean(name = "bill")
    public Founder windowsFounder(){
        return new Founder("Bill Gates");
    }
    @Bean(name = "jobs")
    public Founder macosFounder(){
        return new Founder("Steve Jobs");
    }
}
```

可以看到，ConditionalConfig类是一个Spring的配置类，并且在ConditionalConfig类中使用@Bean注解创建了两个Bean对象，并注册到IOC容器中，一个Bean的名称为bill，另一个Bean的名称为jobs。

**（3）新增ConditionalTest类**

ConditionalTest类的源码详见：spring-annotation-chapter-08工程下的io.binghe.spring.annotation.chapter08.ConditionalTest。

```java
public class ConditionalTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ConditionalConfig.class);
        String[] definitionNames = context.getBeanDefinitionNames();
        Arrays.stream(definitionNames).forEach((definitionName) -> System.out.println(definitionName));
    }
}
```

可以看到，在ConditionalTest类的main()方法中，会打印注入到IOC容器中的Bean名称。

**（4）运行ConditionalTest类**

运行ConditionalTest类的main()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
conditionalConfig
bill
jobs
```

从输出的结果信息可以看出，向IOC容器中注入了名称为conditionalConfig、bill和jobs的Bean。

**说明：没设置@Conditional注解时，会向Spring容器中注入所有使用@Bean注解创建的Bean。**

### 3.2 标注到方法上的案例

本节，主要实现将@Conditional注解标注到方法上，向IOC容器中注入Bean的案例，具体实现步骤如下所示。

**注意：本节的案例是在3.1节的基础上进行完善，在对应的方法上添加@Conditional注解。**

**（1）新增WindowsCondition类**

WindowsCondition类的源码详见：spring-annotation-chapter-08工程下的io.binghe.spring.annotation.chapter08.condition.WindowsCondition。

```java
public class WindowsCondition implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String osName = context.getEnvironment().getProperty("os.name");
        return osName.toLowerCase().contains("windows");
    }
}
```

可以看到，WindowsCondition类实现了Condition接口，并实现了matches()方法。在matches()方法中，通过Spring的环境变量读取操作系统名称，如果操作系统名称中包含windows就返回true，否则返回false。当返回true时，使用@Conditional注解指定的条件为WindowsCondition类的Class对象的Bean会被创建并注入到IOC容器中。

**（2）新增MacosCondition类**

MacosCondition类的源码详见：spring-annotation-chapter-08工程下的io.binghe.spring.annotation.chapter08.condition.MacosCondition。

```java
public class MacosCondition implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String osName = context.getEnvironment().getProperty("os.name");
        return osName.toLowerCase().contains("mac");
    }
}
```

可以看到，MacosCondition类实现了Condition接口，并实现了matches()方法。在matches()方法中，通过Spring的环境变量读取操作系统名称，如果操作系统名称中包含mac就返回true，否则返回false。当返回true时，使用@Conditional注解指定的条件为MacosCondition类的Class对象的Bean会被创建并注入到IOC容器中。

**（3）修改ConditionalConfig类**

在ConditionalConfig类的方法上标注@Conditional注解，修改后的源码如下所示。

```java
@Bean(name = "bill")
@Conditional(value = {WindowsCondition.class})
public Founder windowsFounder(){
    System.out.println("创建名称为bill的Bean对象");
    return new Founder("Bill Gates");
}

@Bean(name = "jobs")
@Conditional(value = {MacosCondition.class})
public Founder macosFounder(){
    System.out.println("创建名称为jobs的Bean对象");
    return new Founder("Steve Jobs");
}
```

可以看到，在创建名称为bill的Bean的方法上标注了@Conditional注解，并指定了value的属性为WindowsCondition类的class对象。在创建名称为jobs的Bean的方法上标注了@Conditional注解，并指定了value的属性为MacosCondition类的class对象。

**（4）运行ConditionalTest类**

运行ConditionalTest类的main()方法，输出的结果信息如下所示。

```java
创建名称为bill的Bean对象
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
conditionalConfig
bill
```

可以看到，由于我的电脑是Windows操作系统，所以，打印出的Bean名称包含conditionalConfig和bill，不包含jobs。

**说明：@Conditional注解标注到使用@Bean创建Bean的方法上时，只有满足@Conditional注解的条件时，才会执行方法体创建Bean对象并注入到IOC容器中。**

### 3.3 标注到类上的案例

本节，主要实现将@Conditional注解标注到类上，向IOC容器中注入Bean的案例，具体实现步骤如下所示。

**注意：本节的案例是在3.1节的基础上进行完善，在对应的类上添加@Conditional注解。**

**（1）修改ConditionalConfig类**

删除ConditionalConfig类中的方法上的@Conditional注解，并在ConditionalConfig类上标注@Conditional注解。

```java
@Configuration
@Conditional(value = {MacosCondition.class})
public class ConditionalConfig {
    @Bean(name = "bill")
    public Founder windowsFounder(){
        System.out.println("创建名称为bill的Bean对象");
        return new Founder("Bill Gates");
    }
    @Bean(name = "jobs")
    public Founder macosFounder(){
        System.out.println("创建名称为jobs的Bean对象");
        return new Founder("Steve Jobs");
    }
}
```

可以看到，在ConditionalConfig类上标注了@Conditional注解，并且将value属性设置为MacosCondition。也就是说，当前操作系统为MacOS操作系统时，才会创建名称为bill和jobs的Bean，并将其注入到IOC容器中。

**（2）运行ConditionalTest类**

运行ConditionalTest类的main()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
```

从输出的结果信息可以看出，由于我的电脑是Windows操作系统，所以，在输出的Bean名称中，并不包含conditionalConfig、bill和jobs。

**说明：当@Conditional注解标注到类上时，如果运行程序时，不满足@Conditional注解中指定的条件，则当前类的所有Bean都不会被创建，也不会注入到IOC容器中。**

### 3.4 同时标注到类和方法上

本节，主要实现将@Conditional注解同时标注到类和方法上，向IOC容器中注入Bean的案例，具体实现步骤如下所示。

**注意：本节的案例是在3.1节的基础上进行完善，在对应的类上添加@Conditional注解。**

**（1）修改ConditionalConfig类**

在ConditionalConfig类的类上和方法上同时标注@Conditional注解。如下所示。

```java
@Configuration
@Conditional(value = {MacosCondition.class})
public class ConditionalConfig {
    @Bean(name = "bill")
    @Conditional(value = {WindowsCondition.class})
    public Founder windowsFounder(){
        System.out.println("创建名称为bill的Bean对象");
        return new Founder("Bill Gates");
    }
    @Bean(name = "jobs")
    @Conditional(value = {MacosCondition.class})
    public Founder macosFounder(){
        System.out.println("创建名称为jobs的Bean对象");
        return new Founder("Steve Jobs");
    }
}
```

可以看到，在ConditionalConfig类的类上和方法上都标注了@Conditional注解。其中，在类上标注的@Conditional注解的条件是当前操作系统为MacOS系统。

**（2）运行ConditionalTest类**

运行ConditionalTest类的main()方法，输出的结果信息如下所示。

```java
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
```

从输出的结果信息可以看出，由于我的电脑是Windows操作系统，所以，在输出的Bean名称中，并不包含conditionalConfig、bill和jobs。

**说明：当@Conditional注解同时标注到类和方法上时，如果标注到类上的@Conditional注解不满足条件，即使类中的方法上标注的@Conditional注解满足条件，也不会创建Bean，并且也不会将Bean注入到IOC容器中。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本节，就以源码时序图的方式，直观的感受下@Conditional注解在Spring源码层面的执行流程。@Conditional注解的源码时序图如图8-1和8-2所示。

![图8-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-28-001.png)



![图8-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-28-002.png)



## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

@Conditional注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻。本节，就简单结合源码时序图简单分析下@Conditional注解在Spring源码层面的执行流程。

**注意：@Conditional注解在Spring源码层面的执行流程与第7章的5.1节@DependsOn注解在Spring源码层面注册Bean的执行流程大体类似，只是在执行AnnotatedBeanDefinitionReader类的doRegisterBean()方法的逻辑时，略有差异。**

（1）解析AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)。

```java
private <T> void doRegisterBean(Class<T> beanClass, @Nullable String name, @Nullable Class<? extends Annotation>[] qualifiers, @Nullable Supplier<T> supplier, @Nullable BeanDefinitionCustomizer[] customizers) {
    AnnotatedGenericBeanDefinition abd = new AnnotatedGenericBeanDefinition(beanClass);
    if (this.conditionEvaluator.shouldSkip(abd.getMetadata())) {
        return;
    }
    abd.setInstanceSupplier(supplier);
    ScopeMetadata scopeMetadata = this.scopeMetadataResolver.resolveScopeMetadata(abd);
    abd.setScope(scopeMetadata.getScopeName());
    String beanName = (name != null ? name : this.beanNameGenerator.generateBeanName(abd, this.registry));
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
    if (customizers != null) {
        for (BeanDefinitionCustomizer customizer : customizers) {
            customizer.customize(abd);
        }
    }
    BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(abd, beanName);
    definitionHolder = AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
    BeanDefinitionReaderUtils.registerBeanDefinition(definitionHolder, this.registry);
}
```

可以看到，在AnnotatedBeanDefinitionReader类的doRegisterBean()方法中，调用了conditionEvaluator对象的shouldSkip()方法判断是否要忽略当前Bean的注册。

（2）解析ConditionEvaluator类的shouldSkip(AnnotatedTypeMetadata metadata)方法

源码详见：org.springframework.context.annotation.ConditionEvaluator#shouldSkip(AnnotatedTypeMetadata metadata)

```java
public boolean shouldSkip(AnnotatedTypeMetadata metadata) {
    return shouldSkip(metadata, null);
}
```

可以看到，在ConditionEvaluator类的shouldSkip()方法中，直接调用了另一个重载的shouldSkip()方法。

（3）解析ConditionEvaluator类的shouldSkip(AnnotatedTypeMetadata metadata, ConfigurationPhase phase)方法

源码详见：org.springframework.context.annotation.ConditionEvaluator#shouldSkip(AnnotatedTypeMetadata metadata, ConfigurationPhase phase)。

```java
public boolean shouldSkip(@Nullable AnnotatedTypeMetadata metadata, @Nullable ConfigurationPhase phase) {
    if (metadata == null || !metadata.isAnnotated(Conditional.class.getName())) {
        return false;
    }

    if (phase == null) {
        if (metadata instanceof AnnotationMetadata &&
            ConfigurationClassUtils.isConfigurationCandidate((AnnotationMetadata) metadata)) {
            return shouldSkip(metadata, ConfigurationPhase.PARSE_CONFIGURATION);
        }
        return shouldSkip(metadata, ConfigurationPhase.REGISTER_BEAN);
    }

    List<Condition> conditions = new ArrayList<>();
    for (String[] conditionClasses : getConditionClasses(metadata)) {
        for (String conditionClass : conditionClasses) {
            Condition condition = getCondition(conditionClass, this.context.getClassLoader());
            conditions.add(condition);
        }
    }

    AnnotationAwareOrderComparator.sort(conditions);

    for (Condition condition : conditions) {
        ConfigurationPhase requiredPhase = null;
        if (condition instanceof ConfigurationCondition) {
            requiredPhase = ((ConfigurationCondition) condition).getConfigurationPhase();
        }
        if ((requiredPhase == null || requiredPhase == phase) && !condition.matches(this.context, metadata)) {
            return true;
        }
    }

    return false;
}
```

可以看到，在shouldSkip()方法中，首先会判断类或方法上是否标注了@Conditional注解，如果没有标注@Conditional注解，则直接返回false，此时对应的Bean会被创建并注入到IOC容器中。否则，会解析@Conditional注解中的value属性设置的Class对象，将Class对象的全类名解析到conditionClasses数组中，遍历conditionClasses数组中的每个元素生成Condition对象，将Condition对象存入conditions集合中。后续会遍历conditions集合中的每个Condition对象，调用matches()方法，此处的逻辑与matches()方法的返回值正好相反。

* matches()方法返回false，则此处返回true，表示对应的Bean不会被创建，也不会注入到IOC容器中。
* matches()方法返回true，则此处返回false，表示对应的Bean会被创建并且会注入到IOC容器中。

接下来，就会回到AnnotatedBeanDefinitionReader类的doRegisterBean()方法继续执行后续流程，后续流程与第7章的5.1节@DependsOn注解在Spring源码层面注册Bean的执行流程一致，这里不再赘述。

至此，@Conditional注解在Spring源码层面的执行流程分析完毕。

## 六、扩展注解

@Conditional的扩展注解如下所示：

**@ConditionalOnBean**：仅仅在当前上下文中存在某个对象时，才会实例化一个Bean。

**@ConditionalOnClass**：某个class位于类路径上，才会实例化一个Bean。

**@ConditionalOnExpression**：当表达式为true的时候，才会实例化一个Bean。

**@ConditionalOnMissingBean**：仅仅在当前上下文中不存在某个对象时，才会实例化一个Bean。

**@ConditionalOnMissingClass**：某个class类路径上不存在的时候，才会实例化一个Bean。

**@ConditionalOnNotWebApplication**：不是web应用，才会实例化一个Bean。

**@ConditionalOnBean**：当容器中有指定Bean的条件下进行实例化。

**@ConditionalOnMissingBean**：当容器里没有指定Bean的条件下进行实例化。

**@ConditionalOnClass**：当classpath类路径下有指定类的条件下进行实例化。

**@ConditionalOnMissingClass**：当类路径下没有指定类的条件下进行实例化。

**@ConditionalOnWebApplication**：当项目是一个Web项目时进行实例化。

**@ConditionalOnNotWebApplication**：当项目不是一个Web项目时进行实例化。

**@ConditionalOnProperty**：当指定的属性有指定的值时进行实例化。

**@ConditionalOnExpression**：基于SpEL表达式的条件判断。

**@ConditionalOnJava**：当JVM版本为指定的版本范围时触发实例化。

**@ConditionalOnResource**：当类路径下有指定的资源时触发实例化。

**@ConditionalOnJndi**：在JNDI存在的条件下触发实例化。

**@ConditionalOnSingleCandidate**：当指定的Bean在容器中只有一个，或者有多个但是指定了首选的Bean时触发实例化。

## 七、总结

`@Conditional注解介绍完了，我们一起总结下吧！`

本章，首先介绍了@Conditional注解的源码和使用场景。随后，列举了四个关于@Conditional注解的案例，分别是：无条件案例、标注到方法上的案例、标注到类上的案例和同时标注到类和方法上的案例。接下来，介绍了@Conditional注解执行的源码时序图和源码流程。

## 八、思考

`既然学完了，就开始思考几个问题吧？`

关于@Conditional注解，通常会有如下几个经典面试题：

* @Conditional注解的作用是什么？
* @Conditional注解有哪些使用场景？
* @Conditional注解与@Profile注解有什么区别？
* @Conditional注解在Spring内层的执行流程？
* 你在平时工作中，会在哪些场景下使用@Conditional注解？
* 你从@Conditional注解的设计中得到了哪些启发？

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