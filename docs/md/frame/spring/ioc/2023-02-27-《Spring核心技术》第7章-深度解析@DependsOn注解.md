---
layout: post
category: binghe-code-spring
title: 第07章：深度解析@DependsOn注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第07章：深度解析@DependsOn注解
lock: need
---

# 《Spring核心技术》第07章-条件型注解：深度解析@DependsOn注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-07](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-07)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@DependsOn注解指定Bean依赖顺序的案例和流程，从源码级别彻底掌握@DependsOn注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
* 使用案例
  * 标注到类上的案例
  * 标注到方法上的案例
* 源码时序图
  * 注册Bean的源码时序图
  * 调用Bean工厂后置处理器的源码时序图
  * 创建Bean的源码时序图
* 源码解析
  * 注册Bean的源码流程
  * 调用Bean工厂后置处理器的源码流程
  * 创建Bean的源码流程
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring创建Bean时如何指定Bean的依赖顺序呢？`

在实际开发项目的过程中，经常会遇到这样一种场景：在开发一个A功能模块时，这个A功能模块可能会依赖另一个B功能模块。此时，就需要先开发B功能模块，然后在开发A功能模块，在A功能模块中调用B功能模块的功能。

在Spring中创建Bean对象也是如此，可以通过某种方式指定Spring中创建Bean的依赖顺序，Spring会根据创建Bean的依赖顺序来创建对应的Bean对象。这个指定创建Bean依赖顺序的注解就是@DependsOn注解。

本章，就一起深入探讨下Spring的@DependsOn注解。

## 二、注解说明

`关于@DependsOn注解的一点点说明~~`

@DependsOn注解是Spring中提供的一个指定Spring创建Bean的依赖顺序的注解。例如，在Spring中需要创建A对象和B对象，可以使用@DependsOn注解指定创建A对象时依赖B对象，此时，在Spring中就会先创建B对象，然后再创建A对象。

### 2.1 注解源码

@DependsOn注解可以标注到类或方法上，可以控制bean的创建、初始化和销毁方法的执行顺序。源码详见：org.springframework.context.annotation.DependsOn。

```java
/**
 * @author Juergen Hoeller
 * @since 3.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface DependsOn {
	String[] value() default {};
}
```

从@DependsOn注解的源码可以看出，@DependsOn注解是从Spring 3.0版本开始提供的注解。其中，只提供了一个String数组类型的value属性，含义如下所示。

* value：表示指定的Bean的唯一标识，被指定的Bean会在Spring创建当前Bean之前被创建。

### 2.2 注解使用场景

@DependsOn注解主要用于指定当前Bean对象所依赖的其他Bean对象。Spring在创建当前Bean之前，会先创建由@DependsOn注解指定的依赖Bean，在Spring中使用@DependsOn注解的场景通常会有以下几种场景：

（1）在某些情况下，Bean不是通过`属性`或`构造函数参数`显式依赖于另一个Bean的，但是却需要在创建一个Bean对象之前，需要先创建另一个Bean对象，此时就可以使用@DependsOn注解。

（2）在单例Bean的情况下`@DependsOn`既可以指定**初始化依赖顺序**，也可以指定Bean相应的**销毁执行顺序**。

（3）@DependsOn注解可标注到任何直接或间接带有@Component注解的Bean或标注到@Bean注解的方法上，可以控制Bean的创建、初始化和销毁方法执行顺序。

（4）观察者模式可以分为事件，事件源和监听器三个组件，如果在Spring中需要实现观察者模式时，就可以使用@DependsOn注解实现监听器的Bean对象在事件源的Bean对象之前被创建。

## 三、使用案例

`@DependsOn注解案例实战~~`

Spring的@DependsOn注解可以标注到类或方法上，所以，本节，会列举@DependsOn注解标注到类和方法上两个案例。

### 3.1 标注到类上的案例

本节，主要使用@DependsOn注解标注到类上来实现Spring创建Bean的依赖顺序案例，具体实现步骤如下所示。

**（1）新建DependsOnClassA类**

DependsOnClassA类的源码详见：spring-annotation-chapter-07工程下的io.binghe.spring.annotation.chapter07.bean.DependsOnClassA。

```java
@Component(value = "dependsOnClassA")
@DependsOn(value = {"dependsOnClassB"})
public class DependsOnClassA {
    private final Logger logger = LoggerFactory.getLogger(DependsOnClassA.class);
    public DependsOnClassA(){
        logger.info("执行DependsOnClassA的构造方法");
    }
}
```

可以看到，DependsOnClassA类上使用@Component注解标注，并且指定了Bean的名称为dependsOnClassA，以及使用@DependsOn注解指定了依赖的Bean名称为dependsOnClassB。

**（2）新建DependsOnClassB类**

DependsOnClassB类的源码详见：spring-annotation-chapter-07工程下的io.binghe.spring.annotation.chapter07.bean.DependsOnClassB。

```java
@Component(value = "dependsOnClassB")
public class DependsOnClassB {
    private final Logger logger = LoggerFactory.getLogger(DependsOnClassB.class);
    public DependsOnClassB(){
        logger.info("执行DependsOnClassB的构造方法");
    }
}
```

可以看到，在DependsOnClassB类上标注了@Component注解，指定了Bean对象的名称为dependsOnClassB。

由DependsOnClassA类和DependsOnClassB类可以看出，在Spring中创建DependsOnClassA类的对象时，会依赖DependsOnClassB类的对象。所以，在Spring中，创建DependsOnClassA类的对象之前，会先创建DependsOnClassB类的对象。

**（3）新建DependsOnConfig类**

DependsOnConfig类的源码详见：spring-annotation-chapter-07工程下的io.binghe.spring.annotation.chapter07.config.DependsOnConfig。

```java
@Configuration
@ComponentScan(basePackages = "io.binghe.spring.annotation.chapter07")
public class DependsOnConfig {
}
```

可以看到，DependsOnConfig类的实现比较简单，在DependsOnConfig类上标注了@Configuration注解，表示这是一个Spring的配置类，并且使用@ComponentScan注解指定了扫描的基础包名。

**（4）新建DependsOnTest类**

DependsOnTest类的源码详见：spring-annotation-chapter-07工程下的io.binghe.spring.annotation.chapter07.DependsOnTest。

```java
public class DependsOnTest {
    public static void main(String[] args) {
        new AnnotationConfigApplicationContext(DependsOnConfig.class);
    }
}
```

可以看到，DependsOnTest类作为测试案例的启动类，整体实现比较简单，就是在main()方法中创建Spring的IOC容器。

**（5）测试DependsOnTest类**

运行DependsOnTest类中的main()方法，输出的结果信息如下所示。

```java
14:56:17.977 [main] INFO DependsOnClassB - 执行DependsOnClassB的构造方法
14:56:17.978 [main] INFO DependsOnClassA - 执行DependsOnClassA的构造方法
```

**可以看到，当@DependsOn注解标注到类上时，Spring在创建标注了@DependsOn注解的类的Bean对象之前，会先创建使用@DependsOn注解指定的Bean对象。**

### 3.2 标注到方法上的案例

本节，主要使用@DependsOn注解标注到方法上来实现Spring创建Bean的依赖顺序案例，并且本节的案例程序是在3.1节的基础上扩展，具体实现步骤如下所示。

**（1）新建DependsOnMethodA类**

DependsOnMethodA类的源码详见：spring-annotation-chapter-07工程下的io.binghe.spring.annotation.chapter07.bean.DependsOnMethodA。

```java
public class DependsOnMethodA {
    private final Logger logger = LoggerFactory.getLogger(DependsOnMethodA.class);
    public DependsOnMethodA(){
        logger.info("执行DependsOnMethodA的构造方法");
    }
}
```

可以看到，DependsOnMethodA类就是一个简单的实体类，这里不再赘述。

**（2）新增DependsOnMethodB类**

DependsOnMethodB类的源码详见：spring-annotation-chapter-07工程下的io.binghe.spring.annotation.chapter07.bean.DependsOnMethodB。

```java
public class DependsOnMethodB {
    private final Logger logger = LoggerFactory.getLogger(DependsOnMethodB.class);
    public DependsOnMethodB(){
        logger.info("执行DependsOnMethodB的构造方法");
    }
}
```

可以看到，DependsOnMethodB类就是一个简单的实体类，这里不再赘述。

**（3）修改DependsOnConfig类**

在DependsOnConfig类中使用@Bean注解分别创建DependsOnMethodA类和DependsOnMethodB类的Bean对象，如下所示。

```java
@DependsOn(value = {"dependsOnMethodB"})
@Bean(value = "dependsOnMethodA")
public DependsOnMethodA dependsOnMethodA(){
    return new DependsOnMethodA();
}

@Bean(value = "dependsOnMethodB")
public DependsOnMethodB dependsOnMethodB(){
    return new DependsOnMethodB();
}
```

可以看到，在DependsOnConfig类中使用@Bean注解创建DependsOnMethodA类的Bean对象时，使用@DependsOn注解依赖了名称为dependsOnMethodB的Bean对象。

**（4）测试DependsOnTest类**

运行DependsOnTest类中的main()方法，输出的结果信息如下所示。

```bash
15:16:24.523 [main] INFO DependsOnClassB - 执行DependsOnClassB的构造方法
15:16:24.524 [main] INFO DependsOnClassA - 执行DependsOnClassA的构造方法
15:16:24.528 [main] INFO DependsOnMethodB - 执行DependsOnMethodB的构造方法
15:16:24.529 [main] INFO DependsOnMethodA - 执行DependsOnMethodA的构造方法
```

**可以看到，当@DependsOn注解标注到方法上时，Spring在执行标注了@DependsOn注解的方法创建Bean对象前，先执行其他方法来创建使用@DependsOn注解指定的Bean对象。**

**通过上述两个案例得知：@DependsOn注解可以指定Spring中Bean对象创建的依赖顺序，并且Spring在创建当前Bean之前，会先创建由@DependsOn注解指定的依赖Bean**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本节，就以源码时序图的方式，直观的感受下@DependsOn注解在Spring源码层面的执行流程。本节，主要从注册Bean、调用Bean工厂后置处理器和创建Bean三个方面分析源码时序图。

### 4.1 注册Bean的源码时序图

@DependsOn注解涉及到的注册Bean的源码时序图如图7-1所示。

![图7-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-27-001.png)

由图7-1可以看出，@DependsOn注解在注册Bean的流程中涉及到DependsOnTest类、AnnotationConfigApplicationContext类、AnnotatedBeanDefinitionReader类、AnnotationConfigUtils类、BeanDefinitionReaderUtils类和DefaultListableBeanFactory类。具体的源码执行细节参见源码解析部分。 

### 4.2 调用Bean工厂后置处理器的源码时序图

@DependsOn注解涉及到的调用Bean工厂后置处理器的源码时序图如图7-2~7-4所示。

![图7-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-27-002.png)



![图7-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-27-003.png)



![图7-4](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-27-004.png)

由图7-2~7-4可以看出，@DependsOn注解涉及到的调用Bean工厂后置处理器的流程涉及到DependsOnTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、ComponentScanAnnotationParser类、ClassPathBeanDefinitionScanner类、AnnotationConfigUtils类、BeanDefinitionReaderUtils类和DefaultListableBeanFactory类。具体的源码执行细节参见源码解析部分。 

### 4.3 创建Bean的源码时序图

@DependsOn注解涉及到的创建Bean的源码时序图如图7-5所示。

![图7-5](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-27-005.png)

由图7-5可以看出，@DependsOn注解涉及到的创建Bean的流程涉及到DependsOnTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类和AbstractBeanFactory类。具体的源码执行细节参见源码解析部分。 

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

本节，主要分析@DependsOn注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻。本节，同样会从注册Bean、调用Bean工厂后置处理器和创建Bean三个方面分析源码的执行流程

### 5.1 注册Bean的源码流程

@DependsOn注解在Spring源码层面注册Bean的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图7-1进行理解。

（1）运行案例程序启动类

案例程序启动类源码详见：spring-annotation-chapter-07工程下的io.binghe.spring.annotation.chapter07.DependsOnTest，运行DependsOnTest类的main()方法。

在DependsOnTest类的main()方法中调用了AnnotationConfigApplicationContext类的构造方法，并传入了DependsOnConfig类的Class对象来创建IOC容器。接下来，会进入AnnotationConfigApplicationContext类的构造方法。

（2）解析AnnotationConfigApplicationContext类的AnnotationConfigApplicationContext(Class<?>... componentClasses)构造方法

源码详见：org.springframework.context.annotation.AnnotationConfigApplicationContext#AnnotationConfigApplicationContext(Class<?>... componentClasses)。

```java
public AnnotationConfigApplicationContext(Class<?>... componentClasses) {
    this();
    register(componentClasses);
    refresh();
}
```

可以看到，在上述构造方法中，调用了register()方法来注册Bean。

（3）解析AnnotationConfigApplicationContext类的register(Class<?>... componentClasses) 方法

源码详见：org.springframework.context.annotation.AnnotationConfigApplicationContext#register(Class<?>... componentClasses) 。

```java
@Override
public void register(Class<?>... componentClasses) {
    /************省略其他代码***************/
    this.reader.register(componentClasses);
    registerComponentClass.end();
}
```

可以看到，在AnnotationConfigApplicationContext类的register()方法中，调用reader对象的register()方法注册Bean。

（4）解析AnnotatedBeanDefinitionReader类的register(Class<?>... componentClasses)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#register(Class<?>... componentClasses)。

```java
public void register(Class<?>... componentClasses) {
    for (Class<?> componentClass : componentClasses) {
        registerBean(componentClass);
    }
}
```

可以看到，在AnnotatedBeanDefinitionReader类的register()方法中，会循环遍历传入的componentClasses数组，并将遍历出的每个componentClass元素作为参数调用registerBean()方法注册Bean。

（5）解析AnnotatedBeanDefinitionReader类的registerBean(Class<?> beanClass)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#registerBean(Class<?> beanClass)。

```java
public void registerBean(Class<?> beanClass) {
    doRegisterBean(beanClass, null, null, null, null);
}
```

可以看到，在AnnotatedBeanDefinitionReader类的registerBean()方法中会调用doRegisterBean()方法来注册Bean。

（6）解析AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)。重点关注如下代码片段。

```java
private <T> void doRegisterBean(Class<T> beanClass, @Nullable String name, @Nullable Class<? extends Annotation>[] qualifiers, @Nullable Supplier<T> supplier, @Nullable BeanDefinitionCustomizer[] customizers) {
    /******************省略其他代码**********************/
    AnnotationConfigUtils.processCommonDefinitionAnnotations(abd);
    /******************省略其他代码**********************/
    BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(abd, beanName);
    definitionHolder = AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
    BeanDefinitionReaderUtils.registerBeanDefinition(definitionHolder, this.registry);
}
```

可以看到，在AnnotatedBeanDefinitionReader类的doRegisterBean()方法中，会调用AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法。

（7）解析AnnotationConfigUtils类的processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd)方法

源码详见：org.springframework.context.annotation.AnnotationConfigUtils#processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd)

```java
public static void processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd) {
    processCommonDefinitionAnnotations(abd, abd.getMetadata());
}
```

可以看到，在AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法中调用了具有两个参数的processCommonDefinitionAnnotations()方法。

（8）解析AnnotationConfigUtils类的processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata)方法

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

    if (metadata.isAnnotated(Primary.class.getName())) {
        abd.setPrimary(true);
    }
    AnnotationAttributes dependsOn = attributesFor(metadata, DependsOn.class);
    if (dependsOn != null) {
        abd.setDependsOn(dependsOn.getStringArray("value"));
    }

    AnnotationAttributes role = attributesFor(metadata, Role.class);
    if (role != null) {
        abd.setRole(role.getNumber("value").intValue());
    }
    AnnotationAttributes description = attributesFor(metadata, Description.class);
    if (description != null) {
        abd.setDescription(description.getString("value"));
    }
}
```

可以看到，在processCommonDefinitionAnnotations()方法中，解析了@DependsOn注解，并将解析出的@DependsOn注解中的value属性的值设置到AnnotatedBeanDefinition对象的dependsOn属性中。

（9）回到AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法。

在AnnotatedBeanDefinitionReader类的doRegisterBean()方法中，会调用BeanDefinitionReaderUtils类的registerBeanDefinition()方法，并将封装了@DependsOn注解属性的abd对象和beanName封装成BeanDefinitionHolder对象，并且与registry一起作为参数传递给BeanDefinitionReaderUtils类的registerBeanDefinition()方法。

（10）解析BeanDefinitionReaderUtils类的registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)方法

源码详见：org.springframework.beans.factory.support.BeanDefinitionReaderUtils#registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)。

```java
public static void registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry) throws BeanDefinitionStoreException {
    String beanName = definitionHolder.getBeanName();
    registry.registerBeanDefinition(beanName, definitionHolder.getBeanDefinition());
    String[] aliases = definitionHolder.getAliases();
    if (aliases != null) {
        for (String alias : aliases) {
            registry.registerAlias(beanName, alias);
        }
    }
}
```

可以看到，在registerBeanDefinition()方法中，会调用DefaultListableBeanFactory类的registerBeanDefinition()方法将BeanDefinition信息注册到IOC容器中。

（11）解析DefaultListableBeanFactory类的registerBeanDefinition(String beanName, BeanDefinition beanDefinition)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#registerBeanDefinition(String beanName, BeanDefinition beanDefinition)。重点关注如下代码片段。

```java
@Override
public void registerBeanDefinition(String beanName, BeanDefinition beanDefinition) throws BeanDefinitionStoreException {
	/*********省略其他代码**********/
	BeanDefinition existingDefinition = this.beanDefinitionMap.get(beanName);
	if (existingDefinition != null) {
		/*********省略其他代码**********/
	}
	else {
		/*********省略其他代码**********/
		else {
			// Still in startup registration phase
			this.beanDefinitionMap.put(beanName, beanDefinition);
			this.beanDefinitionNames.add(beanName);
			removeManualSingletonName(beanName);
		}
		this.frozenBeanDefinitionNames = null;
	}
    /*********省略其他代码**********/
}
```

可以看到，在DefaultListableBeanFactory类的registerBeanDefinition()方法中，会将beanName为Key，beanDefinition对象作为Value保存到beanDefinitionMap中。

至此，@DependsOn注解涉及到的注册Bean的源码流程分析完毕。

### 5.2 调用Bean工厂后置处理器的源码流程

@DependsOn注解在Spring源码层面调用Bean工厂后置处理器的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图7-2~7-4进行理解。

**注意：@DependsOn注解在Spring源码层面调用Bean工厂后置处理器的执行流程，执行到ConfigurationClassParser类的doProcessConfigurationClass()方法之前的逻辑与第5章解析@Import注解的代码流程相同，这里不再赘述。后续的代码流程直接从ConfigurationClassParser类的doProcessConfigurationClass()方法开始解析。**

（1）解析ConfigurationClassParser类的doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)方法

源码详见：org.springframework.context.annotation.ConfigurationClassParser#doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)，重点关注如下代码片段。

```java
protected final SourceClass doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter) throws IOException {
    /****************省略其他代码****************/
    Set<AnnotationAttributes> componentScans = AnnotationConfigUtils.attributesForRepeatable(
        sourceClass.getMetadata(), ComponentScans.class, ComponentScan.class);
    if (!componentScans.isEmpty() &&
        !this.conditionEvaluator.shouldSkip(sourceClass.getMetadata(), ConfigurationPhase.REGISTER_BEAN)) {
        for (AnnotationAttributes componentScan : componentScans) {
            Set<BeanDefinitionHolder> scannedBeanDefinitions =
                this.componentScanParser.parse(componentScan, sourceClass.getMetadata().getClassName());
            for (BeanDefinitionHolder holder : scannedBeanDefinitions) {
                BeanDefinition bdCand = holder.getBeanDefinition().getOriginatingBeanDefinition();
                if (bdCand == null) {
                    bdCand = holder.getBeanDefinition();
                }
                if (ConfigurationClassUtils.checkConfigurationClassCandidate(bdCand, this.metadataReaderFactory)) {
                    parse(bdCand.getBeanClassName(), holder.getBeanName());
                }
            }
        }
    }
    /****************省略其他代码****************/
    return null;
}
```

可以看到，在ConfigurationClassParser类的doProcessConfigurationClass()方法中，会调用componentScanParser的parse()方法来解析配置类上的注解。

（2）解析ComponentScanAnnotationParser类的parse(AnnotationAttributes componentScan, String declaringClass)方法

源码详见：org.springframework.context.annotation.ComponentScanAnnotationParser#parse(AnnotationAttributes componentScan, String declaringClass)。

```java
public Set<BeanDefinitionHolder> parse(AnnotationAttributes componentScan, String declaringClass) {
    /***********省略其他代码*************/
    return scanner.doScan(StringUtils.toStringArray(basePackages));
}
```

可以看到，在ComponentScanAnnotationParser类的parse()方法中，会调用scanner对象的doScan()方法扫描@ComponentScan注解中basePackages属性设置的包名。

（3）解析ClassPathBeanDefinitionScanner类中的doScan(String... basePackages)方法

源码详见：org.springframework.context.annotation.ClassPathBeanDefinitionScanner#doScan(String... basePackages)。

```java
protected Set<BeanDefinitionHolder> doScan(String... basePackages) {
    Assert.notEmpty(basePackages, "At least one base package must be specified");
    Set<BeanDefinitionHolder> beanDefinitions = new LinkedHashSet<>();
    for (String basePackage : basePackages) {
        Set<BeanDefinition> candidates = findCandidateComponents(basePackage);
        for (BeanDefinition candidate : candidates) {
            /************省略其他代码************/
            if (candidate instanceof AnnotatedBeanDefinition) {
                AnnotationConfigUtils.processCommonDefinitionAnnotations((AnnotatedBeanDefinition) candidate);
            }
            if (checkCandidate(beanName, candidate)) {
                BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(candidate, beanName);
                definitionHolder = AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
                beanDefinitions.add(definitionHolder);
                registerBeanDefinition(definitionHolder, this.registry);
            }
        }
    }
    return beanDefinitions;
}
```

可以看到，在ClassPathBeanDefinitionScanner类中的doScan()方法中，会调用AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法来解析注解的信息。后续的执行流程与5.1节中源码解析的步骤（7）~（8）相同，这里不再赘述。

另外，在ClassPathBeanDefinitionScanner类中的doScan()方法中，会调用registerBeanDefinition()方法来注册BeanDefinition信息。

（4）解析ClassPathBeanDefinitionScanner类的registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)方法

源码详见：org.springframework.context.annotation.ClassPathBeanDefinitionScanner#registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)。

```java
protected void registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry) {
    BeanDefinitionReaderUtils.registerBeanDefinition(definitionHolder, registry);
}
```

可以看到，在ClassPathBeanDefinitionScanner类的registerBeanDefinition()方法中，直接调用了BeanDefinitionReaderUtils类的registerBeanDefinition()方法来注册BeanDefinition信息。

（5）解析BeanDefinitionReaderUtils类的registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)方法

源码详见：org.springframework.beans.factory.support.BeanDefinitionReaderUtils#registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)。

```java
public static void registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)throws BeanDefinitionStoreException {
    String beanName = definitionHolder.getBeanName();
    registry.registerBeanDefinition(beanName, definitionHolder.getBeanDefinition());
    /*********省略其他代码************/
}
```

可以看到，在BeanDefinitionReaderUtils类的registerBeanDefinition()方法中，最终就会调用DefaultListableBeanFactory类的registerBeanDefinition()方法来注册BeanDefinition信息。

至此，@DependsOn注解在Spring源码层面调用Bean工厂后置处理器的执行流程分析完毕。

### 5.3 创建Bean的源码流程

@DependsOn注解在Spring源码层面创建Bean的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图7-5进行理解。

**注意：@DependsOn注解在Spring源码层面创建Bean的执行流程，执行到AbstractApplicationContext类的refresh()方法的逻辑，与第5章解析@Import注解执行到AbstractApplicationContext类的refresh()方法的逻辑相同，这里不再赘述。后续会直接从AbstractApplicationContext类的refresh()方法开始分析源码。**

（1）解析AbstractApplicationContext类的refresh()方法

源码详见：org.springframework.context.support.AbstractApplicationContext#refresh()，重点关注如下代码片段。

```java
@Override
public void refresh() throws BeansException, IllegalStateException {
    synchronized (this.startupShutdownMonitor) {
       /*********省略其他代码************/
        try {
            /*********省略其他代码************/
            finishBeanFactoryInitialization(beanFactory);
			/*********省略其他代码************/
        }
        catch (BeansException ex) {
            /*********省略其他代码************/
        }
        finally {
            /*********省略其他代码************/
        }
    }
}
```

可以看到，在refresh()中会调用finishBeanFactoryInitialization()方法来完成非懒加载的单实例Bean的初始化工作。

（2）解析finishBeanFactoryInitialization类的finishBeanFactoryInitialization(ConfigurableListableBeanFactory beanFactory)方法

源码详见：org.springframework.context.support.AbstractApplicationContext#finishBeanFactoryInitialization(ConfigurableListableBeanFactory beanFactory)。

```java
protected void finishBeanFactoryInitialization(ConfigurableListableBeanFactory beanFactory) {
    /*******省略其他代码*******/
    beanFactory.preInstantiateSingletons();
}
```

可以看到，在finishBeanFactoryInitialization类的finishBeanFactoryInitialization()方法中，会调用beanFactory对象的preInstantiateSingletons()方法来初始化所有的非懒加载的单实例Bean。

（3）解析DefaultListableBeanFactory类的preInstantiateSingletons()方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#preInstantiateSingletons()。重点关注如下代码片段。

```java
@Override
public void preInstantiateSingletons() throws BeansException {
    /*********省略其他代码*********/
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
	/*********省略其他代码*********/
}
```

可以看到，在DefaultListableBeanFactory类的preInstantiateSingletons()方法中，会遍历beanDefinitionNames集合中所有的beanName，并调用getBean()方法初始化所有非懒加载的单实例Bean。

（4）解析AbstractBeanFactory类的getBean(String name)方法

源码详见：org.springframework.beans.factory.support.AbstractBeanFactory#getBean(String name)。

```java
@Override
public Object getBean(String name) throws BeansException {
    return doGetBean(name, null, null, false);
}
```

可以看到，在AbstractBeanFactory类的getBean()方法中，直接调用了doGetBean()方法来初始化非懒加载的单实例Bean。

（5）解析AbstractBeanFactory类的doGetBean(String name, Class<T> requiredType, Object[] args, boolean typeCheckOnly)方法

源码详见：org.springframework.beans.factory.support.AbstractBeanFactory#doGetBean(String name, Class<T> requiredType, Object[] args, boolean typeCheckOnly)。重点关注如下代码片段。

```java
protected <T> T doGetBean(String name, @Nullable Class<T> requiredType, @Nullable Object[] args, boolean typeCheckOnly) throws BeansException {
	/*************省略其他代码**************/
	else {
		/*************省略其他代码**************/
		try {
			/*************省略其他代码**************/
			String[] dependsOn = mbd.getDependsOn();
			if (dependsOn != null) {
				for (String dep : dependsOn) {
					if (isDependent(beanName, dep)) {
						throw new BeanCreationException(mbd.getResourceDescription(), beanName,
								"Circular depends-on relationship between '" + beanName + "' and '" + dep + "'");
					}
					registerDependentBean(dep, beanName);
					try {
						getBean(dep);
					}
					catch (NoSuchBeanDefinitionException ex) {
						throw new BeanCreationException(mbd.getResourceDescription(), beanName,
								"'" + beanName + "' depends on missing bean '" + dep + "'", ex);
					}
				}
			}
			/*************省略其他代码**************/
		}
		catch (BeansException ex) {
			beanCreation.tag("exception", ex.getClass().toString());
			beanCreation.tag("message", String.valueOf(ex.getMessage()));
			cleanupAfterBeanCreationFailure(beanName);
			throw ex;
		}
		finally {
			beanCreation.end();
		}
	}
	return adaptBeanInstance(name, beanInstance, requiredType);
}
```

可以看到，在AbstractBeanFactory类的doGetBean()方法中，会获取这些被依赖的beanName，按照数组顺序，再调用AbstractBeanFactory类的getBean()方法来优先创建被依赖的Bean，从而达到控制依赖顺序的目的。

另外，在创建Bean时，还会调用AbstractBeanFactory类的registerDisposableBeanIfNecessary()方法，向Spring中注册带有销毁方法的Bean，源码详见：org.springframework.beans.factory.support.DefaultSingletonBeanRegistry#registerDisposableBean(String beanName, DisposableBean bean)，在DefaultSingletonBeanRegistry类的registerDisposableBean()方法内部会通过LinkedHashMap保存带有销毁方法的Bean。其中，key为Bean的名称。当关闭Spring应用时，会逆序调用Bean的销毁方法。

**注意：本节不再详细阐述获取到Bean的依赖后，详细创建Bean的流程，后续会有专门的章节详细介绍创建单例Bean和多例Bean的流程。**

至此，@DependsOn注解在Spring源码层面创建Bean的执行流程分析完毕。

## 六、总结

`@DependsOn注解介绍完了，我们一起总结下吧！`

本章，首先介绍了@DependsOn注解的源码和使用场景。随后，给出了两个关于@DependsOn注解的案例，分别是标注到类上的案例和标注到方法上的案例。接下来，分别从注册Bean、调用Bean工厂后置处理器和创建Bean三个方面详细给出了@DependsOn注解在Spring源码中的执行时序图和对应的源码执行流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@DependsOn注解，通常会有如下几个经典面试题：

* @DependsOn注解的作用是什么？
* @DependsOn注解是如何指定Bean的依赖顺序的？
* 你了解过Bean的循环依赖吗？这和@DependsOn注解有关系吗？
* 你在平时工作中，会在哪些场景下使用@DependsOn注解？
* 你从@DependsOn注解的设计中得到了哪些启发？

## 八、VIP服务

**强烈推荐阅读：《[原来大厂面试官也会在这里偷偷学习！](https://mp.weixin.qq.com/s/Zp0nI2RyFb_UCYpSsUt2OQ)》，如果文中优惠券过期，可长按或扫码下面优惠券二维码加入星球。**

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-18-008.png?raw=true" width="70%">
    <div style="font-size: 18px;">星球优惠券</div>
    <br/>
</div>

**冰河技术** 知识星球**《SpringCloud Alibaba实战》**从零搭建并开发微服务项目已完结；**《RPC手撸专栏》**已经更新120+篇文章，已提交120+项目工程，120+项目源码Tag分支；**《Spring核心技术》**专栏以Spring的核心注解为突破口，通过源码执行的时序图带你详细分析Spring底层源码，让你学习Spring底层源码不再枯燥。并这些专栏已经将源码的获取方式放到了知识星球中，同时在微信上创建了专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

目前，星球群已形成良好的技术讨论氛围，后续也会像PRC项目一样全程手撸企业级中间件项目，**涉及分布式、高并发、高性能、高可靠、高可扩展，让大家知其然，更知其所以然，从手写企业级中间件项目的过程中，充分掌握分布式、高并发、高性能、高可靠、高可扩展的编程技巧。**

**更加值得一提的是：有超过30+的大厂面试官悄悄在这里提升核心竞争力！**

### 星球提供的服务

冰河整理了星球提供的一些服务，如下所示。

加入星球，你将获得：

1.学习从零开始手撸可用于实际场景的高性能、可扩展的RPC框架项目

2.学习SpringCloud Alibaba实战项目—从零开发微服务项目

3.学习高并发、大流量业务场景的解决方案，体验大厂真正的高并发、大流量的业务场景

4.学习进大厂必备技能：性能调优、并发编程、分布式、微服务、框架源码、中间件开发、项目实战

5.提供站点 https://binghe.gitcode.host 所有学习内容的指导、帮助

6.GitHub：https://github.com/binghe001/BingheGuide - 非常有价值的技术资料仓库，包括冰河所有的博客开放案例代码

7.提供技术问题、系统架构、学习成长、晋升答辩等各项内容的回答

8.定期的整理和分享出各类专属星球的技术小册、电子书、编程视频、PDF文件

9.定期组织技术直播分享，传道、授业、解惑，指导阶段瓶颈突破技巧

### 如何加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

**好了，今天就到这儿吧，我是冰河，我们下期见~~**



## 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`学习加群`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>





## 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>




## 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>





## 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>

