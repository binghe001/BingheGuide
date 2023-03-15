---
layout: post
category: binghe-code-spring
title: 第01章：深度解析@Configuration注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第01章：深度解析@Configuration注解
lock: need
---

# 《Spring核心技术》第01章-驱动型注解：深度解析@Configuration注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book](https://github.com/binghe001/spring-annotation-book)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★☆☆

* **本章重点**：进一步了解@Configuration注解的使用方法和避坑，并在源码级别彻底理解@Configuration注解的执行流程。

------

## 一、学习指引

`关于@Configuration注解，不能只停留在表面！`

翻开Spring中@Configuration注解的源码，在源码上赫然标注了`Since: 3.0`的字样，也就是@Configuration注解是从Spring 3.0开始提供的注解。

大部读者都知道@Configuration注解可以标注到类上，当标注到类上时，启动Spring就会自动扫描@Configuration注解标注的类，将其注册到IOC容器中，并被实例化成Bean对象。如果被@Configuration注解标注的类中存在使用@Bean注解标注的创建某个类对象的方法，那么，Spring也会自动执行使用@Bean注解标注的方法，将对应的Bean定义信息注册到IOC容器，并进行实例化。

如果你只想做CRUD操作，或者你只想做一名默默无闻的代码工，关于@Configuration注解，你了解到这一步就可以了，因为做CRUD不需要你对@Configuration注解了解的多么深入。但是，如果你是一个不甘于做CRUD操作，想突破自己的瓶颈，想成为一名合格的架构师或技术专家，那你只了解这些是远远不够的，你必须对@Configuration注解有更进一步的认识。

## 二、注解说明

`@Configuration注解的一点点说明`

@Configuration注解是从Spring 3.0版本开始加入的一个使Spring能够支持注解驱动开发的标注型注解，主要用于标注在类上。当某个类标注了@Configuration注解时，表示这个类是Spring的一个配置类。@Configuration注解能够替代Spring的applicationContext.xml文件，并且被@Configuration注解标注的类，能够自动注册到IOC容器并进行实例化。

### 2.1 注解源码

源码详见：org.springframework.context.annotation.Configuration。

```java
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Component
public @interface Configuration {
	@AliasFor(annotation = Component.class)
	String value() default "";
    //Since: 5.2
	boolean proxyBeanMethods() default true;
    //Since: 6.0
	boolean enforceUniqueMethods() default true;
}
```

@Configuration注解中每个属性的含义如下所示。

* value：存入到Spring IOC容器中的Bean的id。
* proxyBeanMethods：从Spring 5.2版本开始加入到@Configuration注解，表示被@Configuration注解标注的配置类是否会被代理，并且在配置类中使用@Bean注解生成的Bean对象在IOC容器中是否是单例对象，取值为true或者false。当取值为true时，表示full（全局）模式，此模式下被@Configuration注解标注的配置类会被代理，在配置类中使用@Bean注解注入到IOC容器中的Bean对象是单例模式，无论调用多少次被@Bean注解标注的方法，返回的都是同一个Bean对象。当取值为false时，表示lite（轻量级）模式，此模式下被@Configuration注解标注的配置类不会被代理，在配置类中使用@Bean注解注入到IOC容器中的Bean对象不是单例模式，每次调用被@Bean注解标注的方法时，都会返回一个新的Bean对象。默认的取值为true。
* enforceUniqueMethods：从Spring 6.0开始加入到@Configuration注解，指定使用@Bean注解标注的方法是否需要具有唯一的方法名称，取值为true或者false。当取值为true时，表示使用@Bean注解标注的方法具有唯一的方法名称，并且这些方法名称不会重叠。当取值为false时，表示使用@Bean注解标注的方法名称不唯一，存在被重叠的风险。默认取值为true。

从@Configuration注解的源码也可以看出，@Configuration注解本质上是一个@Component注解，所以，被@Configuration注解标注的配置类本身也会被注册到IOC容器中。同时，@Configuration注解也会被@ComponentScan注解扫描到。

### 2.2 注解使用场景

基于Spring的注解开发应用程序时，可以将@Configuration注解标注到某个类上。当某个类被@Configuration注解标注时，说明这个类是配置类，可以在这个类中使用@Bean注解向IOC容器中注入Bean对象，也可以使用@Autowired、@Inject和@Resource等注解来注入所需的Bean对象。

注意：基于Spring的注解模式开发应用程序时，在使用AnnotationConfigApplicationContext类创建IOC容器时，需要注意如下事项：

（1）如果调用的是AnnotationConfigApplicationContext类中传入Class类型可变参数的构造方法来创建IOC容器，表示传入使用@Configuration注解标注的配置类的Class对象来创建IOC容器，则标注到配置类上的@Configuration注解可以省略。

AnnotationConfigApplicationContext类中传入Class类型可变参数的构造方法源码如下所示。

```java
public AnnotationConfigApplicationContext(Class<?>... componentClasses) {
    this();
    register(componentClasses);
    refresh();
}
```

（2）如果调用的是AnnotationConfigApplicationContext类中传入String类型可变参数的构造方法来创建IOC容器，表示传入应用程序的包名来创建IOC容器，则标注到配置类上的@Configuration注解不能省略。

AnnotationConfigApplicationContext类中传入String类型可变参数的构造方法源码如下所示。

```java
public AnnotationConfigApplicationContext(String... basePackages) {
    this();
    scan(basePackages);
    refresh();
}
```

另外，当调用的是AnnotationConfigApplicationContext类中传入Class类型可变参数的构造方法来创建IOC容器时，如果传入的配置类上省略了@Configuration注解，则每次调用配置类中被@Bean注解标注的方法时，都会返回不同的Bean实例对象。

## 三、使用案例

`不给案例学起来挺枯燥的。`

本节，简单介绍使用@Configuration注解的几个案例程序。

### 3.1  验证proxyBeanMethods属性的作用

在2.1节已经详细介绍过@Configuration注解中proxyBeanMethods属性的作用，proxyBeanMethods属性可取值为true或者false。取值为true时，无论调用多少次在被@Configuration注解标注的类中被@Bean注解标注的方法，返回的都是同一个Bean对象。取值为false时，每次调用在被@Configuration注解标注的类中被@Bean注解标注的方法，都回返回不同的Bean对象。

#### 3.1.1 验证proxyBeanMethods取值为true的情况

具体的案例实现步骤如下所示。

（1）创建Person类

Person类主要是用来注册到IOC容器中，并实例化对象。

源码详见：spring-annotation-chapter-01工程下的io.binghe.spring.annotation.chapter01.configuration.bean.Person，如下所示。

```java
public class Person {
    private String name;
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
}
```

（2）创建ConfigurationAnnotationConfig类

ConfigurationAnnotationConfig类的作用就是充当程序启动的配置类，会在ConfigurationAnnotationConfig类上标注@Configuration注解，说明ConfigurationAnnotationConfig类是Spring启动时的配置类。

源码详见：spring-annotation-chapter-01工程下的io.binghe.spring.annotation.chapter01.configuration.config.ConfigurationAnnotationConfig，如下所示。

```java
@Configuration
public class ConfigurationAnnotationConfig {
    @Bean
    public Person person(){
        return new Person();
    }
}
```

可以看到，在ConfigurationAnnotationConfig类上标注了@Configuration注解，由于@Configuration注解中的proxyBeanMethods属性默认为true，所以在ConfigurationAnnotationConfig类上的@Configuration注解省略了proxyBeanMethods属性。

（3）创建ConfigurationAnnotationTest类

ConfigurationAnnotationTest类的作用就是整个案例程序的启动类，对整个案例程序进行测试。

源码详见：spring-annotation-chapter-01工程下的io.binghe.spring.annotation.chapter01.configuration.ConfigurationAnnotationTest，如下所示。

```java
public class ConfigurationAnnotationTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationAnnotationTest.class);

    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ConfigurationAnnotationConfig.class);
        ConfigurationAnnotationConfig config = context.getBean(ConfigurationAnnotationConfig.class);
        Person person1 = config.person();
        Person person2 = config.person();
        LOGGER.info("person1 == person2 ===>> {}", (person1 == person2));
    }
}
```

可以看到，在ConfigurationAnnotationTest类的main()方法中，首先基于AnnotationConfigApplicationContext常见了IOC容器context，从context中获取了ConfigurationAnnotationConfig类的Bean实例对象config，接下来，调用两次config的person()方法分别赋值给Person类型的局部变量person1和person2，最后打印person1是否等于person2的日志。

（4）测试案例

运行ConfigurationAnnotationTest类的main()方法，输出的结果信息如下所示。

```bash
person1 是否等于 person2 ===>> true
```

通过输出的结果信息可以看出，person1是否等于person2输出的结果为true。说明当@Configuration注解中的proxyBeanMethods属性为true时，每次调用使用@Configuration注解标注的类中被@Bean注解标注的方法时，都会返回同一个Bean实例对象。

#### 3.1.2 验证proxyBeanMethods取值为false的情况

验证@Configuration注解中的proxyBeanMethods属性为false的情况，与验证proxyBeanMethods属性为true的情况的案例程序基本一致，只是将ConfigurationAnnotationConfig类上标注的@Configuration注解的proxyBeanMethods属性设置为false，案例实现的具体步骤如下所示。

（1）修改proxyBeanMethods属性的值

修改后的ConfigurationAnnotationConfig类的源码如下所示。

```java
@Configuration(proxyBeanMethods = false)
public class ConfigurationAnnotationConfig {
    @Bean
    public Person person(){
        return new Person();
    }
}
```

可以看到，此时在ConfigurationAnnotationConfig类上标注的@Configuration注解的proxyBeanMethods属性为false。

（2）测试案例

运行ConfigurationAnnotationTest类的main()方法，输出的结果信息如下所示。

```bash
person1 是否等于 person2 ===>> false
```

从输出的结果信息可以看出，person1是否等于person2输出的结果为false。说明当@Configuration注解中的proxyBeanMethods属性为false时，每次调用使用@Configuration注解标注的类中被@Bean注解标注的方法时，都会返回不同的Bean实例对象。

### 3.2 传入配置类创建IOC容器

调用AnnotationConfigApplicationContext类的构造方法传入配置类的Class对象创建IOC容器时，可以省略配置类上的@Configuration注解，案例的具体实现步骤如下所示。

（1）删除@Configuration注解

删除ConfigurationAnnotationConfig类上的@Configuration注解，源码如下所示。

```java
public class ConfigurationAnnotationConfig {
    @Bean
    public Person person(){
        return new Person();
    }
}
```

（2）测试案例

运行ConfigurationAnnotationTest类的main()方法，输出的结果信息如下所示。

```java
person1 是否等于 person2 ===>> false
```

从输出的结果信息可以看到，输出了person1是否等于person2的结果为false。说明调用AnnotationConfigApplicationContext类的构造方法传入配置类的Class对象创建IOC容器时，可以省略配置类上的@Configuration注解，此时每次调用配置类中被@Bean注解标注的方法时，都会返回不同的Bean实例对象。

### 3.3 传入包名创建IOC容器

调用AnnotationConfigApplicationContext类的构造方法传入包名创建IOC容器时，不能省略配置类上的@Configuration注解，案例的具体实现步骤如下所示。

（1）修改测试类

修改ConfigurationAnnotationTest类的main()方法中，创建AnnotationConfigApplicationContext对象的代码，将调用传入Class对象的构造方法修改为调用传入String对象的方法，修改后的代码如下所示。

```java
public class ConfigurationAnnotationTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationAnnotationTest.class);

    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext("io.binghe.spring.annotation.chapter01.configuration");
        ConfigurationAnnotationConfig config = context.getBean(ConfigurationAnnotationConfig.class);
        Person person1 = config.person();
        Person person2 = config.person();
        LOGGER.info("person1 是否等于 person2 ===>> {}", (person1 == person2));
    }
}
```

（2）删除@Configuration注解

删除ConfigurationAnnotationConfig类上的@Configuration注解，源码如下所示。

```java
public class ConfigurationAnnotationConfig {
    @Bean
    public Person person(){
        return new Person();
    }
}
```

（3）测试案例

运行ConfigurationAnnotationTest类的main()方法，可以看到程序抛出了异常信息，如下所示。

```bash
Exception in thread "main" org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type 'io.binghe.spring.annotation.chapter01.configuration.config.ConfigurationAnnotationConfig' available
```

从输出的结果信息可以看出，调用AnnotationConfigApplicationContext类的构造方法传入包名创建IOC容器时，不能省略配置类上的@Configuration注解，否则会抛出NoSuchBeanDefinitionException。

（4）添加@Configuration注解

在ConfigurationAnnotationConfig类上添加@Configuration注解，源码如下所示。

```java
@Configuration
public class ConfigurationAnnotationConfig {
    @Bean
    public Person person(){
        return new Person();
    }
}
```

（5）再次测试案例

再次运行ConfigurationAnnotationTest类的main()方法，输出的结果信息如下所示。

```bash
person1 是否等于 person2 ===>> true
```

从输出的结果信息可以看到，输出了person1是否等于person2的结果为true，再次说明调用AnnotationConfigApplicationContext类的构造方法传入包名创建IOC容器时，不能省略配置类上的@Configuration注解。

## 四、源码时序图

`根据源码执行的流程图分析源码思路会更加清晰！`

就@Configuration注解本身而言，在源码层面的执行流程涉及到注册与实例化两种执行流程，就注册流程而言，会涉及到Spring内部的ConfigurationClassPostProcessor类的Bean定义信息的注册流程，以及案例中标注了@Configuration注解的ConfigurationAnnotationConfig配置类的Bean定义信息注册流程。

本节，就简单介绍下@Configuration注解在源码层面的注册与实例化两种执行时序图。

**注意：本章的源码时序图和源码解析均以本章案例程序作为入口进行分析，并且会在ConfigurationAnnotationConfig类上标注@Configuration注解，同时在ConfigurationAnnotationTest测试类中，调用AnnotationConfigApplicationContext类的AnnotationConfigApplicationContext(Class<?>... componentClasses)构造方法来创建IOC容器。**

### 4.1 注册ConfigurationClassPostProcessor流程源码时序图

ConfigurationClassPostProcessor后置处理器是解析@Configuration注解的核心类，也是Spring中的一个非常重要的后置处理器类， Spring IOC容器启动时，会向IOC容器中注册ConfigurationClassPostProcessor类的Bean定义信息。向IOC容器中注册ConfigurationClassPostProcessor类的Bean定义信息的时序图如图1-1所示。

![图1-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-05-001.png)

由图1-1可以看出，Spring IOC容器启动时，向IOC容器中注册ConfigurationClassPostProcessor类的Bean定义信息时，会涉及到AnnotationConfigApplicationContext类、AnnotatedBeanDefinitionReader类和AnnotationConfigUtils类中方法的调用。具体源码的调用细节见源码解析部分。

### 4.2 注册ConfigurationAnnotationConfig流程源码时序图

ConfigurationAnnotationConfig类是本章中案例程序的配置类，在ConfigurationAnnotationConfig类上标注了@Configuration注解，当Spring IOC容器启动时，也会将ConfigurationAnnotationConfig类的Bean定义信息注册到Spring IOC容器中，向Spring IOC容器中注册ConfigurationAnnotationConfig类的Bean定义信息的时序图如图1-2所示。

![图1-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-05-002.png)

由图1-2可以看出，Spring IOC容器启动时，向IOC容器中注册ConfigurationAnnotationConfig类的Bean定义信息时，会涉及到AnnotationConfigApplicationContext类、AnnotatedBeanDefinitionReader类、BeanDefinitionReaderUtils类和DefaultListableBeanFactory类的方法调用，具体的源码调用细节见源码解析部分。

**注意：Spring IOC容器在启动时，会向IOC容器中注册ConfigurationClassPostProcessor类的bean定义信息和使用@Configuration注解标注的ConfigurationAnnotationConfig配置类的Bean定义信息。当Spring IOC容器在刷新时，会递归处理所有使用@Configuration注解标注的类，解析@Bean等注解标注的方法，解析成一个个ConfigurationClassBeanDefinition类型的BeanDefinition对象，注册到IOC容器中。Spring IOC容器刷新时，解析@Bean等注解的时序图和源码执行流程会在后续章节介绍@Bean等注解时，详细介绍，这里不再赘述。**

### 4.3 实例化流程源码时序图

Spring IOC容器在启动过程中，最终会调用AnnotationConfigApplicationContext类的refresh()方法刷新IOC容器，刷新IOC容器的过程中就会对标注了@Configuration注解的配置类进行实例化。本节，就结合案例程序简单分析下刷新IOC容器时，对标注了@Configuration注解的配置类进行实例化的源码时序图，源码时序图如图1-3-1和1-3-2所示。

![图1-3-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-05-003.png)

![图1-3-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-05-004.png)

由图1-3-1和图1-3-2可以看出，刷新IOC容器时，对标注了@Configuration注解的配置类进行实例化时，会涉及到AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类和ConfigurationClassEnhancer类方法的调用，具体方法调用的细节见源码解析部分。

## 五、源码解析

`重点来了，源码解析，跟上节奏，别走神！`

本节，同样按照注册流程和实例化流程来深入分析@Configuration注解在Spring源码层面的执行流程。

### 5.1 注册ConfigurationClassPostProcessor流程源码解析

@Configuration注解涉及到ConfigurationClassPostProcessor类的Bean定义信息的注册流程的源码执行过程可结合图1-1进行分析。启动Spring IOC容器时，@Configuration注解涉及到的ConfigurationClassPostProcessor核心类的注册流程的源码执行过程如下所示。

（1）运行案例程序启动类ConfigurationAnnotationTest的main()方法

源码详见：io.binghe.spring.annotation.chapter01.configuration.ConfigurationAnnotationTest#main()。

```java
public static void main(String[] args) {
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ConfigurationAnnotationConfig.class);
	//#############省略其他代码##################
}
```

可以看到，在main()方法中会调用AnnotationConfigApplicationContext类的构造方法传入配置类ConfigurationAnnotationConfig的Class对象来创建IOC容器。接下来，会进入AnnotationConfigApplicationContext类的构造方法。

（2）解析AnnotationConfigApplicationContext类的AnnotationConfigApplicationContext(Class<?>... componentClasses)构造方法

源码详见：org.springframework.context.annotation.AnnotationConfigApplicationContext#AnnotationConfigApplicationContext(Class<?>... componentClasses)。

```java
public AnnotationConfigApplicationContext(Class<?>... componentClasses) {
    this();
    register(componentClasses);
    refresh();
}
```

可以看到，在上述构造方法中，会通过this()调用AnnotationConfigApplicationContext类的无参构造方法。

（3）解析AnnotationConfigApplicationContext类的AnnotationConfigApplicationContext()无参构造方法

源码详见：org.springframework.context.annotation.AnnotationConfigApplicationContext#AnnotationConfigApplicationContext()。

```java
public AnnotationConfigApplicationContext() {
    StartupStep createAnnotatedBeanDefReader = this.getApplicationStartup().start("spring.context.annotated-bean-reader.create");
    this.reader = new AnnotatedBeanDefinitionReader(this);
    createAnnotatedBeanDefReader.end();
    this.scanner = new ClassPathBeanDefinitionScanner(this);
}
```

可以看到，在AnnotationConfigApplicationContext类的无参构造方法中，主要的逻辑就是实例化了AnnotatedBeanDefinitionReader类型的reader成员变量和ClassPathBeanDefinitionScanner类型的scanner成员变量。

* reader：表示注解类型的Bean定义信息读取器，主要就是读取通过注解方式进行实例化的Bean的定义信息。
* scanner：表示类路径下的Bean定义扫描器，主要就是扫描类路径下的Bean定义信息。

@Configuration注解涉及到的注册流程源码的执行过程，会执行实例化reader成员变量的代码，也就是下面的代码片段。

```java
this.reader = new AnnotatedBeanDefinitionReader(this);
```

接下来，会调用AnnotatedBeanDefinitionReader类中的AnnotatedBeanDefinitionReader(BeanDefinitionRegistry registry)构造方法。

（4）解析AnnotatedBeanDefinitionReader类中的AnnotatedBeanDefinitionReader(BeanDefinitionRegistry registry)构造方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#AnnotatedBeanDefinitionReader(BeanDefinitionRegistry registry)。

```java
public AnnotatedBeanDefinitionReader(BeanDefinitionRegistry registry) {
    this(registry, getOrCreateEnvironment(registry));
}
```

可以看到，在上述构造方法中，通过this调用了AnnotatedBeanDefinitionReader类的AnnotatedBeanDefinitionReader(BeanDefinitionRegistry registry, Environment environment)构造方法。

（5）解析AnnotatedBeanDefinitionReader类的AnnotatedBeanDefinitionReader(BeanDefinitionRegistry registry, Environment environment)构造方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#AnnotatedBeanDefinitionReader(BeanDefinitionRegistry registry, Environment environment)。

```java
public AnnotatedBeanDefinitionReader(BeanDefinitionRegistry registry, Environment environment) {
    Assert.notNull(registry, "BeanDefinitionRegistry must not be null");
    Assert.notNull(environment, "Environment must not be null");
    this.registry = registry;
    this.conditionEvaluator = new ConditionEvaluator(registry, environment, null);
    AnnotationConfigUtils.registerAnnotationConfigProcessors(this.registry);
}
```

可以看到，在上述构造方法中，最核心的逻辑就是调用了AnnotationConfigUtils工具类的registerAnnotationConfigProcessors()方法，将BeanDefinitionRegistry类型的registry对象传入方法中。其中，registry对象本质上就是一个AnnotationConfigApplicationContext类对象的实例，这是因为AnnotationConfigApplicationContext类继承了GenericApplicationContext类，而GenericApplicationContext类实现了BeanDefinitionRegistry接口。

（6）解析AnnotationConfigUtils类的registerAnnotationConfigProcessors(BeanDefinitionRegistry registry)方法

源码详见：org.springframework.context.annotation.AnnotationConfigUtils#registerAnnotationConfigProcessors(BeanDefinitionRegistry registry)。

```java
public static void registerAnnotationConfigProcessors(BeanDefinitionRegistry registry) {
    registerAnnotationConfigProcessors(registry, null);
}
```

可以看到，在AnnotationConfigUtils类的registerAnnotationConfigProcessors(BeanDefinitionRegistry registry)方法中调用了AnnotationConfigUtils类中的另外一个registerAnnotationConfigProcessors()方法。

（7）解析AnnotationConfigUtils类的registerAnnotationConfigProcessors(BeanDefinitionRegistry registry, Object source)方法

源码详见：org.springframework.context.annotation.AnnotationConfigUtils#registerAnnotationConfigProcessors(BeanDefinitionRegistry registry, Object source)。

这里，只给出在AnnotationConfigUtils类的registerAnnotationConfigProcessors(BeanDefinitionRegistry registry, Object source)方法中，将@Configuration注解涉及到的ConfigurationClassPostProcessor类的Bean定义信息注册到IOC容器中的核心代码，如下所示。

```java
public static Set<BeanDefinitionHolder> registerAnnotationConfigProcessors(
			BeanDefinitionRegistry registry, @Nullable Object source) {
    //################省略其他代码########################
    if (!registry.containsBeanDefinition(CONFIGURATION_ANNOTATION_PROCESSOR_BEAN_NAME)) {
        RootBeanDefinition def = new RootBeanDefinition(ConfigurationClassPostProcessor.class);
        def.setSource(source);
        beanDefs.add(registerPostProcessor(registry, def, CONFIGURATION_ANNOTATION_PROCESSOR_BEAN_NAME));
    }
    //################省略其他代码########################
}
```

可以看到，会调用registerPostProcessor()方法注册后置处理器。

（8）解析registerPostProcessor(BeanDefinitionRegistry registry, RootBeanDefinition definition, String beanName)方法

源码详见：org.springframework.context.annotation.AnnotationConfigUtils#registerPostProcessor(BeanDefinitionRegistry registry, RootBeanDefinition definition, String beanName)。

```java
private static BeanDefinitionHolder registerPostProcessor(
    BeanDefinitionRegistry registry, RootBeanDefinition definition, String beanName) {
    definition.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
    registry.registerBeanDefinition(beanName, definition);
    return new BeanDefinitionHolder(definition, beanName);
}
```

可以看到，上述代码中，调用了registry参数的registerBeanDefinition()方法来注册ConfigurationClassPostProcessor类的Bean定义信息，definition参数本质上就是一个AnnotationConfigApplicationContext类的实例对象。最终会调用DefaultListableBeanFactory类的registerBeanDefinition()方法来注册ConfigurationClassPostProcessor类的Bean定义信息。

（9）解析DefaultListableBeanFactory类的registerBeanDefinition(String beanName, BeanDefinition beanDefinition)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#registerBeanDefinition(String beanName, BeanDefinition beanDefinition)。

```java
@Override
public void registerBeanDefinition(String beanName, BeanDefinition beanDefinition)
    throws BeanDefinitionStoreException {
    //##################省略其他代码###############
	this.beanDefinitionMap.put(beanName, beanDefinition);
    //##################省略其他代码###############
}
```

通过上述代码可知，向Spring的IOC容器中注册类的Bean定义信息，其实就是向beanDefinitionMap对象中添加元素，beanDefinitionMap对象本质上是一个ConcurrentHashMap对象。向beanDefinitionMap对象中添加的元素的Key为Bean的名称，Value为Bean的定义信息。

beanDefinitionMap源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#beanDefinitionMap。

```java
private final Map<String, BeanDefinition> beanDefinitionMap = new ConcurrentHashMap<>(256);
```

至此，@Configuration注解涉及到的ConfigurationClassPostProcessor类的注册过程分析完毕。

### 5.2 注册ConfigurationAnnotationConfig流程源码解析

使用@Configuration注解标注的ConfigurationAnnotationConfig类的Bean定义信息的注册流程的源码执行过程可结合图1-2进行分析，启动Spring IOC容器时，向IOC容器中注册ConfigurationAnnotationConfig类的Bean定义信息的源码执行过程如下所示。

（1）运行案例程序启动类ConfigurationAnnotationTest的main()方法，并进入AnnotationConfigApplicationContext类的AnnotationConfigApplicationContext(Class<?>... componentClasses)构造方法。

源码详见：org.springframework.context.annotation.AnnotationConfigApplicationContext#AnnotationConfigApplicationContext(Class<?>... componentClasses)。

```java
public AnnotationConfigApplicationContext(Class<?>... componentClasses) {
    this();
    register(componentClasses);
    refresh();
}
```

可以看到，在AnnotationConfigApplicationContext(Class<?>... componentClasses)方法中调用了register()方法，传入componentClasses参数进行注册。

（2）解析AnnotationConfigApplicationContext类的register(Class<?>... componentClasses)方法

源码详见：org.springframework.context.annotation.AnnotationConfigApplicationContext#register(Class<?>... componentClasses)。

```java
@Override
public void register(Class<?>... componentClasses) {
	//###########省略其他代码##############
    this.reader.register(componentClasses);
    //###########省略其他代码##############
}
```

可以看到，在register(Class<?>... componentClasses)方法中调用了reader的register()方法。

（3）解析AnnotatedBeanDefinitionReader类的register(Class<?>... componentClasses)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#register(Class<?>... componentClasses)。

```java
public void register(Class<?>... componentClasses) {
    for (Class<?> componentClass : componentClasses) {
        registerBean(componentClass);
    }
}
```

可以看到，在register(Class<?>... componentClasses)方法中，会循环遍历传入的可变参数componentClasses，每次循环时，都会调用registerBean()方法。

（4）解析AnnotatedBeanDefinitionReader类的registerBean(Class<?> beanClass)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#registerBean(Class<?> beanClass)。

```java
public void registerBean(Class<?> beanClass) {
    doRegisterBean(beanClass, null, null, null, null);
}
```

可以看到，在registerBean(Class<?> beanClass)方法中调用了doRegisterBean()方法。

（5）解析AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法。

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)。

```java
private <T> void doRegisterBean(Class<T> beanClass, @Nullable String name,@Nullable Class<? extends Annotation>[] qualifiers, @Nullable Supplier<T> supplier, @Nullable BeanDefinitionCustomizer[] customizers) {

    AnnotatedGenericBeanDefinition abd = new AnnotatedGenericBeanDefinition(beanClass);
    //###########################省略其他代码#############################
    String beanName = (name != null ? name : this.beanNameGenerator.generateBeanName(abd, this.registry));
    //###########################省略其他代码#############################
    BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(abd, beanName);
    definitionHolder = AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
    BeanDefinitionReaderUtils.registerBeanDefinition(definitionHolder, this.registry);
}
```

可以看到，在doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法中调用了BeanDefinitionReaderUtils类的registerBeanDefinition()方法。

（6）解析BeanDefinitionReaderUtils类的registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)方法

源码详见：org.springframework.beans.factory.support.BeanDefinitionReaderUtils#registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)。

```java
public static void registerBeanDefinition(
    BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)
    throws BeanDefinitionStoreException {

    // Register bean definition under primary name.
    String beanName = definitionHolder.getBeanName();
    registry.registerBeanDefinition(beanName, definitionHolder.getBeanDefinition());
    //###########################省略其他代码#############################
}
```

可以看到，在registerBeanDefinition(BeanDefinitionHolder definitionHolder, BeanDefinitionRegistry registry)方法中通过调用registry的registerBeanDefinition()方法来向IOC容器中注册Bean定义信息。

**注意：到目前为止，后续向IOC容器注册Bean定义信息的源码执行流程与向IOC容器中注册ConfigurationClassPostProcessor类的Bean定义信息的源码执行流程基本相同，这里不再赘述。**

### 5.3 实例化流程源码解析

Spring IOC容器在刷新时，会实例化使用@Configuration注解标注的类，可结合图1-3-1和图1-3-2理解，具体的源码执行流程如下所示。

（1）运行案例程序启动类ConfigurationAnnotationTest的main()方法，并进入AnnotationConfigApplicationContext类的AnnotationConfigApplicationContext(Class<?>... componentClasses)构造方法。

源码详见：org.springframework.context.annotation.AnnotationConfigApplicationContext#AnnotationConfigApplicationContext(Class<?>... componentClasses)。

```java
public AnnotationConfigApplicationContext(Class<?>... componentClasses) {
    this();
    register(componentClasses);
    refresh();
}
```

可以看到，在AnnotationConfigApplicationContext(Class<?>... componentClasses)构造方法中会调用refresh()方法刷新IOC容器。

（2）解析AbstractApplicationContext类的refresh()方法

源码详见：org.springframework.context.support.AbstractApplicationContext#refresh()。

```java
@Override
public void refresh() throws BeansException, IllegalStateException {
    synchronized (this.startupShutdownMonitor) {
		//#############省略其他代码#####################
        try {
            //#############省略其他代码#####################
            invokeBeanFactoryPostProcessors(beanFactory);
			//#############省略其他代码#####################
        }
        catch (BeansException ex) {
           //#############省略其他代码#####################
        }
        finally {
           //#############省略其他代码#####################
        }
    }
}
```

可以看到，在refresh()方法中调用了invokeBeanFactoryPostProcessors()方法。

（3）解析AbstractApplicationContext类的invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory)方法

源码详见：org.springframework.context.support.AbstractApplicationContext#invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory)。

```java
protected void invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory) {
    PostProcessorRegistrationDelegate.invokeBeanFactoryPostProcessors(beanFactory, getBeanFactoryPostProcessors());
	//################省略其他代码####################
}
```

可以看到，在invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory)方法中调用了PostProcessorRegistrationDelegate类的invokeBeanFactoryPostProcessors()方法。

（4）解析PostProcessorRegistrationDelegate类的invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory, List<BeanFactoryPostProcessor> beanFactoryPostProcessors)方法

源码详见：org.springframework.context.support.PostProcessorRegistrationDelegate#invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory, List<BeanFactoryPostProcessor> beanFactoryPostProcessors)。

```java
public static void invokeBeanFactoryPostProcessors(
    ConfigurableListableBeanFactory beanFactory, List<BeanFactoryPostProcessor> beanFactoryPostProcessors) {
	//#################省略其他代码##################
    invokeBeanFactoryPostProcessors(registryProcessors, beanFactory);
	invokeBeanFactoryPostProcessors(regularPostProcessors, beanFactory);
    //#################省略其他代码##################
}
```

在invokeBeanFactoryPostProcessors()方法中会解析标注了@Configuration注解的类中标注了@Bean等注解的方法，生成相应的Bean定义信息注册到IOC容器中。这里，主要关注的是标注了@Configuration注解的类的实例化过程，所以，只需要关注invokeBeanFactoryPostProcessors()方法中的上述代码片段即可。

可以看到，在invokeBeanFactoryPostProcessors()方法中又调用了PostProcessorRegistrationDelegate类中的另一个invokeBeanFactoryPostProcessors()方法。

（5）解析PostProcessorRegistrationDelegate类的invokeBeanFactoryPostProcessors(Collection<? extends BeanFactoryPostProcessor> postProcessors, ConfigurableListableBeanFactory beanFactory)方法

源码详见：org.springframework.context.support.PostProcessorRegistrationDelegate#invokeBeanFactoryPostProcessors(Collection<? extends BeanFactoryPostProcessor> postProcessors, ConfigurableListableBeanFactory beanFactory)。

```java
private static void invokeBeanFactoryPostProcessors(Collection<? extends BeanFactoryPostProcessor> postProcessors, ConfigurableListableBeanFactory beanFactory) {
    for (BeanFactoryPostProcessor postProcessor : postProcessors) {
        StartupStep postProcessBeanFactory = beanFactory.getApplicationStartup().start("spring.context.bean-factory.post-process")
            .tag("postProcessor", postProcessor::toString);
        postProcessor.postProcessBeanFactory(beanFactory);
        postProcessBeanFactory.end();
    }
}
```

可以看到，在invokeBeanFactoryPostProcessors()方法中，会循环遍历传递进来的所有postProcessors集合，每次循环时，都会使用一个postProcessor对象来接收postProcessors集合中的每一个元素，调用postProcessor对象的postProcessBeanFactory()方法，并传入beanFactory来实例化对象。

（6）解析ConfigurationClassPostProcessor类中的postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory)方法

源码详见：org.springframework.context.annotation.ConfigurationClassPostProcessor#postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory)

```java
@Override
public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
    //##############省略其他代码###############
    enhanceConfigurationClasses(beanFactory);
    beanFactory.addBeanPostProcessor(new ImportAwareBeanPostProcessor(beanFactory));
}
```

可以看到，在postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory)方法中调用了enhanceConfigurationClasses()方法。

（7）解析ConfigurationClassPostProcessor类的enhanceConfigurationClasses(ConfigurableListableBeanFactory beanFactory)方法

源码详见：org.springframework.context.annotation.ConfigurationClassPostProcessor#enhanceConfigurationClasses(ConfigurableListableBeanFactory beanFactory)。

```java
public void enhanceConfigurationClasses(ConfigurableListableBeanFactory beanFactory) {
    //################省略其他代码########################
    ConfigurationClassEnhancer enhancer = new ConfigurationClassEnhancer();
    for (Map.Entry<String, AbstractBeanDefinition> entry : configBeanDefs.entrySet()) {
        AbstractBeanDefinition beanDef = entry.getValue();
        // If a @Configuration class gets proxied, always proxy the target class
        beanDef.setAttribute(AutoProxyUtils.PRESERVE_TARGET_CLASS_ATTRIBUTE, Boolean.TRUE);
        // Set enhanced subclass of the user-specified bean class
        Class<?> configClass = beanDef.getBeanClass();
        Class<?> enhancedClass = enhancer.enhance(configClass, this.beanClassLoader);
        if (configClass != enhancedClass) {
            //################省略其他代码###################
            beanDef.setBeanClass(enhancedClass);
        }
    }
    enhanceConfigClasses.tag("classCount", () -> String.valueOf(configBeanDefs.keySet().size())).end();
}
```

可以看到，在enhanceConfigurationClasses(ConfigurableListableBeanFactory beanFactory)方法中，主要是使用ConfigurationClassEnhancer对象的enhance()方法生成代理类，也就是使用CGLib生成代理类。

（8）解析ConfigurationClassEnhancer类的enhance(Class<?> configClass, ClassLoader classLoader)方法

源码详见：org.springframework.context.annotation.ConfigurationClassEnhancer#enhance(Class<?> configClass, @Nullable ClassLoader classLoader)。

```java
public Class<?> enhance(Class<?> configClass, @Nullable ClassLoader classLoader) {
    //###################省略其他代码###############
    Class<?> enhancedClass = createClass(newEnhancer(configClass, classLoader));
    //###################省略其他代码###############
    return enhancedClass;
}
```

可以看到，在enhance(Class<?> configClass, ClassLoader classLoader)方法中调用了createClass()方法创建代理类，在这之前先调用newEnhancer()方法实例化Enhancer对象。

（9）解析ConfigurationClassEnhancer类的newEnhancer(Class<?> configSuperClass, ClassLoader classLoader)方法

源码详见：org.springframework.context.annotation.ConfigurationClassEnhancer#newEnhancer(Class<?> configSuperClass, @Nullable ClassLoader classLoader)。

```java
private Enhancer newEnhancer(Class<?> configSuperClass, @Nullable ClassLoader classLoader) {
    Enhancer enhancer = new Enhancer();
    enhancer.setSuperclass(configSuperClass);
    enhancer.setInterfaces(new Class<?>[] {EnhancedConfiguration.class});
    enhancer.setUseFactory(false);
    enhancer.setNamingPolicy(SpringNamingPolicy.INSTANCE);
    enhancer.setAttemptLoad(true);
    enhancer.setStrategy(new BeanFactoryAwareGeneratorStrategy(classLoader));
    enhancer.setCallbackFilter(CALLBACK_FILTER);
    enhancer.setCallbackTypes(CALLBACK_FILTER.getCallbackTypes());
    return enhancer;
}
```

可以看到，newEnhancer()方法中主要是生成CGLib动态代理的Enhancer对象，后续会使用Enhancer对象生成代理类。

在newEnhancer()方法中为要生成的代理类设置了父类和接口，由于为要生成的代理类设置的接口为EnhancedConfiguration，同时，EnhancedConfiguration接口继承了BeanFactoryAware接口，所以，在后续生成的代理类中可以调用BeanFactoryAware接口的setBeanFactory(BeanFactory beanFactory)方法获取到beanFactory对象。

（10）解析ConfigurationClassEnhancer类的createClass(Enhancer enhancer)方法

源码详见：org.springframework.context.annotation.ConfigurationClassEnhancer#createClass(Enhancer enhancer)。

```java
private Class<?> createClass(Enhancer enhancer) {
    Class<?> subclass = enhancer.createClass();
    Enhancer.registerStaticCallbacks(subclass, CALLBACKS);
    return subclass;
}
```

可以看到，在createClass(Enhancer enhancer)方法中，主要调用了enhancer对象的createClass()方法来创建代理类，因为使用CGLib创建出来的代理类是目标类的子类，所以，这里创建出来的代理类就是目标类的子类。

最后，再来关注下Enhancer类中传入的CALLBACKS参数。

（11）解析CALLBACKS

源码详见：org.springframework.context.annotation.ConfigurationClassEnhancer#CALLBACKS。

```java
static final Callback[] CALLBACKS = new Callback[] {
    new BeanMethodInterceptor(),
    new BeanFactoryAwareMethodInterceptor(),
    NoOp.INSTANCE
};
```

可以看到，CALLBACKS是一个Callback类型的数组，数组中的每个元素都是一个Callback类型的对象。其中，BeanMethodInterceptor类和BeanFactoryAwareMethodInterceptor类也是拦截器类型。接下来，以BeanMethodInterceptor类为例进行介绍。

（12）解析BeanMethodInterceptor类

源码详见：org.springframework.context.annotation.ConfigurationClassEnhancer.BeanMethodInterceptor。

BeanMethodInterceptor实现了MethodInterceptor接口和ConditionalCallback接口，主要的作用就是对标注了@Bean的注解的方法进行拦截，执行intercept(Object enhancedConfigInstance, Method beanMethod, Object[] beanMethodArgs,  MethodProxy  cglibMethodProxy)方法，生成Bean的实例对象。在方法中有如下一段代码逻辑。

```java
public Object intercept(Object enhancedConfigInstance, Method beanMethod, Object[] beanMethodArgs,
					MethodProxy cglibMethodProxy) throws Throwable {
    //如果已经创建了Bean的代理实例对象，则调用父类的方法。
    if (isCurrentlyInvokedFactoryMethod(beanMethod)) {
        //#################省略其他代码###############
        return cglibMethodProxy.invokeSuper(enhancedConfigInstance, beanMethodArgs);
    }
    return resolveBeanReference(beanMethod, beanMethodArgs, beanFactory, beanName);   
}
```

上述代码能够保证在类上添加@Configuration注解后，只会为类生成一个代理对象。也就是说，上述代码的逻辑能够保证标注了@Configuration注解的类生成的代理类是单例模式的。

因为使用CGLib创建出来的代理类是目标类的子类，所以第一次执行上述代码片段时，会调用cglibMethodProxy的invokeSuper()方法执行父类的方法，也就是执行目标类的方法。第二次执行上述代码片段时，会调用resolveBeanReference()方法。

（13）解析BeanMethodInterceptor类的resolveBeanReference(Method beanMethod, Object[] beanMethodArgs,  ConfigurableBeanFactory beanFactory, String beanName)方法

源码详见：org.springframework.context.annotation.ConfigurationClassEnhancer.BeanMethodInterceptor#resolveBeanReference(Method beanMethod, Object[] beanMethodArgs,  ConfigurableBeanFactory beanFactory, String beanName)。

```java
private Object resolveBeanReference(Method beanMethod, Object[] beanMethodArgs, ConfigurableBeanFactory beanFactory, String beanName) {
    //##############省略其他代码###############
    boolean alreadyInCreation = beanFactory.isCurrentlyInCreation(beanName);
    try {
        //##############省略其他代码###############
        Object beanInstance = (useArgs ? beanFactory.getBean(beanName, beanMethodArgs) :
                               beanFactory.getBean(beanName));
       //##############省略其他代码###############
        return beanInstance;
    }
    finally {
       //##############省略其他代码###############
    }
}
```

可以看到，从resolveBeanReference()方法中，会通过beanFactory获取已经初始化好的Bean对象，并将这个已经初始化好的bean对象返回。并不会再进行第二次初始化的操作。

所以，在类上添加@Configuration注解后，Spring能够保证为类生成的代理类是单例的。

## 六、总结

`@Configuration注解讲完了，来一起总结下吧。`

本章，主要对@Configuration注解进行了系统性的介绍。首先，对@Configuration注解进行了简单的说明，包括@Configuration注解的源码和使用场景以及注意事项。随后，给出了@Configuration注解的使用案例，本章的案例主要是针对使用@Configuration注解的一些注意事项给出的案例。接下来，详细介绍了@Configuration注解在Spring源码层面执行的时序图和对应的源码流程。其中，对于注册流程，主要介绍了注册ConfigurationClassPostProcessor类后置处理器的Bean定义信息和ConfigurationAnnotationConfig配置类Bean定义信息的注册时序图和源码执行流程。对于实例化流程，主要介绍了在Spring IOC容器刷新时，实例化ConfigurationAnnotationConfig配置类的代理对象的流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

* Spring为何在创建IOC容器时先注册ConfigurationClassPostProcessor类后置处理器的Bean定义信息，随后才是注册标注了@Configuration注解的ConfigurationAnnotationConfig配置类的Bean定义信息？
* Spring为何先将类的Bean定义信息注册到IOC容器？为何不是直接注册实例化后的对象？
* Spring为何是在刷新IOC容器时，实例化标注了@Configuration注解的配置类的代理对象？为何不是在创建IOC容器时就进行实例化？
* Spring IOC容器的这种设计能给你带来哪些启示？


## 八、VIP服务

**强烈推荐阅读：《[原来大厂面试官也会在这里偷偷学习！](https://mp.weixin.qq.com/s/Zp0nI2RyFb_UCYpSsUt2OQ)》，如果文中优惠券过期，可长按或扫码下面优惠券二维码加入星球。**

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-18-008.png?raw=true" width="70%">
    <div style="font-size: 18px;">星球优惠券</div>
    <br/>
</div>

**冰河技术** 知识星球 **《SpringCloud Alibaba实战》** 从零搭建并开发微服务项目已完结；**《RPC手撸专栏》** 已经更新120+篇文章，已提交120+项目工程，120+项目源码Tag分支；**《Spring核心技术》** 专栏以Spring的核心注解为突破口，通过源码执行的时序图带你详细分析Spring底层源码，让你学习Spring底层源码不再枯燥。并这些专栏已经将源码的获取方式放到了知识星球中，同时在微信上创建了专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

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