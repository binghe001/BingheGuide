---
layout: post
category: binghe-code-spring
title: 第05章：深度解析@Import注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第05章：深度解析@Import注解
lock: need
---

# 《Spring核心技术》第5章：深度解析@Import注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-05](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-05)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Import注解向Spring IOC容器中注入Bean的示例与流程，从源码级别彻底掌握@Import注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 注解使用场景
* 使用案例
  * 引入普通类案例
  * 引入实现了ImportSelector接口的类案例
  * 引入实现了ImportBeanDefinitionRegistrar接口的类案例
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`@Import注解是什么？`

想深入学习一项技术并不是一朝一夕就能够完成的，它需要我们花费大量的时间和精力，塌下心来深入研究，从不知道，到了解，再到熟悉，最后到精通，这需要一个不断深入研究，不断实践的过程。学习Spring亦是如此，要想掌握好Spring的核心技术，同样需要塌下心来不断研究和实践。

## 二、注解说明

`关于@Import注解的一点点说明~~`

@Import注解可以将第三方包中的类对象注入到IOC容器中。使用Spring开发业务系统时，@Import注解的使用频率不及@Bean注解，@Import注解往往在一些中间件或者框架项目中使用的比较多。在Spring底层，也大量使用了@Import注解来向IOC容器中注入Bean对象。当然，如果在开发业务系统时，也可以使用@Import注解向IOC容器中注入Bean对象。@Import注解相比于@Bean注解来讲，在使用上会更加灵活。

### 2.1 注解源码

@Import注解只能标注到类或其他注解上，通常与配置类一起使用的，使用此注解引入的类上可以不再使用@Configuration，@Component等注解标注。本节，就对@Import注解的源码进行简单的剖析。

@Import注解的源码详见：org.springframework.context.annotation.Import，如下所示。

```java
/**
 * Since: 3.0
 * @author Chris Beams
 * @author Juergen Hoeller
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Import {
	Class<?>[] value();
}
```

从@Import源码的注释可以看出，@Import是Spring从3.0版本开始提供的注解，注解中只有一个Class数组类型的value属性。含义如下所示。

* value：Class数组类型，用于指定其他配置类的字节码，支持指定多个配置类。另外，使用value属性指定的有一定的条件，必须是普通类、实现了ImportSelector接口的类和实现了ImportBeanDefinitionRegistrar接口的类。

**注意：@Import注解只能标注到类上。**

### 2.2 注解使用场景

在使用Spring进行开发时，如果涉及到的配置项比较多，要是将所有的配置项都写到一个类里，则配置结构和配置内容将会变得非常杂乱，如果此时使用@Import注解，则可以将配置项进行分类管理。另外，如果在项目中需要引入第三方的类，并且需要将这些类的对象注入到IOC容器中，也可以使用@Import注解。

## 三、使用案例

`@Import注解案例实战~~`

@Import注解可以引入三种类，分别如下所示。

* 引入普通类，将Bean对象注入到IOC容器。
* 引入实现了ImportSelector接口的类，将selectImports()方法返回的Bean数组注入到IOC容器，但是实现了ImportSelector接口的类对象本身不会被注册到IOC容器中。
* 引入实现了ImportBeanDefinitionRegistrar接口的类，使用registerBeanDefinitions()方法中的BeanDefinitionRegistry对象注入BeanDefinition对象到IOC容器中，但是实现了ImportBeanDefinitionRegistrar接口的类对象本身不会被注册到IOC容器中。

### 3.1 引入普通类案例

本节，主要实现使用@Import注解实现引入普通类，并且将Bean对象注入到IOC容器中的案例。具体实现步骤如下所示。

**（1）新建User类**

User类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.bean.User，如下所示。

```java
public class User {
    private Long userId;
    private String userName;
    //#############省略getter/serrer方法############
}
```

可以看到，User类就是一个普通的类对象，后续会通过@Import注解引入User类，并且将User类的对象注入到IOC容器中。

**（2）新建Spring配置类ImportConfig**

ImportConfig类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.config.ImportConfig，如下所示。

```java
@Import(value = {User.class})
@Configuration
public class ImportConfig {
}
```

可以看到，ImportConfig类主要是Spring的配置类，会在ImportConfig类上标注@Configuration注解和@Import注解，并且会通过@Import注解引入User类，将User类的对象注入到IOC容器中。

**（3）新建ImportTest类**

ImportTest类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.ImportTest，如下所示。

```java
public class ImportTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ImportConfig.class);
        String[] definitionNames = context.getBeanDefinitionNames();
        Arrays.stream(definitionNames).forEach((definitionName) -> System.out.println(definitionName));
    }
}
```

可以看到，ImportTest类主要是案例的测试类，在ImportTest类的main()方法中，主要打印了Bean定义的名称。

**（4）运行ImportTest类**

运行ImportTest类的main()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
importConfig
io.binghe.spring.annotation.chapter05.bean.User
```

其中，以`org.springframework`包命名的Bean是Spring内部的Bean。另外，可以看到，结果信息中也输出了ImportConfig类的Bean名称和User类的Bean名称。

**说明：使用@Import注解可以引入普通的类，并且能够将类对象注入到Spring容器中。**

### 3.2 引入实现了ImportSelector接口的类案例

本节，主要实现使用@Import注解引入实现了ImportSelector接口的类，将selectImports()方法返回的Bean数组注入到IOC容器中的案例。具体的实现步骤如下所示。

**注意：本节实现的案例是在3.1节的基础上实现的。**

**（1）新建ImportSelectorBean类**

ImportSelectorBean类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.bean.ImportSelectorBean，如下所示。

```java
public class ImportSelectorBean {
    private Long id;
    private String name;
    //########省略getter/setter方法#########
}
```

可以看到，ImportSelectorBean类是一个普通的类，ImportSelectorBean类的对象后续会通过ImportSelector接口的selectImports()注入到IOC容器中。

**（2）新建MyImportSelector类**

MyImportSelector类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.selector.MyImportSelector，如下所示。

```java
public class MyImportSelector implements ImportSelector {
    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        return new String[]{ImportSelectorBean.class.getName()};
    }
}
```

可以看到，MyImportSelector类实现了ImportSelector接口，并实现了ImportSelector接口的selectImports()方法，在selectImports()中返回了包含ImportSelectorBean类的全类名的Spring数组。

**（3）修改ImportConfig类**

ImportConfig类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.config.ImportConfig，如下所示。

```java
@Import(value = {User.class, MyImportSelector.class})
@Configuration
public class ImportConfig {
}
```

可以看到，在ImportConfig类上标注的@Import注解的value属性中，新增MyImportSelector类的Class对象。

**（4）运行ImportTest类**

运行ImportTest类的main()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
importConfig
io.binghe.spring.annotation.chapter05.bean.User
io.binghe.spring.annotation.chapter05.bean.ImportSelectorBean
```

可以看到，在输出的结果信息中，除了有Spring内部的Bean对象的名称、ImportConfig类的Bean对象名称和User类的Bean对象名称外，还输出了ImportSelectorBean类的Bean对象名称。但是，并没有输出实现了ImportSelector接口的MyImportSelector类的Bean对象的名称。

**说明：使用@Import注解可以引入实现了ImportSelector接口的类，将selectImports()方法返回的Bean数组注入到IOC容器中，但是实现了ImportSelector接口的类对象本身不会被注册到IOC容器中。**

### 3.3 引入实现了ImportBeanDefinitionRegistrar接口的类案例

本节，主要实现使用@Import注解引入实现了ImportBeanDefinitionRegistrar接口的类，使用registerBeanDefinitions()方法中的BeanDefinitionRegistry对象注入BeanDefinition对象到IOC容器中的案例。具体实现步骤如下所示。

**（1）新增ImportBeanDefinitionRegistrarBean类**

ImportBeanDefinitionRegistrarBean类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.bean.ImportBeanDefinitionRegistrarBean，如下所示。

```java
public class ImportBeanDefinitionRegistrarBean {
    private Long id;
    private String name;
	//#########省略getter/setter方法############
}
```

可以看到，ImportBeanDefinitionRegistrarBean类就是一个普通的类，后续会通过ImportBeanDefinitionRegistrar接口的实现类实现的registerBeanDefinitions()方法将ImportBeanDefinitionRegistrarBean类的Bean对象注入到IOC容器中。

**（2）新增MyImportBeanDefinitionRegistrar类**

MyImportBeanDefinitionRegistrar类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.registrar.MyImportBeanDefinitionRegistrar，如下所示。

```java
public class MyImportBeanDefinitionRegistrar implements ImportBeanDefinitionRegistrar {
    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
        String beanName = ImportBeanDefinitionRegistrarBean.class.getName();
        BeanDefinition beanDefinition = new RootBeanDefinition(ImportBeanDefinitionRegistrarBean.class);
        registry.registerBeanDefinition(beanName, beanDefinition);
    }
}
```

可以看到，MyImportBeanDefinitionRegistrar类实现了ImportBeanDefinitionRegistrar接口，并实现了ImportBeanDefinitionRegistrar接口的registerBeanDefinitions()方法。在registerBeanDefinitions()方法中，获取ImportBeanDefinitionRegistrarBean类的全类名作为注入到IOC容器中的Bean名称。接下来，调用RootBeanDefinition类的构造方法传入ImportBeanDefinitionRegistrarBean类的Class对象创建BeanDefinition对象。最终，调用registry的registerBeanDefinition()方法将创建的BeanDefinition对象注入到IOC容器中。

**（3）修改ImportConfig类**

ImportConfig类的源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.config.ImportConfig，如下所示。

```java
@Import(value = {User.class, MyImportSelector.class, MyImportBeanDefinitionRegistrar.class})
@Configuration
public class ImportConfig {
}
```

可以看到，在ImportConfig类上标注的@Import注解的value属性中，新增了实现了ImportBeanDefinitionRegistrar接口的MyImportBeanDefinitionRegistrar类的Class对象。

**（4）运行ImportTest类**

运行ImportTest类的main()方法，输出的结果信息如下所示。

```bash
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
importConfig
io.binghe.spring.annotation.chapter05.bean.User
io.binghe.spring.annotation.chapter05.bean.ImportSelectorBean
io.binghe.spring.annotation.chapter05.bean.ImportBeanDefinitionRegistrarBean
```

可以看到，在输出的结果信息中，除了Spring内部的Bean名称、ImportConfig类的Bean名称、User类的Bean名称和ImportSelectorBean类的Bean名称外，还输出了ImportBeanDefinitionRegistrarBean类的名称。但是并没有输出实现了ImportBeanDefinitionRegistrar接口的MyImportBeanDefinitionRegistrar类的Bean名称。

**说明：使用@Import注解能够引入实现了ImportBeanDefinitionRegistrar接口的类，使用registerBeanDefinitions()方法中的BeanDefinitionRegistry对象注入BeanDefinition对象到IOC容器中，但是实现了ImportBeanDefinitionRegistrar接口的类对象本身不会被注册到IOC容器中。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本节，就以源码时序图的方式，直观的感受下@Import注解在Spring源码层面的执行流程。@Import注解在Spring源码层面的执行流程如图5-1~5-3所示。

![图5-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-24-001.png)

![图5-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-24-002.png)

![图5-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-24-003.png)

由图5-1~图5-3可以看出，@Import注解在Spring源码层面的执行流程会涉及到ImportTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、MyImportSelector类、ConfigurationClassBeanDefinitionReader类、ImportBeanDefinitionRegistrar类、MyImportBeanDefinitionRegistrar类和DefaultListableBeanFactory类。具体的源码执行细节参见源码解析部分。

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

@Bean注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻。

（1）运行案例程序启动类

案例程序启动类源码详见：spring-annotation-chapter-05工程下的io.binghe.spring.annotation.chapter05.ImportTest，运行ImportTest类的main()方法。

在ImportTest类的main()方法中调用了AnnotationConfigApplicationContext类的构造方法，并传入了ImportConfig类的Class对象来创建IOC容器。接下来，会进入AnnotationConfigApplicationContext类的构造方法。

（2）解析AnnotationConfigApplicationContext类的AnnotationConfigApplicationContext(Class<?>... componentClasses)构造方法

源码详见：org.springframework.context.annotation.AnnotationConfigApplicationContext#AnnotationConfigApplicationContext(Class<?>... componentClasses)。

```java
public AnnotationConfigApplicationContext(Class<?>... componentClasses) {
    this();
    register(componentClasses);
    refresh();
}
```

可以看到，在上述构造方法中，调用了refresh()方法来刷新IOC容器。

（3）解析AbstractApplicationContext类的refresh()方法

源码详见：org.springframework.context.support.AbstractApplicationContext#refresh()。

```java
@Override
public void refresh() throws BeansException, IllegalStateException {
    synchronized (this.startupShutdownMonitor) {
        //############省略其他代码##############
        try {
            //############省略其他代码##############
            invokeBeanFactoryPostProcessors(beanFactory);
           //############省略其他代码##############
        }catch (BeansException ex) {
            //############省略其他代码##############
        }finally {
            //############省略其他代码##############
        }
    }
}
```

refresh()方法是Spring中一个非常重要的方法，很多重要的功能和特性都是通过refresh()方法进行注入的。可以看到，在refresh()方法中，调用了invokeBeanFactoryPostProcessors()方法。

（4）解析AbstractApplicationContext类的invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory)方法

源码详见：org.springframework.context.support.AbstractApplicationContext#invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory)。

```java
protected void invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory) {
    PostProcessorRegistrationDelegate.invokeBeanFactoryPostProcessors(beanFactory, getBeanFactoryPostProcessors());
    if (!NativeDetector.inNativeImage() && beanFactory.getTempClassLoader() == null && beanFactory.containsBean(LOAD_TIME_WEAVER_BEAN_NAME)) {
        beanFactory.addBeanPostProcessor(new LoadTimeWeaverAwareProcessor(beanFactory));
        beanFactory.setTempClassLoader(new ContextTypeMatchClassLoader(beanFactory.getBeanClassLoader()));
    }
}
```

可以看到，在AbstractApplicationContext类的invokeBeanFactoryPostProcessors()方法中调用了PostProcessorRegistrationDelegate类的invokeBeanFactoryPostProcessors()方法。

（5）解析PostProcessorRegistrationDelegate类的invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory, List<BeanFactoryPostProcessor> beanFactoryPostProcessors)方法

源码详见：org.springframework.context.support.PostProcessorRegistrationDelegate#invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory, List<BeanFactoryPostProcessor> beanFactoryPostProcessors)。

由于方法的源码比较长，这里，只关注当前最核心的逻辑，如下所示。

```java
public static void invokeBeanFactoryPostProcessors(
    ConfigurableListableBeanFactory beanFactory, List<BeanFactoryPostProcessor> beanFactoryPostProcessors) {

    //############省略其他代码##############
    List<BeanDefinitionRegistryPostProcessor> currentRegistryProcessors = new ArrayList<>();

    // First, invoke the BeanDefinitionRegistryPostProcessors that implement PriorityOrdered.
    String[] postProcessorNames =
        beanFactory.getBeanNamesForType(BeanDefinitionRegistryPostProcessor.class, true, false);
    for (String ppName : postProcessorNames) {
        if (beanFactory.isTypeMatch(ppName, PriorityOrdered.class)) {
            currentRegistryProcessors.add(beanFactory.getBean(ppName, BeanDefinitionRegistryPostProcessor.class));
            processedBeans.add(ppName);
        }
    }
    sortPostProcessors(currentRegistryProcessors, beanFactory);
    registryProcessors.addAll(currentRegistryProcessors);
    invokeBeanDefinitionRegistryPostProcessors(currentRegistryProcessors, registry, beanFactory.getApplicationStartup());
    currentRegistryProcessors.clear();

    // Next, invoke the BeanDefinitionRegistryPostProcessors that implement Ordered.
    postProcessorNames = beanFactory.getBeanNamesForType(BeanDefinitionRegistryPostProcessor.class, true, false);
    for (String ppName : postProcessorNames) {
        if (!processedBeans.contains(ppName) && beanFactory.isTypeMatch(ppName, Ordered.class)) {
            currentRegistryProcessors.add(beanFactory.getBean(ppName, BeanDefinitionRegistryPostProcessor.class));
            processedBeans.add(ppName);
        }
    }
    sortPostProcessors(currentRegistryProcessors, beanFactory);
    registryProcessors.addAll(currentRegistryProcessors);
    invokeBeanDefinitionRegistryPostProcessors(currentRegistryProcessors, registry, beanFactory.getApplicationStartup());
    currentRegistryProcessors.clear();

    // Finally, invoke all other BeanDefinitionRegistryPostProcessors until no further ones appear.
    boolean reiterate = true;
    while (reiterate) {
        reiterate = false;
        postProcessorNames = beanFactory.getBeanNamesForType(BeanDefinitionRegistryPostProcessor.class, true, false);
        for (String ppName : postProcessorNames) {
            if (!processedBeans.contains(ppName)) {
                currentRegistryProcessors.add(beanFactory.getBean(ppName, BeanDefinitionRegistryPostProcessor.class));
                processedBeans.add(ppName);
                reiterate = true;
            }
        }
        sortPostProcessors(currentRegistryProcessors, beanFactory);
        registryProcessors.addAll(currentRegistryProcessors);
        invokeBeanDefinitionRegistryPostProcessors(currentRegistryProcessors, registry, beanFactory.getApplicationStartup());
        currentRegistryProcessors.clear();
    }
    //############省略其他代码##############
}
```

可以看到，在PostProcessorRegistrationDelegate类的invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory, List<BeanFactoryPostProcessor> beanFactoryPostProcessors)方法中，BeanDefinitionRegistryPostProcessor的实现类在执行逻辑上会有先后顺序，并且最终都会调用invokeBeanDefinitionRegistryPostProcessors()方法。

（6）解析PostProcessorRegistrationDelegate类的invokeBeanDefinitionRegistryPostProcessors(Collection<? extends BeanDefinitionRegistryPostProcessor> postProcessors, BeanDefinitionRegistry registry, ApplicationStartup applicationStartup)方法

源码详见：org.springframework.context.support.PostProcessorRegistrationDelegate#invokeBeanDefinitionRegistryPostProcessors(Collection<? extends BeanDefinitionRegistryPostProcessor> postProcessors, BeanDefinitionRegistry registry, ApplicationStartup applicationStartup)。

```java
private static void invokeBeanDefinitionRegistryPostProcessors(
    Collection<? extends BeanDefinitionRegistryPostProcessor> postProcessors, BeanDefinitionRegistry registry, ApplicationStartup applicationStartup) {

    for (BeanDefinitionRegistryPostProcessor postProcessor : postProcessors) {
        StartupStep postProcessBeanDefRegistry = applicationStartup.start("spring.context.beandef-registry.post-process")
            .tag("postProcessor", postProcessor::toString);
        postProcessor.postProcessBeanDefinitionRegistry(registry);
        postProcessBeanDefRegistry.end();
    }
}
```

可以看到，在invokeBeanDefinitionRegistryPostProcessors()方法中，会循环遍历postProcessors集合中的每个元素，调用postProcessBeanDefinitionRegistry()方法注册Bean的定义信息。

（7）解析ConfigurationClassPostProcessor类的postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry)方法

源码详见：org.springframework.context.annotation.ConfigurationClassPostProcessor#postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry)。

```java
@Override
public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
	//##########省略其他代码###################
    processConfigBeanDefinitions(registry);
}
```

可以看到，在postProcessBeanDefinitionRegistry()方法中，会调用processConfigBeanDefinitions()方法。

（8）解析ConfigurationClassPostProcessor类的processConfigBeanDefinitions(BeanDefinitionRegistry registry)方法

源码详见：org.springframework.context.annotation.ConfigurationClassPostProcessor#processConfigBeanDefinitions(BeanDefinitionRegistry registry)。

这里，重点关注方法中的如下逻辑。

```java
public void processConfigBeanDefinitions(BeanDefinitionRegistry registry) {
    //############省略其他代码#################
    // Parse each @Configuration class
    ConfigurationClassParser parser = new ConfigurationClassParser(
        this.metadataReaderFactory, this.problemReporter, this.environment,
        this.resourceLoader, this.componentScanBeanNameGenerator, registry);
    
    Set<BeanDefinitionHolder> candidates = new LinkedHashSet<>(configCandidates);
    Set<ConfigurationClass> alreadyParsed = new HashSet<>(configCandidates.size());
    do {
        StartupStep processConfig = this.applicationStartup.start("spring.context.config-classes.parse");
        parser.parse(candidates);
        parser.validate();
        //############省略其他代码#################
        this.reader.loadBeanDefinitions(configClasses);
        alreadyParsed.addAll(configClasses);
        processConfig.tag("classCount", () -> String.valueOf(configClasses.size())).end();
        //############省略其他代码#################
    }
    while (!candidates.isEmpty());
    //############省略其他代码#################
}
```

可以看到，在processConfigBeanDefinitions()方法中，创建了一个ConfigurationClassParser类型的对象parser，并且调用了parser的parse()方法来解析类的配置信息。

（9）解析ConfigurationClassParser类的parse(Set<BeanDefinitionHolder> configCandidates)方法

源码详见：org.springframework.context.annotation.ConfigurationClassParser#parse(Set<BeanDefinitionHolder> configCandidates)，重点关注如下代码片段

```java
public void parse(Set<BeanDefinitionHolder> configCandidates) {
    for (BeanDefinitionHolder holder : configCandidates) {
        BeanDefinition bd = holder.getBeanDefinition();
        try {
            if (bd instanceof AnnotatedBeanDefinition) {
                parse(((AnnotatedBeanDefinition) bd).getMetadata(), holder.getBeanName());
            }
            //###############省略其他代码###############
        }
        catch (BeanDefinitionStoreException ex) {
            throw ex;
        }
        catch (Throwable ex) {
            throw new BeanDefinitionStoreException(
                "Failed to parse configuration class [" + bd.getBeanClassName() + "]", ex);
        }
    }
    this.deferredImportSelectorHandler.process();
}
```

可以看到，在ConfigurationClassParser类的parse(Set<BeanDefinitionHolder> configCandidates)方法中，调用了类中的另一个parse()方法。

（10）解析ConfigurationClassParser类的parse(AnnotationMetadata metadata, String beanName)方法

源码详见：org.springframework.context.annotation.ConfigurationClassParser#parse(AnnotationMetadata metadata, String beanName)

```java
protected final void parse(AnnotationMetadata metadata, String beanName) throws IOException {
    processConfigurationClass(new ConfigurationClass(metadata, beanName), DEFAULT_EXCLUSION_FILTER);
}
```

可以看到，上述parse()方法的实现比较简单，直接调用了processConfigurationClass()方法。

（11）解析ConfigurationClassParser类的processConfigurationClass(ConfigurationClass configClass, Predicate<String> filter)方法

源码详见：org.springframework.context.annotation.ConfigurationClassParser#processConfigurationClass(ConfigurationClass configClass, Predicate<String> filter)。

```java
protected void processConfigurationClass(ConfigurationClass configClass, Predicate<String> filter) throws IOException {
    //###############省略其他代码####################
    SourceClass sourceClass = asSourceClass(configClass, filter);
    do {
        sourceClass = doProcessConfigurationClass(configClass, sourceClass, filter);
    }
    while (sourceClass != null);
    this.configurationClasses.put(configClass, configClass);
}
```

可以看到，在processConfigurationClass()方法中，会通过do-while()循环获取配置类和其父类的注解信息，SourceClass类中会封装配置类上注解的详细信息。在在processConfigurationClass()方法中，调用了doProcessConfigurationClass()方法。

（12）解析ConfigurationClassParser类的doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)方法

源码详见：org.springframework.context.annotation.ConfigurationClassParser#doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)，重点关注如下代码片段。

```java
protected final SourceClass doProcessConfigurationClass(
    ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)
    throws IOException {
	 //#############省略其他代码#############
    // Process any @Import annotations
    processImports(configClass, sourceClass, getImports(sourceClass), filter, true);
    //#############省略其他代码#############
    // No superclass -> processing is complete
    return null;
}
```

可以看到，在doProcessConfigurationClass()方法中，会调用processImports()方法来解析@Import注解。

（13）解析ConfigurationClassParser类的processImports(ConfigurationClass configClass, SourceClass currentSourceClass, Collection<SourceClass> importCandidates, Predicate<String> exclusionFilter, boolean checkForCircularImports)方法。

源码详见：org.springframework.context.annotation.ConfigurationClassParser#processImports(ConfigurationClass configClass, SourceClass currentSourceClass, Collection<SourceClass> importCandidates, Predicate<String> exclusionFilter, boolean checkForCircularImports)。

```java
private void processImports(ConfigurationClass configClass, SourceClass currentSourceClass,
                            Collection<SourceClass> importCandidates, Predicate<String> exclusionFilter,
                            boolean checkForCircularImports) {
	//################省略其他代码#################
    this.importStack.push(configClass);
    try {
        for (SourceClass candidate : importCandidates) {
            if (candidate.isAssignable(ImportSelector.class)) {
                // Candidate class is an ImportSelector -> delegate to it to determine imports
                Class<?> candidateClass = candidate.loadClass();
                ImportSelector selector = ParserStrategyUtils.instantiateClass(candidateClass, ImportSelector.class, this.environment, this.resourceLoader, this.registry);
                Predicate<String> selectorFilter = selector.getExclusionFilter();
                if (selectorFilter != null) {
                    exclusionFilter = exclusionFilter.or(selectorFilter);
                }
                if (selector instanceof DeferredImportSelector) {
                    this.deferredImportSelectorHandler.handle(configClass, (DeferredImportSelector) selector);
                }
                else {
                    String[] importClassNames = selector.selectImports(currentSourceClass.getMetadata());
                    Collection<SourceClass> importSourceClasses = asSourceClasses(importClassNames, exclusionFilter);
                    processImports(configClass, currentSourceClass, importSourceClasses, exclusionFilter, false);
                }
            }
            else if (candidate.isAssignable(ImportBeanDefinitionRegistrar.class)) {
                // Candidate class is an ImportBeanDefinitionRegistrar ->
                // delegate to it to register additional bean definitions
                Class<?> candidateClass = candidate.loadClass();
                ImportBeanDefinitionRegistrar registrar =
                    ParserStrategyUtils.instantiateClass(candidateClass, ImportBeanDefinitionRegistrar.class,
                                                         this.environment, this.resourceLoader, this.registry);
                configClass.addImportBeanDefinitionRegistrar(registrar, currentSourceClass.getMetadata());
            }
            else {
                // Candidate class not an ImportSelector or ImportBeanDefinitionRegistrar ->
                // process it as an @Configuration class
                this.importStack.registerImport(
                    currentSourceClass.getMetadata(), candidate.getMetadata().getClassName());
                processConfigurationClass(candidate.asConfigClass(configClass), exclusionFilter);
            }
        }
    }
    catch (BeanDefinitionStoreException ex) {
        throw ex;
    }
    catch (Throwable ex) {
        throw new BeanDefinitionStoreException(
            "Failed to process import candidates for configuration class [" +
            configClass.getMetadata().getClassName() + "]: " + ex.getMessage(), ex);
    }
    finally {
        this.importStack.pop();
    }
}
```

在processImports()方法中，如果使用@Import注解引入的是实现了ImportSelector接口的类，则执行的是` if (candidate.isAssignable(ImportSelector.class)) `条件的逻辑。如果@Import注解引入的是实现了ImportBeanDefinitionRegistrar接口的类，则执行的是` else if (candidate.isAssignable(ImportBeanDefinitionRegistrar.class))`条件的逻辑，否则执行的是`else`条件的逻辑。

其中，执行` if (candidate.isAssignable(ImportSelector.class)) `条件的逻辑时，会调用ImportSelector接口的selectImports()方法获取要注入到IOC容器中的Bean名称数组，如下所示。

```java
String[] importClassNames = selector.selectImports(currentSourceClass.getMetadata());
```

调用ImportSelector接口的selectImports()方法时，就会调用案例程序中的MyImportSelector类的selectImports()方法。

（14）解析MyImportSelector类的selectImports(AnnotationMetadata importingClassMetadata)方法

源码详见：io.binghe.spring.annotation.chapter05.selector.MyImportSelector#selectImports(AnnotationMetadata importingClassMetadata)

```java
@Override
public String[] selectImports(AnnotationMetadata importingClassMetadata) {
    return new String[]{ImportSelectorBean.class.getName()};
}
```

可以看到，在MyImportSelector类的selectImports()方法中，会返回包含ImportSelectorBean类的全类名的String数组，后续会将ImportSelectorBean类的Bean对象注入IOC容器。

（15）回到ConfigurationClassParser类的processImports(ConfigurationClass configClass, SourceClass currentSourceClass, Collection<SourceClass> importCandidates, Predicate<String> exclusionFilter, boolean checkForCircularImports)方法。

如果@Import注解引入的是实现了ImportBeanDefinitionRegistrar接口的类，则执行的是` else if (candidate.isAssignable(ImportBeanDefinitionRegistrar.class))`条件的逻辑，如下所示。

```java
else if (candidate.isAssignable(ImportBeanDefinitionRegistrar.class)) {
    Class<?> candidateClass = candidate.loadClass();
    ImportBeanDefinitionRegistrar registrar =
        ParserStrategyUtils.instantiateClass(candidateClass, ImportBeanDefinitionRegistrar.class, this.environment, this.resourceLoader, this.registry);
    configClass.addImportBeanDefinitionRegistrar(registrar, currentSourceClass.getMetadata());
}
```

可以看到，在上述代码逻辑中会调用configClass的addImportBeanDefinitionRegistrar()方法来添加ImportBeanDefinitionRegistrar对象。

（16）解析ConfigurationClass类的addImportBeanDefinitionRegistrar(ImportBeanDefinitionRegistrar registrar, AnnotationMetadata importingClassMetadata)方法

源码详见：org.springframework.context.annotation.ConfigurationClass#addImportBeanDefinitionRegistrar(ImportBeanDefinitionRegistrar registrar, AnnotationMetadata importingClassMetadata)。

```java
void addImportBeanDefinitionRegistrar(ImportBeanDefinitionRegistrar registrar, AnnotationMetadata importingClassMetadata) {
    this.importBeanDefinitionRegistrars.put(registrar, importingClassMetadata);
}
```

可以看到，在addImportBeanDefinitionRegistrar()方法中，会将传入的registrar参数作为Key，importingClassMetadata参数作为Value存储importBeanDefinitionRegistrars结构中。

其中，importBeanDefinitionRegistrars结构的定义如下所示。

```java
private final Map<ImportBeanDefinitionRegistrar, AnnotationMetadata> importBeanDefinitionRegistrars = new LinkedHashMap<>();
```

可以看到，importBeanDefinitionRegistrars是一个LinkedHashMap对象，也就是说，会将ImportBeanDefinitionRegistrar对象和AnnotationMetadata对象的映射关系存入一个LinkedHashMap对象中。

（17）再次回到ConfigurationClassParser类的processImports(ConfigurationClass configClass, SourceClass currentSourceClass, Collection<SourceClass> importCandidates, Predicate<String> exclusionFilter, boolean checkForCircularImports)方法。

如果@Import注解引入的类既没有实现ImportSelector接口，又没有实现ImportBeanDefinitionRegistrar接口，则执行`else`逻辑，如下所示。

```java
else {
    this.importStack.registerImport(
        currentSourceClass.getMetadata(), candidate.getMetadata().getClassName());
    processConfigurationClass(candidate.asConfigClass(configClass), exclusionFilter);
}
```

在`else`逻辑中，会按照解析@Configuration注解的逻辑执行，有关@Configuration注解的执行流程，可以参见第1章的内容，这里不再赘述。

其实，在processImports()方法中，如果@Import注解引入的类实现了ImportSelector接口，并且没有实现DeferredImportSelector接口的话，最终还是会执行processImports()方法的`else`逻辑。

（18）回到ConfigurationClassPostProcessor类的processConfigBeanDefinitions(BeanDefinitionRegistry registry)方法。

在ConfigurationClassPostProcessor类的processConfigBeanDefinitions()方法中，执行完ConfigurationClassParser类的parse()方法后，会执行ConfigurationClassBeanDefinitionReader类的loadBeanDefinitions()方法，如下所示。

```java
this.reader.loadBeanDefinitions(configClasses);
```

（19）解析ConfigurationClassBeanDefinitionReader类的loadBeanDefinitions(Set<ConfigurationClass> configurationModel)方法

源码详见：org.springframework.context.annotation.ConfigurationClassBeanDefinitionReader#loadBeanDefinitions(Set<ConfigurationClass> configurationModel)，如下所示。

```java
public void loadBeanDefinitions(Set<ConfigurationClass> configurationModel) {
    TrackedConditionEvaluator trackedConditionEvaluator = new TrackedConditionEvaluator();
    for (ConfigurationClass configClass : configurationModel) {
        loadBeanDefinitionsForConfigurationClass(configClass, trackedConditionEvaluator);
    }
}
```

可以看到，在loadBeanDefinitions()方法中，会循环遍历传入的configurationModel集合，并调用loadBeanDefinitionsForConfigurationClass()方法处理遍历的每个元素。

（20）解析ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForConfigurationClass(ConfigurationClass configClass, TrackedConditionEvaluator trackedConditionEvaluator)方法

源码详见：org.springframework.context.annotation.ConfigurationClassBeanDefinitionReader#loadBeanDefinitionsForConfigurationClass(ConfigurationClass configClass, TrackedConditionEvaluator trackedConditionEvaluator)。

```java
private void loadBeanDefinitionsForConfigurationClass(ConfigurationClass configClass, TrackedConditionEvaluator trackedConditionEvaluator) {
    //################省略其他代码######################
    if (configClass.isImported()) {
        registerBeanDefinitionForImportedConfigurationClass(configClass);
    }
    for (BeanMethod beanMethod : configClass.getBeanMethods()) {
        loadBeanDefinitionsForBeanMethod(beanMethod);
    }

    loadBeanDefinitionsFromImportedResources(configClass.getImportedResources());
    loadBeanDefinitionsFromRegistrars(configClass.getImportBeanDefinitionRegistrars());
}
```

在loadBeanDefinitionsForConfigurationClass()方法中，如果@Import注解引入的是普通的类，或者是实现了ImportSelector接口的类，则会执行`if (configClass.isImported())`条件的逻辑，此时会调用registerBeanDefinitionForImportedConfigurationClass()方法向IOC容器中注入配置类的BeanDefinition信息。

（21）解析ConfigurationClassBeanDefinitionReader类的registerBeanDefinitionForImportedConfigurationClass(ConfigurationClass configClass)方法

源码详见：org.springframework.context.annotation.ConfigurationClassBeanDefinitionReader#registerBeanDefinitionForImportedConfigurationClass(ConfigurationClass configClass)，如下所示。

```java
private void registerBeanDefinitionForImportedConfigurationClass(ConfigurationClass configClass) {
    //###############省略其他代码#################
    BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(configBeanDef, configBeanName);
    definitionHolder = AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
  this.registry.registerBeanDefinition(definitionHolder.getBeanName(),definitionHolder.getBeanDefinition());
    configClass.setBeanName(configBeanName);
	//###############省略其他代码#################
}
```

可以看到，在registerBeanDefinitionForImportedConfigurationClass()方法中会调用DefaultListableBeanFactory类的registerBeanDefinition()方法向IOC容器中注入BeanDefinition信息。最终，会将BeanDefinition信息保存到DefaultListableBeanFactory类的beanDefinitionMap中。

（22）回到ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForConfigurationClass(ConfigurationClass configClass, TrackedConditionEvaluator trackedConditionEvaluator)方法

如果@Import注解引入的是实现了ImportBeanDefinitionRegistrar接口的类，则在loadBeanDefinitionsForConfigurationClass()方法中调用loadBeanDefinitionsForConfigurationClass()方法时，会通过configClass的getImportBeanDefinitionRegistrars()方法获取第（16）步保存信息的LinkedHashMap对象。

（23）解析ConfigurationClass类的getImportBeanDefinitionRegistrars()方法

源码详见：org.springframework.context.annotation.ConfigurationClass#getImportBeanDefinitionRegistrars()。

```java
Map<ImportBeanDefinitionRegistrar, AnnotationMetadata> getImportBeanDefinitionRegistrars() {
    return this.importBeanDefinitionRegistrars;
}
```

（24）再次ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForConfigurationClass(ConfigurationClass configClass, TrackedConditionEvaluator trackedConditionEvaluator)方法。

在loadBeanDefinitionsForConfigurationClass()会调用loadBeanDefinitionsFromRegistrars()方法从实现了ImportBeanDefinitionRegistrar接口的类中加载Bean定义信息。

（25）解析ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsFromRegistrars(Map<ImportBeanDefinitionRegistrar, AnnotationMetadata> registrars)方法

源码详见：org.springframework.context.annotation.ConfigurationClassBeanDefinitionReader#loadBeanDefinitionsFromRegistrars(Map<ImportBeanDefinitionRegistrar, AnnotationMetadata> registrars)。

```java
private void loadBeanDefinitionsFromRegistrars(Map<ImportBeanDefinitionRegistrar, AnnotationMetadata> registrars) {
    registrars.forEach((registrar, metadata) -> registrar.registerBeanDefinitions(metadata, this.registry, this.importBeanNameGenerator));
}
```

可以看到，在loadBeanDefinitionsFromRegistrars()方法中，会遍历传入的registrars，并调用每个registrar的registerBeanDefinitions()方法注册BeanDefinition信息。

（26）解析ImportBeanDefinitionRegistrar接口的registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry,BeanNameGenerator importBeanNameGenerator)方法

源码详见：org.springframework.context.annotation.ImportBeanDefinitionRegistrar#registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry,BeanNameGenerator importBeanNameGenerator)

```java
default void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry,BeanNameGenerator importBeanNameGenerator) {
    registerBeanDefinitions(importingClassMetadata, registry);
}
```

可以看到，registerBeanDefinitions()方法是ImportBeanDefinitionRegistrar接口的一个默认方法，并在方法中调用了另一个registerBeanDefinitions()方法。其中，调用的这个registerBeanDefinitions()方法就是我们自己写的案例中实现了ImportBeanDefinitionRegistrar接口的MyImportBeanDefinitionRegistrar类中的方法。

（27）解析MyImportBeanDefinitionRegistrar类的registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry)方法

源码详见：io.binghe.spring.annotation.chapter05.registrar.MyImportBeanDefinitionRegistrar#registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry)。

```java
@Override
public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
    String beanName = ImportBeanDefinitionRegistrarBean.class.getName();
    BeanDefinition beanDefinition = new RootBeanDefinition(ImportBeanDefinitionRegistrarBean.class);
    registry.registerBeanDefinition(beanName, beanDefinition);
}
```

可以看到，在registerBeanDefinitions()方法中，最终会调用DefaultListableBeanFactory类的registerBeanDefinition()方法向IOC容器中注入BeanDefinition信息。最终，会将BeanDefinition信息保存到DefaultListableBeanFactory类的beanDefinitionMap中。

至此，整个@Import注解在Spring源码层面的执行流程分析完毕。

## 六、总结

`@Import注解讲完了，我们一起总结下吧！`

本章，首先介绍了@Import注解的源码和使用场景，并列举了使用@Import注解向IOC容器中注入Bean对象的三种案例。接下来，详细分析了@Import注解的源码时序图和@Import注解在Spring源码层面的执行流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Import注解，通常会有如下几个经典面试题：

* 在ConfigurationClassParser类的processImports()中，如果@Import注解引入的是普通类或者引入的是实现了ImportSelector接口，并且没有实现DeferredImportSelector接口的类，最终还是会执行processImports()方法的`else`逻辑。那么，如果@Import注解引入的是实现了ImportSelector接口，并且没有实现DeferredImportSelector接口的类，最终是如何执行`else`逻辑的？
* @Import注解的三种案例在Spring底层的源码执行流程分别是什么？
* 使用@Import注解向IOC容器中注入Bean与使用@Bean注解有什么区别？
* 在你自己负责的项目中，会在哪些场景下使用@Import注解向IOC容器中注入Bean？
* 你从Spring的@Import注解的设计中得到了哪些启发？

## 八、VIP服务

**强烈推荐：《[原来大厂面试官也会在这里偷偷学习！](https://mp.weixin.qq.com/s/Zp0nI2RyFb_UCYpSsUt2OQ)》，如果文中优惠券过期，可长按或扫码下面优惠券二维码加入星球。**

![星球优惠券](https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-18-008.png)

**冰河技术** 知识星球《SpringCloud Alibaba实战》从零搭建并开发微服务项目已完结，《RPC手撸专栏》已经更新120+篇文章，已提交120+项目工程，120+项目源码Tag分支，并将源码的获取方式放到了知识星球中，同时在微信上创建了专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

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