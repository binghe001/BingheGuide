---
layout: post
category: binghe-code-spring
title: 第18章：深度解析@PostConstruct注解与@PreDestroy注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第18章：深度解析@PostConstruct注解与@PreDestroy注解
lock: need
---

# 《Spring核心技术》第18章：深度解析@PostConstruct注解与@PreDestroy注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-18](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-18)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@PostConstruct注解与@PreDestroy注解标注的方法的执行时机和流程，从源码级别彻底掌握@PostConstruct注解与@PreDestroy注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * @PostConstruct源码时序图
  * @PreDestroy源码时序图
* 源码解析
  * @PostConstruct源码解析
  * @PreDestroy源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@PostConstruct与@PreDestroy注解，你真的彻底了解过吗？`

Spring中可以通过注解指定方法的执行时机，比如可以指定方法在创建Bean后在为属性赋值后，初始化Bean之前执行，也可以让方法在Bean销毁之前执行。那这些又是如何实现的呢？

## 二、注解说明

`关于@PostConstruct注解与@PreDestroy注解的一点点说明~~`

@PostConstruct注解与@PreDestroy注解都是JSR250规范中提供的注解。@PostConstruct注解标注的方法可以在创建Bean后在为属性赋值后，初始化Bean之前执行，@PreDestroy注解标注的方法可以在Bean销毁之前执行。在Spring6中，如果使用@PostConstruct注解与@PreDestroy注解，则需要在Maven的pom.xml文件中添加如下依赖。

```xml
<dependency>
    <groupId>jakarta.annotation</groupId>
    <artifactId>jakarta.annotation-api</artifactId>
    <version>2.1.1</version>
</dependency>
```

### 2.1 注解源码

**1.@PostConstruct注解**

@PostConstruct注解的源码详见：jakarta.annotation.PostConstruct。

```java
@Documented
@Retention (RUNTIME)
@Target(METHOD)
public @interface PostConstruct {
}
```

在实际开发项目的过程中，@PostConstruct注解通常被用来指定一些Bean对象的初始化操作。在@PostConstruct注解中并未提供任何属性。

**2.@PreDestroy注解**

@PreDestroy注解的源码详见：jakarta.annotation.PreDestroy。

```java
@Documented
@Retention (RUNTIME)
@Target(METHOD)
public @interface PreDestroy {
}
```

在实际开发项目的过程中，@PreDestroy注解通常被用来实现在Bean销毁之前执行的一些操作，比如释放资源、释放数据库连接等操作。在@PreDestroy注解中并未提供任何属性。

### 2.2 使用场景

使用Spring开发项目的过程中，如果在Bean对象创建完成后，需要对Bean对象中的成员进行一些初始化操作，就可以使用@PostConstruct注解注解实现。如果在Bean对象销毁之前，对系统中的一些资源进行清理，例如释放占用的资源，释放数据库连接等，就可以使用@PreDestroy注解实现。

## 三、使用案例

`一起实现@PostConstruct注解与@PreDestroy注解的案例，怎么样?`

本章，就一同实现@PostConstruct注解与@PreDestroy注解的案例，在@PostConstruct注解与@PreDestroy注解标注的方法中打印对应的日志，观察方法的执行时机。具体案例实现步骤如下所示。

**（1）新增PrePostBean类**

PrePostBean类的源码详见：spring-annotation-chapter-18工程下的io.binghe.spring.annotation.chapter18.bean.PrePostBean。

```java
public class PrePostBean {
    public PrePostBean(){
        System.out.println("执行PrePostBean的构造方法...");
    }
    public void init(){
        System.out.println("执行PrePostBean的init方法...");
    }
    @PostConstruct
    public void postConstruct(){
        System.out.println("执行PrePostBean的postConstruct方法...");
    }
    @PreDestroy
    public void preDestroy(){
        System.out.println("执行PrePostBean的preDestroy方法...");
    }
    public void destroy(){
        System.out.println("执行PrePostBean的destroy方法...");
    }
}
```

可以看到，在PrePostBean类中提供了多个方法，含义如下所示。

* PrePostBean()方法：构造方法。
* init()方法：初始化方法，会在@Bean注解中的initMethod属性中指定初始化方法。
* postConstruct()方法：被@PostConstruct注解标注的方法，会在为Bean的属性赋值之后，初始化Bean之前执行。
* preDestroy()：被@PreDestroy注解标注的方法，会在Bean销毁之前执行。
* destroy()方法：销毁方法，会在@Bean注解中的destroyMethod属性中指定销毁方法。

**（2）新增PrePostConfig类**

PrePostConfig类的源码详见：spring-annotation-chapter-18工程下的io.binghe.spring.annotation.chapter18.config.PrePostConfig。

```java
@Configuration
public class PrePostConfig {
    @Bean(initMethod = "init", destroyMethod = "destroy")
    public PrePostBean prePostBean(){
        return new PrePostBean();
    }
}
```

可以看到， 在PrePostConfig类上标注了@Configuration注解，说明PrePostConfig类是案例程序的配置类。并且在PrePostConfig类中的prePostBean()方法上标注了@Bean注解，并通过@Bean注解的initMethod属性指定的初始化方法为PrePostBean类的init()方法，通过@Bean注解的destroyMethod属性指定的销毁方法为PrePostBean类的destroy()方法。

**（3）新增PrePostTest类**

PrePostTest类的源码详见：spring-annotation-chapter-18工程下的io.binghe.spring.annotation.chapter18.PrePostTest。

```java
public class PrePostTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(PrePostConfig.class);
        context.close();
    }
}
```

可以看到，在PrePostTest类的main()方法中，调用AnnotationConfigApplicationContext类的构造方法创建IOC容器后，随后调用close()方法关闭IOC容器。

**（4）运行PrePostTest类**

运行PrePostTest类的main()方法，输出的结果信息如下所示。

```bash
执行PrePostBean的构造方法...
执行PrePostBean的postConstruct方法...
执行PrePostBean的init方法...
执行PrePostBean的preDestroy方法...
执行PrePostBean的destroy方法...
```

从输出的结果信息可以看出，方法的执行顺序为：构造方法—>被@PostConstruct注解标注的方法—>@Bean注解中initMethod属性指定的方法—>被@PreDestroy注解标注的方法—>@Bean注解中destroyMethod属性指定的方法。

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本章，会分别介绍@PostConstruct注解和@PreDestroy注解的源码时序图。

### 4.1 @PostConstruct源码时序图

本节，就简单介绍下@PostConstruct注解的源码时序图，@PostConstruct注解的源码时序图如图18-1~18-2所示。

![图18-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-13-001.png)



![图18-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-13-002.png)

由图18-1~18-2可以看出，@PostConstruct注解的执行的源码时序图涉及到PrePostTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类、AbstractBeanFactory类、AbstractAutowireCapableBeanFactory类、InitDestroyAnnotationBeanPostProcessor类、LifecycleMetadata类、LifecycleElement类和PrePostBean类，具体的源码执行细节参见源码解析部分。 

### 4.2 @PreDestroy源码时序图

本节，就简单介绍下@PreDestroy注解的源码时序图，@PreDestroy注解的源码时序图如图18-3~18-4所示。

![图18-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-13-003.png)



![图18-4](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-13-004.png)

由18-3~18-4可以看出，@PreDestroy注解的源码时序图涉及到PrePostTest类、AbstractApplicationContext类、DefaultListableBeanFactory类、DefaultSingletonBeanRegistry类、DisposableBeanAdapter类、InitDestroyAnnotationBeanPostProcessor类、LifecycleMetadata类、LifecycleElement类和PrePostBean类，具体的源码执行细节参见源码解析部分。 

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

本章，会分别介绍@PostConstruct注解和@PreDestroy注解的源码时序图。

### 5.1 @PostConstruct源码解析

@PostConstruct注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图18-1~18-2进行理解。

本节对@PostConstruct注解的源码分析大体流程与第3章中5.2节调用初始化方法的源码分析流程相同，只是部分细节不同。本节，只介绍与第3章中5.2节中不同的部分。直接从AbstractAutowireCapableBeanFactory类的initializeBean()方法开始解析

（1）解析AbstractAutowireCapableBeanFactory类的initializeBean(String beanName, Object bean, @Nullable RootBeanDefinition mbd)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#initializeBean(String beanName, Object bean, @Nullable RootBeanDefinition mbd)。

```java
protected Object initializeBean(String beanName, Object bean, @Nullable RootBeanDefinition mbd) {
    /*************省略其他代码**********/
    Object wrappedBean = bean;
    if (mbd == null || !mbd.isSynthetic()) {
        wrappedBean = applyBeanPostProcessorsBeforeInitialization(wrappedBean, beanName);
    }
	/*************省略其他代码**********/
    return wrappedBean;
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的initializeBean()方法中，调用Bean的初始化方法之前，会调用applyBeanPostProcessorsBeforeInitialization()方法进行处理。

（2）解析AbstractAutowireCapableBeanFactory类的applyBeanPostProcessorsBeforeInitialization(Object existingBean, String beanName)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#applyBeanPostProcessorsBeforeInitialization(Object existingBean, String beanName)。

```java
@Override
public Object applyBeanPostProcessorsBeforeInitialization(Object existingBean, String beanName) throws BeansException {
    Object result = existingBean;
    for (BeanPostProcessor processor : getBeanPostProcessors()) {
        Object current = processor.postProcessBeforeInitialization(result, beanName);
        if (current == null) {
            return result;
        }
        result = current;
    }
    return result;
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的applyBeanPostProcessorsBeforeInitialization()方法中，会循环遍历所有的BeanPostProcessor对象，调用BeanPostProcessor对象的postProcessBeforeInitialization()方法获取Bean对象，如果获取到的Bean对象为空，则直接返回。否则，继续循环调用BeanPostProcessor对象的postProcessBeforeInitialization()方法。

（3）解析InitDestroyAnnotationBeanPostProcessor类的postProcessBeforeInitialization(Object bean, String beanName)方法

源码详见：org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor#postProcessBeforeInitialization(Object bean, String beanName)。

```java
@Override
public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
    LifecycleMetadata metadata = findLifecycleMetadata(bean.getClass());
    try {
        metadata.invokeInitMethods(bean, beanName);
    }
    catch (InvocationTargetException ex) {
       /**********省略其他代码***********/
    }
    catch (Throwable ex) {
       /**********省略其他代码***********/
    }
    return bean;
}
```

可以看到，在InitDestroyAnnotationBeanPostProcessor类的postProcessBeforeInitialization()方法中，会调用findLifecycleMetadata()方法查找生命周期相关的注解元数据。

（4）解析InitDestroyAnnotationBeanPostProcessor类的findLifecycleMetadata(Class<?> clazz)方法

源码详见：org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor#findLifecycleMetadata(Class<?> clazz)。

```java
private LifecycleMetadata findLifecycleMetadata(Class<?> clazz) {
    if (this.lifecycleMetadataCache == null) {
        return buildLifecycleMetadata(clazz);
    }
    LifecycleMetadata metadata = this.lifecycleMetadataCache.get(clazz);
    if (metadata == null) {
        synchronized (this.lifecycleMetadataCache) {
            metadata = this.lifecycleMetadataCache.get(clazz);
            if (metadata == null) {
                metadata = buildLifecycleMetadata(clazz);
                this.lifecycleMetadataCache.put(clazz, metadata);
            }
            return metadata;
        }
    }
    return metadata;
}
```

可以看到，在InitDestroyAnnotationBeanPostProcessor类的findLifecycleMetadata()方法中，如果lifecycleMetadataCache缓存为null，则直接调用buildLifecycleMetadata()方法构建生命周期元数据并返回。否则，先从lifecycleMetadataCache缓存中获取LifecycleMetadata对象，如果获取到的LifecycleMetadata对象为空，则调用buildLifecycleMetadata()方法构建生命周期元数据，并将其存放到lifecycleMetadataCache缓存中。

（5）解析InitDestroyAnnotationBeanPostProcessor类的buildLifecycleMetadata(final Class<?> clazz)方法

源码详见：org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor#buildLifecycleMetadata(final Class<?> clazz)。

```java
private LifecycleMetadata buildLifecycleMetadata(final Class<?> clazz) {
    if (!AnnotationUtils.isCandidateClass(clazz, Arrays.asList(this.initAnnotationType, this.destroyAnnotationType))) {
        return this.emptyLifecycleMetadata;
    }
    List<LifecycleElement> initMethods = new ArrayList<>();
    List<LifecycleElement> destroyMethods = new ArrayList<>();
    Class<?> targetClass = clazz;
    do {
        final List<LifecycleElement> currInitMethods = new ArrayList<>();
        final List<LifecycleElement> currDestroyMethods = new ArrayList<>();
        ReflectionUtils.doWithLocalMethods(targetClass, method -> {
            if (this.initAnnotationType != null && method.isAnnotationPresent(this.initAnnotationType)) {
                LifecycleElement element = new LifecycleElement(method);
                currInitMethods.add(element);
                if (logger.isTraceEnabled()) {
                    logger.trace("Found init method on class [" + clazz.getName() + "]: " + method);
                }
            }
            if (this.destroyAnnotationType != null && method.isAnnotationPresent(this.destroyAnnotationType)) {
                currDestroyMethods.add(new LifecycleElement(method));
                if (logger.isTraceEnabled()) {
                    logger.trace("Found destroy method on class [" + clazz.getName() + "]: " + method);
                }
            }
        });
        initMethods.addAll(0, currInitMethods);
        destroyMethods.addAll(currDestroyMethods);
        targetClass = targetClass.getSuperclass();
    }
    while (targetClass != null && targetClass != Object.class);
    return (initMethods.isEmpty() && destroyMethods.isEmpty() ? this.emptyLifecycleMetadata :
            new LifecycleMetadata(clazz, initMethods, destroyMethods));
}
```

可以看到，在InitDestroyAnnotationBeanPostProcessor类的buildLifecycleMetadata()方法中，首先，查看类中如果没有被@PostConstruct注解和@PreDestroy注解标注的方法，则直接返回emptyLifecycleMetadata对象。否则，循环类中的所有方法，判断方法上是否标注了@PostConstruct注解，如果标注了@PostConstruct注解，则将当前方法封装到element对象中，并将element对象添加到currInitMethods集合中，并将currInitMethods集合添加到initMethods集合中。同理，会将标注了@PreDestroy注解的方法封装到LifecycleElement类的对象中，并添加到destroyMethods集合中。

这里，有个问题就是：initAnnotationType和destroyAnnotationType是在哪里赋值的？initAnnotationType和destroyAnnotationType的值是在CommonAnnotationBeanPostProcessor类的构造方法中赋值的，如下所示。

```java
public CommonAnnotationBeanPostProcessor() {
    setOrder(Ordered.LOWEST_PRECEDENCE - 3);
    setInitAnnotationType(PostConstruct.class);
    setDestroyAnnotationType(PreDestroy.class);
    // java.naming module present on JDK 9+?
    if (jndiPresent) {
        this.jndiFactory = new SimpleJndiBeanFactory();
    }
}
```

可以看到，在CommonAnnotationBeanPostProcessor类的构造方法中，调用setInitAnnotationType()方法将initAnnotationType赋值为@PostConstruct注解的Class对象。调用setDestroyAnnotationType()方法将destroyAnnotationType赋值为@PreDestroy注解的Class对象。

（6）返回InitDestroyAnnotationBeanPostProcessor类的postProcessBeforeInitialization(Object bean, String beanName)方法

此时重点关注如下代码片段。

```java
@Override
public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
    LifecycleMetadata metadata = findLifecycleMetadata(bean.getClass());
    try {
        metadata.invokeInitMethods(bean, beanName);
    }
    /***********省略其他代码**********/
    return bean;
}
```

可以看到，在InitDestroyAnnotationBeanPostProcessor类的postProcessBeforeInitialization()方法中，会调用查找到的metadata对象的invokeInitMethods()方法来执行初始化方法。

（7）解析LifecycleMetadata类的invokeInitMethods(Object target, String beanName)方法

源码详见：org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor.LifecycleMetadata#invokeInitMethods(Object target, String beanName)

```java
public void invokeInitMethods(Object target, String beanName) throws Throwable {
    Collection<LifecycleElement> checkedInitMethods = this.checkedInitMethods;
    Collection<LifecycleElement> initMethodsToIterate = (checkedInitMethods != null ? checkedInitMethods : this.initMethods);
    if (!initMethodsToIterate.isEmpty()) {
        for (LifecycleElement element : initMethodsToIterate) {
            /********省略其他代码*************/
            element.invoke(target);
        }
    }
}
```

可以看到，在LifecycleMetadata类的invokeInitMethods()方法中，会循环遍历initMethodsToIterate集合，并调用遍历出的每个element对象的invoke()方法。

（8）解析LifecycleElement类的invoke(Object target)方法

源码详见：org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor.LifecycleElement#invoke(Object target)。

```java
public void invoke(Object target) throws Throwable {
    ReflectionUtils.makeAccessible(this.method);
    this.method.invoke(target, (Object[]) null);
}
```

可以看到，在LifecycleElement类的invoke()方法中，会通过Java反射调用标注了@PostConstruct注解的方法。在本章的案例程序中，就会调用PrePostBean类的postConstruct()方法。

至此，@PostConstruct注解在Spring源码层面的执行流程分析完毕。

### 5.2 @PreDestroy源码解析

@PreDestroy注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图18-3~18-4进行理解。

本节对@PreDestroy注解的源码分析大体流程与第3章中5.3节调用销毁方法的源码分析流程相同，只是部分细节不同。本节，只介绍与第3章中5.3节中不同的部分。直接从DisposableBeanAdapter类的destroy()方法开始解析。

（1）解析DisposableBeanAdapter类的destroy()方法

源码详见：org.springframework.beans.factory.support.DisposableBeanAdapter#destroy()。

```java
@Override
public void destroy() {
    if (!CollectionUtils.isEmpty(this.beanPostProcessors)) {
        for (DestructionAwareBeanPostProcessor processor : this.beanPostProcessors) {
            processor.postProcessBeforeDestruction(this.bean, this.beanName);
        }
    }
	/************省略其他代码**************/
}
```

可以看到，在DisposableBeanAdapter类的destroy()方法中，会遍历beanPostProcessors集合，调用每个processor对象的postProcessBeforeDestruction()方法执行Bean销毁前的操作。

（2）解析InitDestroyAnnotationBeanPostProcessor类的postProcessBeforeDestruction(Object bean, String beanName)方法

源码详见：org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor#postProcessBeforeDestruction(Object bean, String beanName)。

```java
@Override
public void postProcessBeforeDestruction(Object bean, String beanName) throws BeansException {
    LifecycleMetadata metadata = findLifecycleMetadata(bean.getClass());
    try {
        metadata.invokeDestroyMethods(bean, beanName);
    }
    catch (InvocationTargetException ex) {
       /***********省略其他代码************/
    }
    catch (Throwable ex) {
        /***********省略其他代码************/
    }
}
```

可以看到，InitDestroyAnnotationBeanPostProcessor类的postProcessBeforeDestruction()方法中，也会调用findLifecycleMetadata()方法来查找与Bean的生命周期有关的注解，执行逻辑与本章5.1节中调用findLifecycleMetadata()方法的逻辑相同，这里不再赘述。后续会调用通过findLifecycleMetadata()方法获取到的metadata对象的invokeDestroyMethods()方法来执行销毁方法。

（3）解析LifecycleMetadata类的invokeDestroyMethods(Object target, String beanName)方法

源码详见：org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor.LifecycleMetadata#invokeDestroyMethods(Object target, String beanName)。

```java
public void invokeDestroyMethods(Object target, String beanName) throws Throwable {
    Collection<LifecycleElement> checkedDestroyMethods = this.checkedDestroyMethods;
    Collection<LifecycleElement> destroyMethodsToUse = (checkedDestroyMethods != null ? checkedDestroyMethods : this.destroyMethods);
    if (!destroyMethodsToUse.isEmpty()) {
        for (LifecycleElement element : destroyMethodsToUse) {
            if (logger.isTraceEnabled()) {
                logger.trace("Invoking destroy method on bean '" + beanName + "': " + element.getMethod());
            }
            element.invoke(target);
        }
    }
}
```

可以看到，在LifecycleMetadata类的invokeDestroyMethods()方法中，会遍历所有标注了@PreDestroy注解的方法，并执行对应的方法。

（4）解析LifecycleElement类的invoke(Object target)方法

源码详见：org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor.LifecycleElement#invoke(Object target)。

```java
public void invoke(Object target) throws Throwable {
    ReflectionUtils.makeAccessible(this.method);
    this.method.invoke(target, (Object[]) null);
}
```

可以看到，在LifecycleElement类的invoke()方法中，会通过Java反射的方式调用对应的方法。在本章的案例程序中，就是调用PrePostBean类的preDestroy()方法。

至此，@PreDestroy注解在Spring源码层面的执行流程分析完毕。

## 六、总结

`@PostConstruct注解和@PreDestroy注解注解介绍完了，我们一起总结下吧！`

本章，主要对@PostConstruct注解和@PreDestroy注解进行简单的介绍。首先，介绍了注解的源码和使用场景。随后，给出了实战案例。接下来，分别介绍了@PostConstruct注解和@PreDestroy注解的源码时序图和源码流程。

最后，给大家总结下Bean的初始化的完整过程，如图18-5所示。

![图18-5](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-13-005.png)

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@PostConstruct注解和@PreDestroy注解注解，通常会有如下几个经典面试题：

* @PostConstruct注解和@PreDestroy注解的作用是什么？
* @PostConstruct注解和@PreDestroy注解有哪些使用场景？
* @PostConstruct注解和@PreDestroy注解是如何体现Bean的生命周期的？
* @PostConstruct注解和@PreDestroy注解在Spring内部的执行流程？
* 你在平时工作中，会在哪些场景下使用@PostConstruct注解和@PreDestroy注解？
* 你从@PostConstruct注解和@PreDestroy注解的设计中得到了哪些启发？

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

