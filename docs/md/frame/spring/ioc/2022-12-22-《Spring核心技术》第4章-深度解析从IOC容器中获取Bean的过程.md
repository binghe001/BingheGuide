---
layout: post
category: binghe-code-spring
title: 第04章：深度解析从IOC容器中获取Bean的过程
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第04章：深度解析从IOC容器中获取Bean的过程
lock: need
---

# 《Spring核心技术》第04章-驱动型注解：深度解析从IOC容器中获取Bean的过程

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-04](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-04)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步了解从IOC容器中获取Bean的过程，初步了解IOC容器使用三级缓存解决循环依赖问题，为后续深度学习Spring创建Bean的过程打下坚实的基础。

------

## 一、学习指引

`你了解过从Spring IOC容器中获取Bean的过程吗？`

学习过Spring的小伙伴都知道：如果是单实例Bean，则IOC容器启动时，就会创建Bean对象，IOC容器关闭时，销毁Bean对象。如果是多实例Bean，IOC容器在启动时，不会创建Bean对象，在每次从IOC容器中获取Bean对象时，都会创建新的Bean对象返回，IOC容器关闭时，也不会销毁对象。也就是说，如果是多实例Bean，IOC容器不会管理Bean对象。

那从IOC容器中获取Bean的具体过程是怎样的呢？想深度学习Spring源码的小伙伴继续往下看。

## 二、测试案例

`整个调试Spring6.0源码的案例玩玩儿呗？`

本章的案例比较简单，只是实现一个用于调试源码的小案例，具体的实现步骤如下所示。

（1）创建配置类BeanConfig

BeanConfig类的源码详见：spring-annotation-chapter-04工程下的io.binghe.spring.annotation.chapter04.config.BeanConfig。

```java
@Configuration
@ComponentScan(basePackages = "io.binghe.spring.annotation.chapter04")
public class BeanConfig {
}
```

可以看到，在BeanConfig类上标注了@Configuration注解，说明BeanConfig类是Spring的配置类，使用@ComponentScan注解标注了扫描的包是`io.binghe.spring.annotation.chapter04`。

（2）创建测试类BeanTest

BeanTest类的源码详见：spring-annotation-chapter-04工程下的io.binghe.spring.annotation.chapter04.BeanTest。

```java
public class BeanTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(BeanConfig.class);
        context.close();
    }
}
```

可以看到，在BeanTest类中只是简单的使用AnnotationConfigApplicationContext类创建IOC容器，并关闭IOC容器。

好了，测试案例准备好了，接下来，就一步步分析从IOC容器中获取Bean的过程。

## 三、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

其实，经过前面章节的学习，细心的小伙伴在调试Spring源码的过程中会发现，在Spring的AbstractApplicationContext类中的refresh()方法中，会调用invokeBeanFactoryPostProcessors()方法，就是在这个invokeBeanFactoryPostProcessors()方法中后续的调用过程中，会调用beanFactory对象的getBean()方法来获取Bean对象。本章，就一起分析从invokeBeanFactoryPostProcessors()方法中获取Bean对象的过程。

从IOC容器中获取Bean的过程的源码时序图如图4-1和4-2所示。

![图4-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-22-001.png)

![图4-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2022-12-22-002.png)

由图4-1和图4-2可以看出，从IOC容器中获取Bean的过程会涉及到BeanTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、AbstractBeanFactory类、DefaultSingletonBeanRegistry类和AbstractAutowireCapableBeanFactory类。具体的源码执行细节参见源码解析部分。

## 四、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

从IOC容器中获取Bean的过程的源码执行流程，结合源码执行的时序图，会理解的更加深刻。

（1）运行案例程序启动类

案例程序启动类源码详见：spring-annotation-chapter-04工程下的io.binghe.spring.annotation.chapter04.BeanTest，运行BeanTest类的main()方法。

在BeanTest类的main()方法中调用了AnnotationConfigApplicationContext类的构造方法，并传入了ComponentScanConfig类的Class对象来创建IOC容器。接下来，会进入AnnotationConfigApplicationContext类的构造方法。

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

可以看到，在PostProcessorRegistrationDelegate类的invokeBeanFactoryPostProcessors(ConfigurableListableBeanFactory beanFactory, List<BeanFactoryPostProcessor> beanFactoryPostProcessors)方法中，有多处通过beanFactory对象的getBean()方法获取Bean对象的代码。

（6）解析AbstractBeanFactory类的getBean(String name, Class<T> requiredType)方法

源码详见org.springframework.beans.factory.support.AbstractBeanFactory#getBean(String name, Class<T> requiredType)。

```java
@Override
public <T> T getBean(String name, Class<T> requiredType) throws BeansException {
    return doGetBean(name, requiredType, null, false);
}
```

可以看到，getBean()方法调用了doGetBean()方法。

（7）解析AbstractBeanFactory类的doGetBean(String name, Class<T> requiredType, Object[] args, boolean typeCheckOnly)方法

源码详见：org.springframework.beans.factory.support.AbstractBeanFactory#doGetBean(String name, @Nullable Class<T> requiredType, @Nullable Object[] args, boolean typeCheckOnly)。

```java
protected <T> T doGetBean(
    String name, @Nullable Class<T> requiredType, @Nullable Object[] args, boolean typeCheckOnly)
    throws BeansException {

    String beanName = transformedBeanName(name);
    Object beanInstance;

    // Eagerly check singleton cache for manually registered singletons.
    Object sharedInstance = getSingleton(beanName);
    if (sharedInstance != null && args == null) {
        if (logger.isTraceEnabled()) {
            if (isSingletonCurrentlyInCreation(beanName)) {
                logger.trace("Returning eagerly cached instance of singleton bean '" + beanName +
                             "' that is not fully initialized yet - a consequence of a circular reference");
            }
            else {
                logger.trace("Returning cached instance of singleton bean '" + beanName + "'");
            }
        }
        beanInstance = getObjectForBeanInstance(sharedInstance, name, beanName, null);
    }

    else {
        if (isPrototypeCurrentlyInCreation(beanName)) {
            throw new BeanCurrentlyInCreationException(beanName);
        }

        BeanFactory parentBeanFactory = getParentBeanFactory();
        if (parentBeanFactory != null && !containsBeanDefinition(beanName)) {
            // Not found -> check parent.
            String nameToLookup = originalBeanName(name);
            if (parentBeanFactory instanceof AbstractBeanFactory abf) {
                return abf.doGetBean(nameToLookup, requiredType, args, typeCheckOnly);
            }
            else if (args != null) {
                // Delegation to parent with explicit args.
                return (T) parentBeanFactory.getBean(nameToLookup, args);
            }
            else if (requiredType != null) {
                // No args -> delegate to standard getBean method.
                return parentBeanFactory.getBean(nameToLookup, requiredType);
            }
            else {
                return (T) parentBeanFactory.getBean(nameToLookup);
            }
        }

        if (!typeCheckOnly) {
            markBeanAsCreated(beanName);
        }

        StartupStep beanCreation = this.applicationStartup.start("spring.beans.instantiate")
            .tag("beanName", name);
        try {
            if (requiredType != null) {
                beanCreation.tag("beanType", requiredType::toString);
            }
            RootBeanDefinition mbd = getMergedLocalBeanDefinition(beanName);
            checkMergedBeanDefinition(mbd, beanName, args);

            // Guarantee initialization of beans that the current bean depends on.
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

            // Create bean instance.
            if (mbd.isSingleton()) {
                sharedInstance = getSingleton(beanName, () -> {
                    try {
                        return createBean(beanName, mbd, args);
                    }
                    catch (BeansException ex) {
                        destroySingleton(beanName);
                        throw ex;
                    }
                });
                beanInstance = getObjectForBeanInstance(sharedInstance, name, beanName, mbd);
            }

            else if (mbd.isPrototype()) {
                // It's a prototype -> create a new instance.
                Object prototypeInstance = null;
                try {
                    beforePrototypeCreation(beanName);
                    prototypeInstance = createBean(beanName, mbd, args);
                }
                finally {
                    afterPrototypeCreation(beanName);
                }
                beanInstance = getObjectForBeanInstance(prototypeInstance, name, beanName, mbd);
            }

            else {
                String scopeName = mbd.getScope();
                if (!StringUtils.hasLength(scopeName)) {
                    throw new IllegalStateException("No scope name defined for bean '" + beanName + "'");
                }
                Scope scope = this.scopes.get(scopeName);
                if (scope == null) {
                    throw new IllegalStateException("No Scope registered for scope name '" + scopeName + "'");
                }
                try {
                    Object scopedInstance = scope.get(beanName, () -> {
                        beforePrototypeCreation(beanName);
                        try {
                            return createBean(beanName, mbd, args);
                        }
                        finally {
                            afterPrototypeCreation(beanName);
                        }
                    });
                    beanInstance = getObjectForBeanInstance(scopedInstance, name, beanName, mbd);
                }
                catch (IllegalStateException ex) {
                    throw new ScopeNotActiveException(beanName, scopeName, ex);
                }
            }
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

doGetBean()方法的源码比较长，也是一个非常重要的方法，方法的大体流程如下所示。

* 先通过transformedBeanName()方法转换bean的名称，这里可能是FactoryBean的名称（&开头），需要转成不带&开头的名称，如果有别名，再获取别名。
* 从缓存中获取bean，这里的缓存分为一二三级缓存，也就是spring的三级缓存。
* 根据获取到的对象再去获取想要的Bean，因为这里获取到的对象可能是需要的Bean，也可能是FactoryBean（工厂Bean）。
* 如果缓存中没有，就去创建Bean对象。
* 查看有没有父类的BeanFactory，如果有，那么就使用父类去创建Bean对象。
* 获取要创建的Bean对象的@DependsOn注解上的名称，先去创建DependsOn的Bean，并且校验是否存在循环引用。
* 创建Bean，根据类型创建不同的Bean，比如singleton，prototype，request，session等。
* 如果需要转换类型，则进行类型转换。如果不需要转换类型，就不转换类型。

本章后续的源码解析部分，都是以doGetBean()方法作为基础进行解析的。

（8）解析DefaultSingletonBeanRegistry类的getSingleton(String beanName)方法

源码详见：org.springframework.beans.factory.support.DefaultSingletonBeanRegistry#getSingleton(String beanName)

```java
@Override
@Nullable
public Object getSingleton(String beanName) {
    return getSingleton(beanName, true);
}
```

可以看到，在getSingleton()方法中调用了另一个getSingleton()方法。

（9）解析DefaultSingletonBeanRegistry类的getSingleton(String beanName, boolean allowEarlyReference)方法

源码详见：org.springframework.beans.factory.support.DefaultSingletonBeanRegistry#getSingleton(String beanName, boolean allowEarlyReference)。

```java
@Nullable
protected Object getSingleton(String beanName, boolean allowEarlyReference) {
    // Quick check for existing instance without full singleton lock
    Object singletonObject = this.singletonObjects.get(beanName);
    if (singletonObject == null && isSingletonCurrentlyInCreation(beanName)) {
        singletonObject = this.earlySingletonObjects.get(beanName);
        if (singletonObject == null && allowEarlyReference) {
            synchronized (this.singletonObjects) {
                // Consistent creation of early reference within full singleton lock
                singletonObject = this.singletonObjects.get(beanName);
                if (singletonObject == null) {
                    singletonObject = this.earlySingletonObjects.get(beanName);
                    if (singletonObject == null) {
                        ObjectFactory<?> singletonFactory = this.singletonFactories.get(beanName);
                        if (singletonFactory != null) {
                            singletonObject = singletonFactory.getObject();
                            this.earlySingletonObjects.put(beanName, singletonObject);
                            this.singletonFactories.remove(beanName);
                        }
                    }
                }
            }
        }
    }
    return singletonObject;
}
```

在Spring中，这个getSingleton(String beanName, boolean allowEarlyReference)方法是个非常重要的方法，这个方法中使用了Spring的三级缓存，在后续的文章中，还会对这个方法进行深度解析。这里，先给大家介绍下Spring的三级缓存。

* singletonObjects：一级缓存，实例化的Bean都会存储在这个Map集合中。
* earlySingletonObjects：二级缓存，存放未完成的bean的缓存，如果有代理的话，存放的是代理对象。
* singletonFactories：三级缓存，存放的是一个ObjectFactory，数据通过getObject方法获得。

（10）解析AbstractBeanFactory类的getObjectForBeanInstance(Object beanInstance, String name, String beanName, RootBeanDefinition mbd)方法

源码详见：org.springframework.beans.factory.support.AbstractBeanFactory#getObjectForBeanInstance(Object beanInstance, String name, String beanName, @Nullable RootBeanDefinition mbd)。

```java
protected Object getObjectForBeanInstance(
    Object beanInstance, String name, String beanName, @Nullable RootBeanDefinition mbd) {
    //name是否是以&开头
    if (BeanFactoryUtils.isFactoryDereference(name)) {
        if (beanInstance instanceof NullBean) {
            return beanInstance;
        }
        if (!(beanInstance instanceof FactoryBean)) {
            throw new BeanIsNotAFactoryException(beanName, beanInstance.getClass());
        }
        if (mbd != null) {
            mbd.isFactoryBean = true;
        }
        return beanInstance;
    }
	//如果bean不是FactoryBean，直接返回beanInstance
    if (!(beanInstance instanceof FactoryBean<?> factoryBean)) {
        return beanInstance;
    }

    Object object = null;
    if (mbd != null) {
        mbd.isFactoryBean = true;
    }
    else {
        //从缓存中获取对象
        object = getCachedObjectForFactoryBean(beanName);
    }
    if (object == null) {
        if (mbd == null && containsBeanDefinition(beanName)) {
            mbd = getMergedLocalBeanDefinition(beanName);
        }
        boolean synthetic = (mbd != null && mbd.isSynthetic());
        //通过FactoryBean获取需要的beanInstance
        object = getObjectFromFactoryBean(factoryBean, beanName, !synthetic);
    }
    return object;
}
```

整个getObjectForBeanInstance()方法的源码还算是比较简单，大家多看几遍就能理解。这里，给大家说明下大体的流程。

* 首先判断name是不是FactoryBean的name，也就是&开头的name，如果beanInstance不是FactoryBean则抛异常。
* 如果name是FactoryBeanName，那么需要获取的就是FactoryBean，直接返回对象。

* 如果都没有返回，那么已经可以确定此时已经可以确定beanInstance是FactoryBean了，因为如果不是FactoryBean在(beanInstance instanceof FactoryBean)就已经返回了。

* 通过FactoryBean的getObject方法获取需要的Bean实例。

（11）解析DefaultSingletonBeanRegistry类的getSingleton(String beanName, ObjectFactory<?> singletonFactory)方法。

源码详见：org.springframework.beans.factory.support.DefaultSingletonBeanRegistry#getSingleton(String beanName, ObjectFactory<?> singletonFactory)。

```java
public Object getSingleton(String beanName, ObjectFactory<?> singletonFactory) {
    Assert.notNull(beanName, "Bean name must not be null");
    synchronized (this.singletonObjects) {
        Object singletonObject = this.singletonObjects.get(beanName);
        if (singletonObject == null) {
            if (this.singletonsCurrentlyInDestruction) {
                //#########省略异常代码################
            }
            if (logger.isDebugEnabled()) {
                logger.debug("Creating shared instance of singleton bean '" + beanName + "'");
            }
            beforeSingletonCreation(beanName);
            boolean newSingleton = false;
            boolean recordSuppressedExceptions = (this.suppressedExceptions == null);
            if (recordSuppressedExceptions) {
                this.suppressedExceptions = new LinkedHashSet<>();
            }
            try {
                //获取创建的bean
                singletonObject = singletonFactory.getObject();
                newSingleton = true;
            }
            catch (IllegalStateException ex) {
                singletonObject = this.singletonObjects.get(beanName);
                if (singletonObject == null) {
                    throw ex;
                }
            }
            catch (BeanCreationException ex) {
                if (recordSuppressedExceptions) {
                    for (Exception suppressedException : this.suppressedExceptions) {
                        ex.addRelatedCause(suppressedException);
                    }
                }
                throw ex;
            }
            finally {
                if (recordSuppressedExceptions) {
                    this.suppressedExceptions = null;
                }
                afterSingletonCreation(beanName);
            }
            if (newSingleton) {
                //将创建的Bean对象加到一级缓存中
                addSingleton(beanName, singletonObject);
            }
        }
        return singletonObject;
    }
}
```

在上述getSingleton()方法中，传入了一个beanName和一个singletonFactory来创建单实例Bean对象，ObjectFactory类中封装了创建Bean的具体逻辑。在上述getSingleton()方法中，创建Bean对象之前调用了 beforeSingletonCreation()方法，在创建对象之后调用了afterSingletonCreation()方法。两个方法的源码如下所示。

```java
protected void beforeSingletonCreation(String beanName) {
    if (!this.inCreationCheckExclusions.contains(beanName) && !this.singletonsCurrentlyInCreation.add(beanName)) {
        throw new BeanCurrentlyInCreationException(beanName);
    }
}

protected void afterSingletonCreation(String beanName) {
    if (!this.inCreationCheckExclusions.contains(beanName) && !this.singletonsCurrentlyInCreation.remove(beanName)) {
        throw new IllegalStateException("Singleton '" + beanName + "' isn't currently in creation");
    }
}
```

可以看到，beforeSingletonCreation()方法和afterSingletonCreation()方法的执行逻辑比较简单，这里不再赘述。

（12）回到AbstractBeanFactory类的doGetBean(String name, Class<T> requiredType, Object[] args, boolean typeCheckOnly)方法，这里重点看如下代码片段。

```java
if (mbd.isSingleton()) {
    sharedInstance = getSingleton(beanName, () -> {
        try {
            return createBean(beanName, mbd, args);
        }
        catch (BeansException ex) {
            destroySingleton(beanName);
            throw ex;
        }
    });
    beanInstance = getObjectForBeanInstance(sharedInstance, name, beanName, mbd);
}
```

可以看到，调用了createBean()方法来创建Bean对象。

（13）解析AbstractAutowireCapableBeanFactory类的createBean(String beanName, RootBeanDefinition mbd, Object[] args)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#createBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)

```java
@Override
protected Object createBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)
    throws BeanCreationException {
	//##############省略其他代码############
    try {
        Object beanInstance = doCreateBean(beanName, mbdToUse, args);
        if (logger.isTraceEnabled()) {
            logger.trace("Finished creating instance of bean '" + beanName + "'");
        }
        return beanInstance;
    }
   //##############省略其他代码############
}
```

在createBean()方法中，只是做了一些准备工作，并没有真正的创建Bean对象，真正创建Bean对象是在doCreateBean()方法中完成的。

（14）解析AbstractAutowireCapableBeanFactory类的doCreateBean(String beanName, RootBeanDefinition mbd, Object[] args)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)。

```java
protected Object doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)
    throws BeanCreationException {

    BeanWrapper instanceWrapper = null;
    if (mbd.isSingleton()) {
        instanceWrapper = this.factoryBeanInstanceCache.remove(beanName);
    }
    if (instanceWrapper == null) {
        instanceWrapper = createBeanInstance(beanName, mbd, args);
    }
    Object bean = instanceWrapper.getWrappedInstance();
    Class<?> beanType = instanceWrapper.getWrappedClass();
    if (beanType != NullBean.class) {
        mbd.resolvedTargetType = beanType;
    }

    synchronized (mbd.postProcessingLock) {
        if (!mbd.postProcessed) {
            try {
                applyMergedBeanDefinitionPostProcessors(mbd, beanType, beanName);
            }
            catch (Throwable ex) {
                throw new BeanCreationException(mbd.getResourceDescription(), beanName,
                                                "Post-processing of merged bean definition failed", ex);
            }
            mbd.markAsPostProcessed();
        }
    }

    boolean earlySingletonExposure = (mbd.isSingleton() && this.allowCircularReferences &&
                                      isSingletonCurrentlyInCreation(beanName));
    if (earlySingletonExposure) {
        if (logger.isTraceEnabled()) {
            logger.trace("Eagerly caching bean '" + beanName +
                         "' to allow for resolving potential circular references");
        }
        addSingletonFactory(beanName, () -> getEarlyBeanReference(beanName, mbd, bean));
    }

    // Initialize the bean instance.
    Object exposedObject = bean;
    try {
        populateBean(beanName, mbd, instanceWrapper);
        exposedObject = initializeBean(beanName, exposedObject, mbd);
    }
    catch (Throwable ex) {
        if (ex instanceof BeanCreationException bce && beanName.equals(bce.getBeanName())) {
            throw bce;
        }
        else {
            throw new BeanCreationException(mbd.getResourceDescription(), beanName, ex.getMessage(), ex);
        }
    }

    if (earlySingletonExposure) {
        Object earlySingletonReference = getSingleton(beanName, false);
        if (earlySingletonReference != null) {
            if (exposedObject == bean) {
                exposedObject = earlySingletonReference;
            }
            else if (!this.allowRawInjectionDespiteWrapping && hasDependentBean(beanName)) {
                String[] dependentBeans = getDependentBeans(beanName);
                Set<String> actualDependentBeans = new LinkedHashSet<>(dependentBeans.length);
                for (String dependentBean : dependentBeans) {
                    if (!removeSingletonIfCreatedForTypeCheckOnly(dependentBean)) {
                        actualDependentBeans.add(dependentBean);
                    }
                }
                if (!actualDependentBeans.isEmpty()) {
                    //###############省略异常代码#################
                }
            }
        }
    }

    try {
        registerDisposableBeanIfNecessary(beanName, bean, mbd);
    }
    catch (BeanDefinitionValidationException ex) {
        throw new BeanCreationException(
            mbd.getResourceDescription(), beanName, "Invalid destruction signature", ex);
    }

    return exposedObject;
}
```

doCreateBean()方法的逻辑看上去还是挺复杂的。大体的流程如下所示。

* 调用createBeanInstance()方法创建bean。

* 调用属于applyMergedBeanDefinitionPostProcessors()方法。对Bean进行一些处理。
* 将bean加入到三级缓存中。
* 填充Bean需要注入的其他Bean对象。
* 调用初始化方法，先去调用@PostConstruct注解方法，然后调用InitializingBean的afterPropertiesSet，以及自定义的init-method方法。在Bean调用初始化方法之后，再去调用后置处理器接口检测是否需要生成Aop代理。
* 接着进行校验。这里稍微比较复杂一点。如果从二级缓存能取到，那就说明之前已经从三级缓存获取过。可能是因为循环依赖，也可能是因为别的地方调用了getBean方法。从三级缓存获取时有个getEarlyBeanReference()的方法，就是查看是否要生成代理的bean。如果已经生成代理的Bean，那么在调用初始化方法时，就不会在生成代理Bean了。这样满足exposedObject ==bean，直接只用代理返回。

* 如果exposedObject和bean不相等：这里的情况就是：如果是spring的@Async注解，在从二级缓存生成代理之后，再去调用初始化方法时，一样会生成代理。所以此时exposedObject不等于bean，再往下发现有循环调用，并且Bean还在创建时，就会抛出异常。

至此，从IOC容器中获取Bean的大体流程分析完毕。

## 五、总结

`从IOC容器中获取Bean的大体流程分析完了，总结下吧？`

本章，主要对从IOC容器中获取Bean的过程进行了简单的介绍。首先，通过一个测试案例来引出调试源码的过程，随后，结合源码执行的时序图详细分析了从IOC容器中获取Bean的过程源码。

## 六、思考

`既然学完了，就开始思考几个问题吧？`

* Spring为何会有循环依赖的问题？
* Spring如何解决循环依赖问题？
* Spring为何使用三级缓存解决循环依赖问题？使用二级缓存不行吗？为什么？
* Spring中为何把创建Bean对象设计的如此复杂？你觉得是出于哪方面的考虑呢？
* 从Spring的设计中，你学到了什么？

## 七、VIP服务

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