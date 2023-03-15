---
layout: post
category: binghe-code-spring
title: 第14章：深度解析@Resource注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第14章：深度解析@Resource注解
lock: need
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



![图14-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-08-002.png)

由图14-1~14-2可以看出，解析并获取@Resource修饰的属性的源码时序图涉及ResourceTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类、AbstractBeanFactory类、AbstractAutowireCapableBeanFactory类和CommonAnnotationBeanPostProcessor类。具体的源码执行细节参见源码解析部分。 

### 4.2 为@Resource修饰属性赋值

为@Resource修饰属性赋值的源码时序图与为@Autowired修饰属性赋值的源码时序图基本相同，只是部分细节略有差异。本节，就简单介绍下为@Resource修饰属性赋值的源码时序图，整体如图14-3~14-4所示。

![图14-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-08-003.png)



![图14-4](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-08-004.png)

由图14-3~14-4可以看出，为@Resource修饰属性赋值的源码时序图涉及ResourceTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类、AbstractBeanFactory类、AbstractAutowireCapableBeanFactory类、CommonAnnotationBeanPostProcessor类、InjectionMetadata类和InjectedElement类。具体的源码执行细节参见源码解析部分。

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

本节，主要分析@Resource注解在Spring源码层面的执行流程，同样的，本节也会从解析并获取 @Resource修饰的属性和为 @Resource修饰属性赋值两个方面分析源码执行流程，并且结合源码执行的时序图，会理解的更加深刻。

**注意：本节以单例Bean为例分析，并且基于@Resource注解标注到类的字段上的源码流程为例进行分析，@Resource注解标注到类的方法上的源码流程与标注到字段上的源码流程基本相同，不再赘述。**

### 5.1 解析并获取@Resource修饰的属性

由于解析并获取@Resource修饰的属性的源码流程总体上与解析并获取@Autowired修饰的属性的源码流程相同，本节，只会介绍略有差异的部分，直接从AbstractAutowireCapableBeanFactory类的applyMergedBeanDefinitionPostProcessors()方法开始解析。

（1）解析AbstractAutowireCapableBeanFactory类的applyMergedBeanDefinitionPostProcessors(RootBeanDefinition mbd, Class<?> beanType, String beanName)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#applyMergedBeanDefinitionPostProcessors(RootBeanDefinition mbd, Class<?> beanType, String beanName)。

```java
protected void applyMergedBeanDefinitionPostProcessors(RootBeanDefinition mbd, Class<?> beanType, String beanName) {
    for (MergedBeanDefinitionPostProcessor processor : getBeanPostProcessorCache().mergedDefinition) {
        processor.postProcessMergedBeanDefinition(mbd, beanType, beanName);
    }
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的applyMergedBeanDefinitionPostProcessors()方法中，会调用循环遍历出的processor对象的postProcessMergedBeanDefinition()方法。

（2）解析CommonAnnotationBeanPostProcessor类的postProcessMergedBeanDefinition(RootBeanDefinition beanDefinition, Class<?> beanType, String beanName)方法

源码详见：org.springframework.context.annotation.CommonAnnotationBeanPostProcessor#postProcessMergedBeanDefinition(RootBeanDefinition beanDefinition, Class<?> beanType, String beanName)。

```java
@Override
public void postProcessMergedBeanDefinition(RootBeanDefinition beanDefinition, Class<?> beanType, String beanName) {
    super.postProcessMergedBeanDefinition(beanDefinition, beanType, beanName);
    InjectionMetadata metadata = findResourceMetadata(beanName, beanType, null);
    metadata.checkConfigMembers(beanDefinition);
}
```

可以看到，在解析@Resource注解时，会进入CommonAnnotationBeanPostProcessor类的postProcessMergedBeanDefinition()。在CommonAnnotationBeanPostProcessor类的postProcessMergedBeanDefinition()方法中，调用了findResourceMetadata()方法来查找使用@Resource注解标注的资源，并返回了InjectionMetadata类的对象metadata。

（3）解析CommonAnnotationBeanPostProcessor类的findResourceMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs)方法

源码详见：org.springframework.context.annotation.CommonAnnotationBeanPostProcessor#findResourceMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs)。

```java
private InjectionMetadata findResourceMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs) {
    // Fall back to class name as cache key, for backwards compatibility with custom callers.
    String cacheKey = (StringUtils.hasLength(beanName) ? beanName : clazz.getName());
    // Quick check on the concurrent map first, with minimal locking.
    InjectionMetadata metadata = this.injectionMetadataCache.get(cacheKey);
    if (InjectionMetadata.needsRefresh(metadata, clazz)) {
        synchronized (this.injectionMetadataCache) {
            metadata = this.injectionMetadataCache.get(cacheKey);
            if (InjectionMetadata.needsRefresh(metadata, clazz)) {
                if (metadata != null) {
                    metadata.clear(pvs);
                }
                metadata = buildResourceMetadata(clazz);
                this.injectionMetadataCache.put(cacheKey, metadata);
            }
        }
    }
    return metadata;
}
```

可以看到，在CommonAnnotationBeanPostProcessor类的findResourceMetadata()方法中，首先会从injectionMetadataCache中获取InjectionMetadata对象，如果InjectionMetadata对象存在并且不需要刷新InjectionMetadata对象，则直接返回InjectionMetadata对象。否则，就调用buildResourceMetadata()方法来构建InjectionMetadata对象，并将其放入injectionMetadataCache缓存中。

（4）解析CommonAnnotationBeanPostProcessor类的buildResourceMetadata(Class<?> clazz)方法

源码详见：org.springframework.context.annotation.CommonAnnotationBeanPostProcessor#buildResourceMetadata(Class<?> clazz)。重点关注如下代码片段。

```java
private InjectionMetadata buildResourceMetadata(Class<?> clazz) {
    if (!AnnotationUtils.isCandidateClass(clazz, resourceAnnotationTypes)) {
        return InjectionMetadata.EMPTY;
    }

    List<InjectionMetadata.InjectedElement> elements = new ArrayList<>();
    Class<?> targetClass = clazz;
    do {
        final List<InjectionMetadata.InjectedElement> currElements = new ArrayList<>();
        ReflectionUtils.doWithLocalFields(targetClass, field -> {
            if (ejbClass != null && field.isAnnotationPresent(ejbClass)) {
                if (Modifier.isStatic(field.getModifiers())) {
                    throw new IllegalStateException("@EJB annotation is not supported on static fields");
                }
                currElements.add(new EjbRefElement(field, field, null));
            }
            else if (field.isAnnotationPresent(Resource.class)) {
                if (Modifier.isStatic(field.getModifiers())) {
                    throw new IllegalStateException("@Resource annotation is not supported on static fields");
                }
                if (!this.ignoredResourceTypes.contains(field.getType().getName())) {
                    currElements.add(new ResourceElement(field, field, null));
                }
            }
        });
        /***********省略其他代码**********/
        elements.addAll(0, currElements);
        targetClass = targetClass.getSuperclass();
    }
    while (targetClass != null && targetClass != Object.class);
    return InjectionMetadata.forElements(elements, clazz);
}
```

可以看到，在CommonAnnotationBeanPostProcessor类的buildResourceMetadata()方法中，会获取类中声明的所有字段，并解析标注了@Resource注解的字段，并且当前字段如果是静态字段，就会抛出IllegalStateException异常。这也是@Resource注解不能为类的静态字段赋值的原因。最终，将解析出的字段封装成InjectionMetadata对象并返回，添加到injectionMetadataCache中，后续就可以直接从injectionMetadataCache中获取数据并处理。

至此，解析并获取@Resource修饰的属性的流程分析完毕。

### 5.2 为@Resource修饰属性赋值

由于为@Resource修饰属性赋值的源码流程总体上与为@Autowired修饰属性赋值的源码流程相同，本节，只会介绍略有差异的部分，直接从AbstractAutowireCapableBeanFactory类的populateBean()方法开始解析。

（1）解析AbstractAutowireCapableBeanFactory类的populateBean(String beanName, RootBeanDefinition mbd, @Nullable BeanWrapper bw)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#populateBean(String beanName, RootBeanDefinition mbd, @Nullable BeanWrapper bw)。重点关注如下代码。

```java
protected void populateBean(String beanName, RootBeanDefinition mbd, @Nullable BeanWrapper bw) {
     /*************省略其他代码*************/
    if (hasInstantiationAwareBeanPostProcessors()) {
        if (pvs == null) {
            pvs = mbd.getPropertyValues();
        }
        for (InstantiationAwareBeanPostProcessor bp : getBeanPostProcessorCache().instantiationAware) {
            PropertyValues pvsToUse = bp.postProcessProperties(pvs, bw.getWrappedInstance(), beanName);
            if (pvsToUse == null) {
                return;
            }
            pvs = pvsToUse;
        }
    }
    /*************省略其他代码*************/
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的populateBean()中，会调用遍历出的InstantiationAwareBeanPostProcessor对象的postProcessProperties()方法处理属性的值。

（2）解析CommonAnnotationBeanPostProcessor类的postProcessProperties(PropertyValues pvs, Object bean, String beanName)方法

源码详见：org.springframework.context.annotation.CommonAnnotationBeanPostProcessor#postProcessProperties(PropertyValues pvs, Object bean, String beanName)。

```java
@Override
public PropertyValues postProcessProperties(PropertyValues pvs, Object bean, String beanName) {
    InjectionMetadata metadata = findResourceMetadata(beanName, bean.getClass(), pvs);
    try {
        metadata.inject(bean, beanName, pvs);
    }
    catch (Throwable ex) {
        throw new BeanCreationException(beanName, "Injection of resource dependencies failed", ex);
    }
    return pvs;
}
```

可以看到，在解析@Resource注解时，会进入CommonAnnotationBeanPostProcessor类的postProcessProperties()方法。在postProcessProperties()方法中，会调用findResourceMetadata()方法查找被@Resource注解标注的资源。

（3）解析CommonAnnotationBeanPostProcessor类的findResourceMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs)方法

源码详见：org.springframework.context.annotation.CommonAnnotationBeanPostProcessor#findResourceMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs)。

```java
private InjectionMetadata findResourceMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs) {
    // Fall back to class name as cache key, for backwards compatibility with custom callers.
    String cacheKey = (StringUtils.hasLength(beanName) ? beanName : clazz.getName());
    // Quick check on the concurrent map first, with minimal locking.
    InjectionMetadata metadata = this.injectionMetadataCache.get(cacheKey);
    if (InjectionMetadata.needsRefresh(metadata, clazz)) {
        synchronized (this.injectionMetadataCache) {
            metadata = this.injectionMetadataCache.get(cacheKey);
            if (InjectionMetadata.needsRefresh(metadata, clazz)) {
                if (metadata != null) {
                    metadata.clear(pvs);
                }
                metadata = buildResourceMetadata(clazz);
                this.injectionMetadataCache.put(cacheKey, metadata);
            }
        }
    }
    return metadata;
}
```

可以看到，再次调用了findResourceMetadata()方法，由于在解析并获取@Resource修饰的属性时，就调用过findResourceMetadata()方法，并将获取到的InjectionMetadata对象存放到了injectionMetadataCache中，所以，后续会直接从injectionMetadataCache中获取数据并返回。

（4）返回CommonAnnotationBeanPostProcessor类的postProcessProperties(PropertyValues pvs, Object bean, String beanName)方法。再次查看源码。

```java
@Override
public PropertyValues postProcessProperties(PropertyValues pvs, Object bean, String beanName) {
    InjectionMetadata metadata = findResourceMetadata(beanName, bean.getClass(), pvs);
    try {
        metadata.inject(bean, beanName, pvs);
    }
    catch (Throwable ex) {
        throw new BeanCreationException(beanName, "Injection of resource dependencies failed", ex);
    }
    return pvs;
}
```

可以看到，在postProcessProperties()方法中会调用InjectionMetadata对象metadata的inject()方法向字段中装配Bean。

（5）解析InjectionMetadata类的inject(Object target, @Nullable String beanName, @Nullable PropertyValues pvs)方法

源码详见：org.springframework.beans.factory.annotation.InjectionMetadata#inject(Object target, @Nullable String beanName, @Nullable PropertyValues pvs)。

```java
public void inject(Object target, @Nullable String beanName, @Nullable PropertyValues pvs) throws Throwable {
    Collection<InjectedElement> checkedElements = this.checkedElements;
    Collection<InjectedElement> elementsToIterate =  (checkedElements != null ? checkedElements : this.injectedElements);
    if (!elementsToIterate.isEmpty()) {
        for (InjectedElement element : elementsToIterate) {
            element.inject(target, beanName, pvs);
        }
    }
}
```

可以看到，在InjectionMetadata类的inject()方法中，会循环调用遍历出的InjectedElement对象的inject()方法，向类的字段中装配Bean。

（6）解析InjectedElement类的inject(Object target, @Nullable String requestingBeanName, @Nullable PropertyValues pvs)方法

源码详见：org.springframework.beans.factory.annotation.InjectionMetadata.InjectedElement#inject(Object target, @Nullable String requestingBeanName, @Nullable PropertyValues pvs)。

```java
protected void inject(Object target, @Nullable String requestingBeanName, @Nullable PropertyValues pvs) throws Throwable {
    if (this.isField) {
        Field field = (Field) this.member;
        ReflectionUtils.makeAccessible(field);
        field.set(target, getResourceToInject(target, requestingBeanName));
    }
   /**********省略其他代码************/
}
```

可以看到，在InjectedElement类的inject()方法中，首先会通过getResourceToInject()方法来获取要注入的值，随后通过Java反射技术将值设置到对应的字段上。

（6）解析ResourceElement类的getResourceToInject(Object target, @Nullable String requestingBeanName)方法

源码详见：org.springframework.context.annotation.CommonAnnotationBeanPostProcessor.ResourceElement#getResourceToInject(Object target, @Nullable String requestingBeanName)。

```java
@Override
protected Object getResourceToInject(Object target, @Nullable String requestingBeanName) {
    return (this.lazyLookup ? buildLazyResourceProxy(this, requestingBeanName) : getResource(this, requestingBeanName));
}
```

在ResourceElement类的getResourceToInject()方法中，首先判断lazyLookup的值是否是true，如果为true，则调用buildLazyResourceProxy()方法返回结果，否则，调用getResource()方法返回结果。返回结果数据后，在在InjectedElement类的inject()方法中通过Java反射技术将返回的结果数据设置到对应的字段中。

至此，为@Resource修饰属性赋值的流程分析完毕。

## 六、总结

`@Resource注解介绍完了，我们一起总结下吧！`

本章，主要对JSR250规范中提供的@Resource注解进行了简单的介绍。首先，介绍了注解的源码和使用场景。随后，给出了注解的使用案例。接下来，从解析并获取@Resource修饰的属性和为@Resource修饰的属性赋值两个方面详细分析了源码时序图和源码流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Resource注解，通常会有如下几个经典面试题：

* @Resource注解的作用是什么？
* @Resource注解有哪些使用场景？
* @Resource向Bean的字段和方法注入值是如何实现的？
* @Resource与@Autowired的区别是什么？
* @Resource注解在Spring内部的执行流程？
* @Resource注解在Spring源码中的执行流程与@Autowired注解有何区别？
* 你在平时工作中，会在哪些场景下使用@Resource注解？
* 你从@Resource注解的设计中得到了哪些启发？

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