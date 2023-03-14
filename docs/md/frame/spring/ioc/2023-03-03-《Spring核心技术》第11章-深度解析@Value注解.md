---
layout: post
category: binghe-code-spring
title: 第11章：深度解析@Value注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第11章：深度解析@Value注解
lock: need
---

# 《Spring核心技术》第11章-注入数据型注解：深度解析@Value注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-11](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-11)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Value注解向Bean中注入值的案例和流程，从源码级别彻底掌握@Value注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
  * 注解用法
* 使用案例
* 源码时序图
  * 解析并获取@Value修饰的属性
  * 为@Value修饰的属性赋值
  * 使用@Value获取属性的值
* 源码解析
  * 解析并获取@Value修饰的属性
  * 为@Value修饰的属性赋值
  * 使用@Value获取属性的值
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Value注解，你真的彻底了解过吗？`

在实际开发过程中，通常会有这样一种场景：将一些配置项写到配置文件中，在业务逻辑中会读取配置文件中的配置项，取出对应的值进行业务逻辑处理。Spring中提供的@Value注解就可以读取配置文件中的值。另外@Value注解也可以向Bean中的属性设置其他值。本章，就对@Value注解进行简单的介绍。

## 二、注解说明

`关于@Value注解的一点点说明~~`

@Value注解可以向Spring的Bean的属性中注入数据。并且支持Spring的EL表达式，可以通过${} 的方式获取配置文件中的数据。配置文件支持properties、XML、和YML文件。

### 2.1 注解源码

@Value注解的源码详见：org.springframework.beans.factory.annotation.Value。

```java
/**
 * @author Juergen Hoeller
 * @since 3.0
 * @see AutowiredAnnotationBeanPostProcessor
 * @see Autowired
 * @see org.springframework.beans.factory.config.BeanExpressionResolver
 * @see org.springframework.beans.factory.support.AutowireCandidateResolver#getSuggestedValue
 */
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Value {
	String value();
}
```

从源码可以看出，@Value注解可以标注到字段、方法、参数和其他注解上，@Value注解中提供了一个String类型的value属性，具体含义如下所示。

* value：指定要向Bean的属性中注入的数据，数据可以是配置文件中的配置项，并且支持EL表达式。

### 2.2 使用场景

在实际开发中，项目中难免会有一些配置信息，此时，就可以将这些配置信息统一写到配置文件中。随后使用@Value注解读取配置文件的值来向Spring中Bean的属性设置值。

例如，一些系统环境变量信息，数据库配置，系统通用配置等等，都可以保存到配置文件中，此时就可以使用Spring的EL表达式读取配置文件中的值。

### 2.3 注解用法

本节，主要介绍不通过配置文件注入属性和通过配置文件注入属性两种情况来介绍@Value注解的用法。

**1.不通过配置文件注入属性**

通过@Value可以将外部的值动态注入到Bean中，有如下几种用法。

（1）注入普通字符串

```java
@Value("normalString")
private String normalString; 
```

（2）注入操作系统属性

```java
@Value("#{systemProperties['os.name']}")
private String osName; 
```

（3）注入表达式的结果信息

```java
@Value("#{ T(java.lang.Math).random() * 100.0 }")
private double randomNum;
```

（4）注入其他Bean属性

```java
@Value("#{otherBean.name}")
private String name; 
```

（5）注入文件资源

```java
@Value("classpath:config.properties")
private Resource resourceFile; 
```

（6）注入URL资源

```java
@Value("http://www.baidu.com")
private Resource url; 
```

**2..通过配置文件注入属性**

通过@Value(“${app.name}”)语法将属性文件的值注入到bean的属性中，

```java
@Component
@PropertySource({"classpath:config.properties","classpath:config_${anotherfile.configinject}.properties"})
public class ConfigurationFileInject{
    @Value("${user.id}")
    private String userId; 

    @Value("${user.name}")
    private String userName; 

    @Value("${user.address}")
    private String userAddress; 
}
```

**3.@Value中`#{...}`和`${...}`的区别**

这里提供一个测试属性文件：test.properties，大致的内容如下所示。

```bash
server.name=server1,server2,server3
author.name=binghe
```

测试类Test：引入test.properties文件，作为属性的注入。

```java
@Component
@PropertySource({"classpath:test.properties"})
public class Test {
}
```

**4.`${...}`的用法**

`{}`里面的内容必须符合SpEL表达式， 通过@Value(“${spelDefault.value}”)可以获取属性文件中对应的值，但是如果属性文件中没有这个属性，则会报错。可以通过赋予默认值解决这个问题，如下所示。

```bash
@Value("${author.name:binghe}")
```

上述代码的含义表示向Bean的属性中注入配置文件中的author.name属性的值，如果配置文件中没有author.name属性，则向Bean的属性中注入默认值binghe。例如下面的代码片段。

```bash
@Value("${author.name:binghe}")
private String name;
```

**5.`#{…}`的用法**

（1）SpEL：调用字符串Hello World的concat方法

```java
@Value("#{'Hello World'.concat('!')}")
private String helloWorld;
```

（2）SpEL: 调用字符串的getBytes方法，然后调用length属性

```java
@Value("#{'Hello World'.bytes.length}")
private int length;
```

**6.`${…}`和`#{…}`混合使用**

`${...}`和`#{...}`可以混合使用，如下文代码执行顺序：传入一个字符串，根据 "," 切分后插入列表中， `#{}`和`${}`配合使用，注意单引号。

```java
@Value("#{'${server.name}'.split(',')}")
private List<String> servers;
```

**注意：`${}`和`#{}`混合实用时，不能`${}`在外面，`#{}`在里面。因为Spring执行`${}`的时机要早于`#{}`，当Spring执行外层的`${}`时，内部的`#{}`为空，会执行失败。**

**7.@Value注解用法总结**

- `#{…}` 用于执行SpEl表达式，并将内容赋值给属性。
- `${…} `主要用于加载外部属性文件中的值。
- `#{…}` 和`${…}` 可以混合使用，但是必须`#{}`外面，`${}`在里面。

## 三、使用案例

`@Value的实现案例，我们一起实现吧~~`

本节，就基于@Value注解实现向Bean属性中赋值的案例，具体的实现步骤如下所示。

**（1）新增test.properties配置文件**

在spring-annotation-chapter-11工程下的resources目录下新增test.properties配置文件，内容如下所示。

```bash
db.url=jdbc:mysql://localhost:3306/test
```

**（2）新增ValueName类**

ValueName类的源码详见：spring-annotation-chapter-11工程下的io.binghe.spring.annotation.chapter11.bean.ValueName。

```java
@Component
public class ValueName {
    private String name;
    public ValueName() {
        this.name = "binghe";
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
}
```

可以看到，ValueName类上标注了@Component注解，说明当Spring的IOC容器启动时，会向IOC容器中注入ValueName类的Bean对象。

**（3）新增ValueConfig类**

ValueConfig类的源码详见：spring-annotation-chapter-11工程下的io.binghe.spring.annotation.chapter11.config.ValueConfig。

```java
@Configuration
@ComponentScan(value = {"io.binghe.spring.annotation.chapter11"})
@PropertySource(value = {"classpath:test.properties"})
public class ValueConfig {
    /**
     * 注入普通字符串
     */
    @Value("normalString")
    private String normalString;
    /**
     * 注入操作系统名称
     */
    @Value("#{systemProperties['os.name']}")
    private String osName;
    /**
     * 注入表达式的结果
     */
    @Value("#{ T(java.lang.Math).random() * 100.0 }")
    private double randomNum;
    /**
     * 注入其他Bean的属性
     */
    @Value("#{valueName.name}")
    private String name;
    /**
     * 注入配置文件中的值
     */
    @Value("${db.url}")
    private String dbUrl;
    @Override
    public String toString() {
        return "ValueConfig{" +
                "normalString='" + normalString + '\'' +
                ", osName='" + osName + '\'' +
                ", randomNum=" + randomNum +
                ", name='" + name + '\'' +
                ", dbUrl='" + dbUrl + '\'' +
                '}';
    }
}
```

可以看到，在ValueConfig类上标注了@Configuration注解，说明ValueConfig类是Spring的配置类。使用@ComponentScan注解指定了扫描的包名是io.binghe.spring.annotation.chapter11。并且使用@PropertySource注解导入了test.properties配置文件。ValueConfig类的字段通过@Value注解注入对应的属性值，代码中有详细的注释，这里不再赘述。

**（4）新增ValueTest类**

ValueTest类的源码详见：spring-annotation-chapter-11工程下的io.binghe.spring.annotation.chapter11.ValueTest。

```java
public class ValueTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ValueConfig.class);
        ValueConfig valueConfig = context.getBean(ValueConfig.class);
        System.out.println(valueConfig.toString());
    }
}
```

可以看到，ValueTest类是案例程序的测试类，实现的代码比较简单，这里不再赘述。

**（5）运行ValueTest类**

运行ValueTest类的main()方法，输出的结果信息如下所示。

```bash
ValueConfig{normalString='normalString', osName='Windows 10', randomNum=60.704013358598715, name='binghe', dbUrl='jdbc:mysql://localhost:3306/test'}
```

可以看到，在ValueTest类中的各个字段值都输出了正确的结果数据。

**说明：使用@Value注解向Bean的属性中正确设置了值。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本节，就以源码时序图的方式，直观的感受下@Value注解在Spring源码层面的执行流程。本节，会从解析并获取 @Value 修饰的属性、为 @Value 修饰属性赋值和使用@Value获取属性值三个方面分析源码时序图。

**注意：本节以单例Bean为例分析源码时序图，并且基于@Value注解标注到类的字段上的源码时序图为例进行分析，@Value注解标注到类的方法上的源码时序图与标注到字段上的源码时序图基本相同，不再赘述。**

### 4.1 解析并获取@Value修饰的属性

本节，就简单介绍下解析并获取@Value修饰的属性的源码时序图，整体如图11-1~11-2所示。

![图11-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-001.png)



![图11-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-002.png)

由图11-1~11-2可以看出，解析并获取@Value修饰的属性的流程中涉及到ValueTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类、AbstractBeanFactory类、AbstractAutowireCapableBeanFactory类和AutowiredAnnotationBeanPostProcessor类。具体的源码执行细节参见源码解析部分。 

### 4.2 为@Value修饰的属性赋值

本节，就简单介绍下为@Value修饰的属性赋值的源码时序图，整体如图11-3~11-4所示。

![图11-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-003.png)



![图11-4](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-004.png)

由图11-3~11-4所示，为@Value修饰的属性赋值流程涉及到ValueTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类、AbstractBeanFactory类、AbstractAutowireCapableBeanFactory类、AutowiredAnnotationBeanPostProcessor类、InjectionMetadata类和AutowiredFieldElement类。具体的源码执行细节参见源码解析部分。 

### 4.3 使用@Value获取属性的值

本节，就简单介绍下使用@Value注解获取属性的值的源码时序图，整体如图11-5~11-7所示。

![图11-5](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-005.png)



![图11-6](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-006.png)



![图11-7](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-007.png)

由图11-5~11-7所示，使用@Value获取属性的值的流程涉及到ValueTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类、AbstractBeanFactory类、AbstractAutowireCapableBeanFactory类、AutowiredAnnotationBeanPostProcessor类、InjectionMetadata类、AutowiredFieldElement类、AbstractEnvironment类、AbstractPropertyResolver类、PropertyPlaceholderHelper类和PropertySourcesPropertyResolver类。具体的源码执行细节参见源码解析部分。 

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

本节，主要分析@Value注解在Spring源码层面的执行流程，同样的，本节也会从解析并获取 @Value 修饰的属性、为 @Value 修饰属性赋值和使用@Value获取属性值三个方面分析源码执行流程，并且结合源码执行的时序图，会理解的更加深刻。

**注意：本节以单例Bean为例分析，并且基于@Value注解标注到类的字段上的源码流程为例进行分析，@Value注解标注到类的方法上的源码流程与标注到字段上的源码流程基本相同，不再赘述。**

### 5.1 解析并获取@Value修饰的属性

本节主要对解析并获取 @Value 修饰属性的源码流程进行简单的分析，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图11-1~11-2进行理解。具体分析步骤如下所示。

**注意：解析并获取 @Value 修饰属性源码流程的前半部分与第7章5.3节分析源码的流程相同，这里，从AbstractBeanFactory类的doGetBean()方法开始分析。**

（1）解析AbstractBeanFactory类的doGetBean(String name, Class<T> requiredType, Object[] args, boolean typeCheckOnly)方法

源码详见：org.springframework.beans.factory.support.AbstractBeanFactory#doGetBean(String name, Class<T> requiredType, Object[] args, boolean typeCheckOnly)。重点关注如下代码片段。

```java
protected <T> T doGetBean( String name, @Nullable Class<T> requiredType, @Nullable Object[] args, boolean typeCheckOnly) throws BeansException {
	/***********省略其他代码***********/
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
	/***********省略其他代码***********/
    return adaptBeanInstance(name, beanInstance, requiredType);
}
```

可以看到，在AbstractBeanFactory类的doGetBean()方法中，如果是单例Bean，会调用getSingleton()方法创建单例Bean，实际执行的是Lambda表达式中的createBean()方法来创建单例Bean。

（2）解析AbstractAutowireCapableBeanFactory类的createBean(String beanName, RootBeanDefinition mbd, Object[] args)。

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#createBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)。

```java
@Override
protected Object createBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)
    throws BeanCreationException {	
	/**************省略其他代码***************/
    try {
        Object beanInstance = doCreateBean(beanName, mbdToUse, args);
        if (logger.isTraceEnabled()) {
            logger.trace("Finished creating instance of bean '" + beanName + "'");
        }
        return beanInstance;
    }
    catch (BeanCreationException | ImplicitlyAppearedSingletonException ex) {
        throw ex;
    }
    catch (Throwable ex) {
        throw new BeanCreationException(
            mbdToUse.getResourceDescription(), beanName, "Unexpected exception during bean creation", ex);
    }
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的createBean()方法中，会调用doCreateBean()方法创建Bean对象。

（3）解析AbstractAutowireCapableBeanFactory类的doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)。此时重点关注创建Bean实例的代码片段，如下所示。

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
    /***********省略其他代码**********/
    return exposedObject;
}
```

（4）解析AbstractAutowireCapableBeanFactory类的(String beanName, RootBeanDefinition mbd, Object[] args)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#createBeanInstance(String beanName, RootBeanDefinition mbd, Object[] args)。

```java
protected BeanWrapper createBeanInstance(String beanName, RootBeanDefinition mbd, @Nullable Object[] args) {
    // Make sure bean class is actually resolved at this point.
    Class<?> beanClass = resolveBeanClass(mbd, beanName);
    if (beanClass != null && !Modifier.isPublic(beanClass.getModifiers()) && !mbd.isNonPublicAccessAllowed()) {
        throw new BeanCreationException(mbd.getResourceDescription(), beanName, "Bean class isn't public, and non-public access not allowed: " + beanClass.getName());
    }

    Supplier<?> instanceSupplier = mbd.getInstanceSupplier();
    if (instanceSupplier != null) {
        return obtainFromSupplier(instanceSupplier, beanName);
    }

    if (mbd.getFactoryMethodName() != null) {
        return instantiateUsingFactoryMethod(beanName, mbd, args);
    }
    boolean resolved = false;
    boolean autowireNecessary = false;
    if (args == null) {
        synchronized (mbd.constructorArgumentLock) {
            if (mbd.resolvedConstructorOrFactoryMethod != null) {
                resolved = true;
                autowireNecessary = mbd.constructorArgumentsResolved;
            }
        }
    }
    if (resolved) {
        if (autowireNecessary) {
            return autowireConstructor(beanName, mbd, null, null);
        }
        else {
            return instantiateBean(beanName, mbd);
        }
    }
    Constructor<?>[] ctors = determineConstructorsFromBeanPostProcessors(beanClass, beanName);
    if (ctors != null || mbd.getResolvedAutowireMode() == AUTOWIRE_CONSTRUCTOR ||
        mbd.hasConstructorArgumentValues() || !ObjectUtils.isEmpty(args)) {
        return autowireConstructor(beanName, mbd, ctors, args);
    }
    ctors = mbd.getPreferredConstructors();
    if (ctors != null) {
        return autowireConstructor(beanName, mbd, ctors, null);
    }
    return instantiateBean(beanName, mbd);
}
```

可以看到，createBeanInstance()方法会创建Bean的实例并返回BeanWrapper对象。

（5）返回AbstractAutowireCapableBeanFactory类的doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)方法，此时，重点关注如下代码片段。

```java
protected Object doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args) throws BeanCreationException {
	/*************省略其他代码***************/
    synchronized (mbd.postProcessingLock) {
        if (!mbd.postProcessed) {
            try {
                applyMergedBeanDefinitionPostProcessors(mbd, beanType, beanName);
            }
            catch (Throwable ex) {
                throw new BeanCreationException(mbd.getResourceDescription(), beanName, "Post-processing of merged bean definition failed", ex);
            }
            mbd.markAsPostProcessed();
        }
    }
	/*************省略其他代码***************/
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的doCreateBean()方法中会调用applyMergedBeanDefinitionPostProcessors()方法的主要作用就是：获取@Value、@Autowired、@PostConstruct、@PreDestroy等注解标注的字段和方法，然后封装到InjectionMetadata对象中，最后将所有的InjectionMetadata对象存入injectionMeatadataCache缓存中。

（6）解析AbstractAutowireCapableBeanFactory类的applyMergedBeanDefinitionPostProcessors(RootBeanDefinition mbd, Class<?> beanType, String beanName)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#applyMergedBeanDefinitionPostProcessors(RootBeanDefinition mbd, Class<?> beanType, String beanName)。

```java
protected void applyMergedBeanDefinitionPostProcessors(RootBeanDefinition mbd, Class<?> beanType, String beanName) {
    for (MergedBeanDefinitionPostProcessor processor : getBeanPostProcessorCache().mergedDefinition) {
        processor.postProcessMergedBeanDefinition(mbd, beanType, beanName);
    }
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的applyMergedBeanDefinitionPostProcessors()方法中，会调用processor的postProcessMergedBeanDefinition()方法处理BeanDefinition信息。

（7）解析AutowiredAnnotationBeanPostProcessor类postProcessMergedBeanDefinition(RootBeanDefinition beanDefinition, Class<?> beanType, String beanName)。

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor#postProcessMergedBeanDefinition(RootBeanDefinition beanDefinition, Class<?> beanType, String beanName)

```java
@Override
public void postProcessMergedBeanDefinition(RootBeanDefinition beanDefinition, Class<?> beanType, String beanName) {
    findInjectionMetadata(beanName, beanType, beanDefinition);
}
```

可以看到，在AutowiredAnnotationBeanPostProcessor类postProcessMergedBeanDefinition()方法中会调用findInjectionMetadata()方法来获取标注了注解的字段或者方法。

（8）解析AutowiredAnnotationBeanPostProcessor类的findInjectionMetadata(String beanName, Class<?> beanType, RootBeanDefinition beanDefinition)

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor#findInjectionMetadata(String beanName, Class<?> beanType, RootBeanDefinition beanDefinition)。

```java
private InjectionMetadata findInjectionMetadata(String beanName, Class<?> beanType, RootBeanDefinition beanDefinition) {
    InjectionMetadata metadata = findAutowiringMetadata(beanName, beanType, null);
    metadata.checkConfigMembers(beanDefinition);
    return metadata;
}
```

可以看到，在AutowiredAnnotationBeanPostProcessor类的findInjectionMetadata()方法中，调用了findAutowiringMetadata方法来解析并获取@Value、@Autowired、@Inject等注解修饰的属性或者方法。

（9）解析AutowiredAnnotationBeanPostProcessor类的findAutowiringMetadata(String beanName, Class<?> clazz, PropertyValues pvs)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor#findAutowiringMetadata(String beanName, Class<?> clazz, PropertyValues pvs)。

```java
private InjectionMetadata findAutowiringMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs) {
    String cacheKey = (StringUtils.hasLength(beanName) ? beanName : clazz.getName());
    InjectionMetadata metadata = this.injectionMetadataCache.get(cacheKey);
    if (InjectionMetadata.needsRefresh(metadata, clazz)) {
        synchronized (this.injectionMetadataCache) {
            metadata = this.injectionMetadataCache.get(cacheKey);
            if (InjectionMetadata.needsRefresh(metadata, clazz)) {
                if (metadata != null) {
                    metadata.clear(pvs);
                }
                metadata = buildAutowiringMetadata(clazz);
                this.injectionMetadataCache.put(cacheKey, metadata);
            }
        }
    }
    return metadata;
}
```

AutowiredAnnotationBeanPostProcessor类的findAutowiringMetadata()方法需要重点关注下，findAutowiringMetadata()方法最核心的功能就是对传递进来的每个类进行筛选判断是否被@Value、@Autowired、@Inject注解修饰的方法或者属性，如果是被 @Value、@Autowired、@Inject注解修饰的方法或者属性，就会将这个类记录下来，存入injectionMetadataCache缓存中，为后续的 DI 依赖注作准备。

首次调用findAutowiringMetadata()方法时，会调用buildAutowiringMetadata()方法来查找使用@Value、@Autowired、@Inject注解修饰的方法或者属性。

（10）解析AutowiredAnnotationBeanPostProcessor类的buildAutowiringMetadata(Class<?> clazz)方法。

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor#buildAutowiringMetadata(Class<?> clazz)。方法中会查找@Value、@Autowired、@Inject注解修饰的方法或者属性，这里以查找属性为例，重点关注如下代码片段。

```java
private InjectionMetadata buildAutowiringMetadata(Class<?> clazz) {
    if (!AnnotationUtils.isCandidateClass(clazz, this.autowiredAnnotationTypes)) {
        return InjectionMetadata.EMPTY;
    }

    List<InjectionMetadata.InjectedElement> elements = new ArrayList<>();
    Class<?> targetClass = clazz;

    do {
        final List<InjectionMetadata.InjectedElement> currElements = new ArrayList<>();

        ReflectionUtils.doWithLocalFields(targetClass, field -> {
            MergedAnnotation<?> ann = findAutowiredAnnotation(field);
            if (ann != null) {
                if (Modifier.isStatic(field.getModifiers())) {
                    if (logger.isInfoEnabled()) {
                        logger.info("Autowired annotation is not supported on static fields: " + field);
                    }
                    return;
                }
                boolean required = determineRequiredStatus(ann);
                currElements.add(new AutowiredFieldElement(field, required));
            }
        });
		/**************省略其他代码****************/
        elements.addAll(0, currElements);
        targetClass = targetClass.getSuperclass();
    }
    while (targetClass != null && targetClass != Object.class);
    return InjectionMetadata.forElements(elements, clazz);
}
```

可以看到，在AutowiredAnnotationBeanPostProcessor类的buildAutowiringMetadata()方法中，获取到类上所有的字段，然后遍历每个字段，判断是否标注了 @Value、@Autowired和@Inject注解，如果标注了 @Value、@Autowired和@Inject注解，直接封装成 AutowiredFieldElement 对象，然后保存到一个名为 currElements集合中。

**指的一提的是，如果解析到的字段是静态字段，则直接返回，这就是为什么Spring不会对类中的静态字段赋值的原因。如下代码片段所示。**

```java
if (Modifier.isStatic(field.getModifiers())) {
    if (logger.isInfoEnabled()) {
        logger.info("Autowired annotation is not supported on static fields: " + field);
    }
    return;
}
```

在AutowiredAnnotationBeanPostProcessor类的buildAutowiringMetadata()方法的最后，则将标注了@Value、@Autowired和@Inject注解的字段封装到 InjectionMetadata 对象中，如下所示。

```java
return InjectionMetadata.forElements(elements, clazz);
```

最终回到AutowiredAnnotationBeanPostProcessor类的findAutowiringMetadata()方法中，将InjectionMetadata 对象存入injectionMetadataCache缓存中。如下所示。

```java
metadata = buildAutowiringMetadata(clazz);
this.injectionMetadataCache.put(cacheKey, metadata);
```

另外，在AutowiredAnnotationBeanPostProcessor类的buildAutowiringMetadata()方法中，调用了findAutowiredAnnotation()方法来获取注解信息，如下所示。

```java
MergedAnnotation<?> ann = findAutowiredAnnotation(field);
```

接下来，看看这个findAutowiredAnnotation()方法。

（11）解析AutowiredAnnotationBeanPostProcessor类的findAutowiredAnnotation(AccessibleObject ao)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor#findAutowiredAnnotation(AccessibleObject ao)。

```java
private MergedAnnotation<?> findAutowiredAnnotation(AccessibleObject ao) {
    MergedAnnotations annotations = MergedAnnotations.from(ao);
    for (Class<? extends Annotation> type : this.autowiredAnnotationTypes) {
        MergedAnnotation<?> annotation = annotations.get(type);
        if (annotation.isPresent()) {
            return annotation;
        }
    }
    return null;
}
```

可以看到，在AutowiredAnnotationBeanPostProcessor类的findAutowiredAnnotation()方法中，会遍历autowiredAnnotationTypes集合，通过遍历出的每个autowiredAnnotationTypes集合中的元素从annotations中获取MergedAnnotation对象annotation，如果annotation存在，则返回annotation。否则返回null。

这里，需要关注下autowiredAnnotationTypes集合，在AutowiredAnnotationBeanPostProcessor类的构造方法中向autowiredAnnotationTypes集合中添加元素，如下所示。

```java
public AutowiredAnnotationBeanPostProcessor() {
    this.autowiredAnnotationTypes.add(Autowired.class);
    this.autowiredAnnotationTypes.add(Value.class);

    try {
        this.autowiredAnnotationTypes.add((Class<? extends Annotation>) ClassUtils.forName("jakarta.inject.Inject", AutowiredAnnotationBeanPostProcessor.class.getClassLoader()));
        logger.trace("'jakarta.inject.Inject' annotation found and supported for autowiring");
    }
    catch (ClassNotFoundException ex) {
        // jakarta.inject API not available - simply skip.
    }

    try {
        this.autowiredAnnotationTypes.add((Class<? extends Annotation>) ClassUtils.forName("javax.inject.Inject", AutowiredAnnotationBeanPostProcessor.class.getClassLoader()));
        logger.trace("'javax.inject.Inject' annotation found and supported for autowiring");
    }
    catch (ClassNotFoundException ex) {
        // javax.inject API not available - simply skip.
    }
}
```

可以看到，在AutowiredAnnotationBeanPostProcessor类的构造方法中，向autowiredAnnotationTypes集合中添加了@Autowired注解、@Value注解和@Inject注解。所以，@Autowired注解赋值的流程和@Value注解赋值的流程基本一致。

至此，解析并获取@Value注解修饰的属性的源码流程分析完毕。

### 5.2 为@Value修饰的属性赋值

本节主要对为@Value修饰的属性赋值的源码流程进行简单的分析，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图11-3~11-4进行理解。具体分析步骤如下所示。

**注意：为@Value修饰的属性赋值的源码流程的前半部分与本章5.1节分析源码的流程相同，这里，同样从AbstractAutowireCapableBeanFactory类的doCreateBean()方法开始分析。**

（1）解析AbstractAutowireCapableBeanFactory类的doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)。重点关注如下代码片段。

```java
protected Object doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)
    throws BeanCreationException {
	/************省略其他代码*************/
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
	/************省略其他代码*************/
    return exposedObject;
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的doCreateBean()方法中，会调用populateBean方法为Bean的属性赋值。

（2）解析AbstractAutowireCapableBeanFactory类的populateBean(String beanName, RootBeanDefinition mbd, @Nullable BeanWrapper bw)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#populateBean(String beanName, RootBeanDefinition mbd, @Nullable BeanWrapper bw)。

```java
protected void populateBean(String beanName, RootBeanDefinition mbd, @Nullable BeanWrapper bw) {
    /**************省略其他代码*************/
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
    /**************省略其他代码*************/
}
```

可以看到，在populateBean()方法中，会调用InstantiationAwareBeanPostProcessor类的postProcessProperties()方法来处理属性或方法的值。实际上是调用的AutowiredAnnotationBeanPostProcessor类的postProcessProperties()方法。

（3）解析AutowiredAnnotationBeanPostProcessor类的postProcessProperties(PropertyValues pvs, Object bean, String beanName)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor#postProcessProperties(PropertyValues pvs, Object bean, String beanName)。

```java
@Override
public PropertyValues postProcessProperties(PropertyValues pvs, Object bean, String beanName) {
    InjectionMetadata metadata = findAutowiringMetadata(beanName, bean.getClass(), pvs);
    try {
        metadata.inject(bean, beanName, pvs);
    }
    catch (BeanCreationException ex) {
        throw ex;
    }
    catch (Throwable ex) {
        throw new BeanCreationException(beanName, "Injection of autowired dependencies failed", ex);
    }
    return pvs;
}
```

可以看到，在AutowiredAnnotationBeanPostProcessor类的postProcessProperties()方法中，会调用findAutowiringMetadata()方法获取注解的元数据信息。

（4）解析AutowiredAnnotationBeanPostProcessor类的findAutowiringMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor#findAutowiringMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs)。

```java
private InjectionMetadata findAutowiringMetadata(String beanName, Class<?> clazz, @Nullable PropertyValues pvs) {
    String cacheKey = (StringUtils.hasLength(beanName) ? beanName : clazz.getName());
    InjectionMetadata metadata = this.injectionMetadataCache.get(cacheKey);
    if (InjectionMetadata.needsRefresh(metadata, clazz)) {
        synchronized (this.injectionMetadataCache) {
            metadata = this.injectionMetadataCache.get(cacheKey);
            if (InjectionMetadata.needsRefresh(metadata, clazz)) {
                if (metadata != null) {
                    metadata.clear(pvs);
                }
                metadata = buildAutowiringMetadata(clazz);
                this.injectionMetadataCache.put(cacheKey, metadata);
            }
        }
    }
    return metadata;
}
```

由于在之前解析并获取@Value修饰的属性的代码流程中，已经完成了对@Value 修饰的属性的获取工作。所以，程序执行到findAutowiringMetadata()方法内部时，injectionMetadataCache缓存中已经有数据了。

（5）返回AutowiredAnnotationBeanPostProcessor类的postProcessProperties(PropertyValues pvs, Object bean, String beanName)方法。在AutowiredAnnotationBeanPostProcessor类的postProcessProperties()方法中，调用了metadata对象的inject()方法为属性赋值。

（6）解析InjectionMetadata类的inject(Object target, @Nullable String beanName, @Nullable PropertyValues pvs)方法

源码详见：org.springframework.beans.factory.annotation.InjectionMetadata#inject(Object target, @Nullable String beanName, @Nullable PropertyValues pvs)。

```java
public void inject(Object target, @Nullable String beanName, @Nullable PropertyValues pvs) throws Throwable {
    Collection<InjectedElement> checkedElements = this.checkedElements;
    Collection<InjectedElement> elementsToIterate = (checkedElements != null ? checkedElements : this.injectedElements);
    if (!elementsToIterate.isEmpty()) {
        for (InjectedElement element : elementsToIterate) {
            element.inject(target, beanName, pvs);
        }
    }
}
```

可以看到，在InjectionMetadata类的inject()方法中，会循环遍历checkedElements集合，调用遍历出的每个InjectedElement对象的inject()方法为属性赋值。

**注意：调用InjectedElement对象的inject()方法时，实际上可能会调用AutowiredFieldElement类的inject()方法、AutowiredMethodElement类的inject()方法或者InjectedElement类的inject()方法。这里，以调用AutowiredFieldElement类的inject()方法为例进行说明。**

（7）解析AutowiredFieldElement类的inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.AutowiredFieldElement#inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs)。

```java
@Override
protected void inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs) throws Throwable {
    Field field = (Field) this.member;
    Object value;
    if (this.cached) {
        try {
            value = resolvedCachedArgument(beanName, this.cachedFieldValue);
        }
        catch (NoSuchBeanDefinitionException ex) {
            value = resolveFieldValue(field, bean, beanName);
        }
    }
    else {
        value = resolveFieldValue(field, bean, beanName);
    }
    if (value != null) {
        ReflectionUtils.makeAccessible(field);
        field.set(bean, value);
    }
}
```

可以看到，在AutowiredFieldElement类的inject()方法中，会调用resolveFieldValue()方法来获取对应的属性值，如下所示。

```java
value = resolveFieldValue(field, bean, beanName);
```

并通过反射向使用@Value注解标注的字段赋值，如下所示。

```java
 field.set(bean, value);
```

（8）返回AbstractAutowireCapableBeanFactory类的doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)方法。再来看下源码：

```java
protected Object doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)
    throws BeanCreationException {
	/************省略其他代码*************/
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
	/************省略其他代码*************/
    return exposedObject;
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的doCreateBean()方法中，为Bean的属性赋值后会调用initializeBean()方法对Bean进行初始化。

（9）解析AbstractAutowireCapableBeanFactory类的initializeBean(String beanName, Object bean, RootBeanDefinition mbd)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#initializeBean(String beanName, Object bean, RootBeanDefinition mbd)。

```java
protected Object initializeBean(String beanName, Object bean, @Nullable RootBeanDefinition mbd) {
    invokeAwareMethods(beanName, bean);
    Object wrappedBean = bean;
    if (mbd == null || !mbd.isSynthetic()) {
        wrappedBean = applyBeanPostProcessorsBeforeInitialization(wrappedBean, beanName);
    }
    try {
        invokeInitMethods(beanName, wrappedBean, mbd);
    }
    catch (Throwable ex) {
        throw new BeanCreationException(
            (mbd != null ? mbd.getResourceDescription() : null), beanName, ex.getMessage(), ex);
    }
    if (mbd == null || !mbd.isSynthetic()) {
        wrappedBean = applyBeanPostProcessorsAfterInitialization(wrappedBean, beanName);
    }
    return wrappedBean;
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的initializeBean()方法中，会调用applyBeanPostProcessorsBeforeInitialization()方法在初始化之前执行一些逻辑，然后调用invokeInitMethods()执行真正的初始化操作，执行完Bean的初始化，会调用applyBeanPostProcessorsAfterInitialization()方法执行初始化之后的一些逻辑。

至此，为@Value修饰的属性赋值的源码流程分析完毕。

### 5.3 使用@Value获取属性的值

本节主要对使用@Value获取属性的值的源码流程进行简单的分析，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图11-5~11-7进行理解。具体分析步骤如下所示。

**注意：使用@Value获取属性的值的源码流程的前半部分与本章5.2节分析源码的流程相同，这里，从AutowiredFieldElement类的inject()方法开始分析。**

（1）解析AutowiredFieldElement类的inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.AutowiredFieldElement#inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs)。

```java
@Override
protected void inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs) throws Throwable {
    Field field = (Field) this.member;
    Object value;
    if (this.cached) {
        try {
            value = resolvedCachedArgument(beanName, this.cachedFieldValue);
        }
        catch (NoSuchBeanDefinitionException ex) {
            // Unexpected removal of target bean for cached argument -> re-resolve
            value = resolveFieldValue(field, bean, beanName);
        }
    }
    else {
        value = resolveFieldValue(field, bean, beanName);
    }
    if (value != null) {
        ReflectionUtils.makeAccessible(field);
        field.set(bean, value);
    }
}
```

可以看到，在AutowiredFieldElement类的inject()方法中，会调用resolveFieldValue()方法处理获取属性的值。

（2）解析AutowiredFieldElement类的resolveFieldValue(Field field, Object bean, @Nullable String beanName)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.AutowiredFieldElement#resolveFieldValue(Field field, Object bean, @Nullable String beanName)。

```java
@Nullable
private Object resolveFieldValue(Field field, Object bean, @Nullable String beanName) {
    /*************省略其他代码************/
    Object value;
    try {
        value = beanFactory.resolveDependency(desc, beanName, autowiredBeanNames, typeConverter);
    }
    catch (BeansException ex) {
        throw new UnsatisfiedDependencyException(null, beanName, new InjectionPoint(field), ex);
    }
     /*************省略其他代码************/
    return value;
}
```

可以看到，在AutowiredFieldElement类的resolveFieldValue()方法中，会调用beanFactory对象的resolveDependency()方法，继续向下分析。

（3）解析DefaultListableBeanFactory类的resolveDependency(DependencyDescriptor descriptor, @Nullable String requestingBeanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#resolveDependency(DependencyDescriptor descriptor, @Nullable String requestingBeanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)。

```java
@Override
@Nullable
public Object resolveDependency(DependencyDescriptor descriptor, @Nullable String requestingBeanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter) throws BeansException {
    /***************省略其他代码**************/
    else {
        Object result = getAutowireCandidateResolver().getLazyResolutionProxyIfNecessary(descriptor, requestingBeanName);
        if (result == null) {
            result = doResolveDependency(descriptor, requestingBeanName, autowiredBeanNames, typeConverter);
        }
        return result;
    }
}
```

可以看到，在DefaultListableBeanFactory类的resolveDependency()方法中，会调用doResolveDependency()方法进一步处理。

（4）解析DefaultListableBeanFactory类的doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)。

```java
@Nullable
public Object doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter) throws BeansException {
	/************省略其他代码*************/
    Object value = getAutowireCandidateResolver().getSuggestedValue(descriptor);
    if (value != null) {
        if (value instanceof String strValue) {
            String resolvedValue = resolveEmbeddedValue(strValue);
            BeanDefinition bd = (beanName != null && containsBean(beanName) ?
                                 getMergedBeanDefinition(beanName) : null);
            value = evaluateBeanDefinitionString(resolvedValue, bd);
        }
        TypeConverter converter = (typeConverter != null ? typeConverter : getTypeConverter());
        try {
            return converter.convertIfNecessary(value, type, descriptor.getTypeDescriptor());
        }
        catch (UnsupportedOperationException ex) {
            // A custom TypeConverter which does not support TypeDescriptor resolution...
            return (descriptor.getField() != null ?
                    converter.convertIfNecessary(value, type, descriptor.getField()) :
                    converter.convertIfNecessary(value, type, descriptor.getMethodParameter()));
        }
    }
    /************省略其他代码*************/
}
```

可以看到，在DefaultListableBeanFactory类的doResolveDependency()方法中，如果当前获取到的数据是String类型，则调用resolveEmbeddedValue()方法进行处理。

（5）解析AbstractBeanFactory类的resolveEmbeddedValue(@Nullable String value)方法

源码详见：org.springframework.beans.factory.support.AbstractBeanFactory#resolveEmbeddedValue(@Nullable String value)。

```java
@Override
@Nullable
public String resolveEmbeddedValue(@Nullable String value) {
    if (value == null) {
        return null;
    }
    String result = value;
    for (StringValueResolver resolver : this.embeddedValueResolvers) {
        result = resolver.resolveStringValue(result);
        if (result == null) {
            return null;
        }
    }
    return result;
}
```

可以看到，在AbstractBeanFactory类的resolveEmbeddedValue()中，会调用遍历出来的StringValueResolver对象的resolveStringValue()方法进行处理。此时，会进入AbstractEnvironment类的resolvePlaceholders(String text)方法。

（6）解析AbstractEnvironment类的resolvePlaceholders(String text)方法

源码详见：org.springframework.core.env.AbstractEnvironment#resolvePlaceholders(String text)。

```java
@Override
public String resolvePlaceholders(String text) {
    return this.propertyResolver.resolvePlaceholders(text);
}
```

可以看到，在AbstractEnvironment类的resolvePlaceholders()方法中，会调用propertyResolver对象的resolvePlaceholders()方法进行处理。

（7）解析AbstractPropertyResolver类的resolvePlaceholders(String text)方法

源码详见：org.springframework.core.env.AbstractPropertyResolver#resolvePlaceholders(String text)。

```java
@Override
public String resolvePlaceholders(String text) {
    if (this.nonStrictHelper == null) {
        this.nonStrictHelper = createPlaceholderHelper(true);
    }
    return doResolvePlaceholders(text, this.nonStrictHelper);
}
```

可以看到，在AbstractPropertyResolver类的resolvePlaceholders()方法中，会调用doResolvePlaceholders()方法进一步处理。

（8）解析AbstractPropertyResolver类的doResolvePlaceholders(String text, PropertyPlaceholderHelper helper)方法

源码详见：org.springframework.core.env.AbstractPropertyResolver#doResolvePlaceholders(String text, PropertyPlaceholderHelper helper)。

```java
private String doResolvePlaceholders(String text, PropertyPlaceholderHelper helper) {
    return helper.replacePlaceholders(text, this::getPropertyAsRawString);
}
```

可以看到，在AbstractPropertyResolver类的doResolvePlaceholders()方法中，会解析 ${xxx.xxx} 这种占位，最终获取到 key = xxx.xxx，随后根据key去资源文件(xml、application.properties、Environment 等)中查找是否配置了这个key的值。其实是通过调用helper的replacePlaceholders()方法并以Lambda表达式的方式传入getPropertyAsRawString()方法实现的。

（9）解析PropertyPlaceholderHelper类的replacePlaceholders(String value, PlaceholderResolver placeholderResolver)方法

源码详见：org.springframework.util.PropertyPlaceholderHelper#replacePlaceholders(String value, PlaceholderResolver placeholderResolver)。

```java
public String replacePlaceholders(String value, PlaceholderResolver placeholderResolver) {
    Assert.notNull(value, "'value' must not be null");
    return parseStringValue(value, placeholderResolver, null);
}
```

可以看到，在PropertyPlaceholderHelper类的replacePlaceholders()方法中，会调用parseStringValue()方法解析String类型的数据。

（10）解析PropertyPlaceholderHelper类的parseStringValue(String value, PlaceholderResolver placeholderResolver, @Nullable Set<String> visitedPlaceholders)方法

源码详见：org.springframework.util.PropertyPlaceholderHelper#parseStringValue(String value, PlaceholderResolver placeholderResolver, @Nullable Set<String> visitedPlaceholders)。

```java
protected String parseStringValue(String value, PlaceholderResolver placeholderResolver, @Nullable Set<String> visitedPlaceholders) {
    /***************省略其他代码****************/
    // Now obtain the value for the fully resolved key...
    String propVal = placeholderResolver.resolvePlaceholder(placeholder);
    if (propVal == null && this.valueSeparator != null) {
        int separatorIndex = placeholder.indexOf(this.valueSeparator);
        if (separatorIndex != -1) {
            String actualPlaceholder = placeholder.substring(0, separatorIndex);
            String defaultValue = placeholder.substring(separatorIndex + this.valueSeparator.length());
            propVal = placeholderResolver.resolvePlaceholder(actualPlaceholder);
            if (propVal == null) {
                propVal = defaultValue;
            }
        }
    }
    /**********省略其他代码***********/
}
```

在PropertyPlaceholderHelper类的parseStringValue()方法中重点关注如下代码片段。

```java
String propVal = placeholderResolver.resolvePlaceholder(placeholder);
```

会调用placeholderResolver对象的resolvePlaceholder()方法传入解析 ${xxx.xxx} 占位符，获取到的key，其中key的形式为xxx.xxx。调用placeholderResolver对象的resolvePlaceholder()方法会最终调用PropertySourcesPropertyResolver类的getPropertyAsRawString()方法。

（11）解析PropertySourcesPropertyResolver类的getPropertyAsRawString(String key)方法

源码详见：org.springframework.core.env.PropertySourcesPropertyResolver#getPropertyAsRawString(String key)。

```java
@Override
@Nullable
protected String getPropertyAsRawString(String key) {
    return getProperty(key, String.class, false);
}
```

可以看到，在getPropertyAsRawString()方法中，会调用getProperty()方法获取属性的值。在调用getPropertyAsRawString()方法时，传入的Key的形式的规则就是：如果使用@Value标注的属性为 ${xxx.xxx} 占位符，则此处传入的Key的形式为xxx.xxx。

（12）解析PropertySourcesPropertyResolver类的getProperty(String key, Class<T> targetValueType, boolean resolveNestedPlaceholders)方法

源码详见：org.springframework.core.env.PropertySourcesPropertyResolver#getProperty(String key, Class<T> targetValueType, boolean resolveNestedPlaceholders)。

```java
@Nullable
protected <T> T getProperty(String key, Class<T> targetValueType, boolean resolveNestedPlaceholders) {
    if (this.propertySources != null) {
        for (PropertySource<?> propertySource : this.propertySources) {
            if (logger.isTraceEnabled()) {
                logger.trace("Searching for key '" + key + "' in PropertySource '" +
                             propertySource.getName() + "'");
            }
            Object value = propertySource.getProperty(key);
            if (value != null) {
                if (resolveNestedPlaceholders && value instanceof String string) {
                    value = resolveNestedPlaceholders(string);
                }
                logKeyFound(key, propertySource, value);
                return convertValueIfNecessary(value, targetValueType);
            }
        }
    }
    if (logger.isTraceEnabled()) {
        logger.trace("Could not find key '" + key + "' in any property source");
    }
    return null;
}
```

在PropertySourcesPropertyResolver类的getProperty()方法中，会从 propertySources 资源中获取 key = xxx.xxx 的值，如果获取到一个对应的值，就会直接返回。其中，在propertySources中会封装PropertiesPropertySource、SystemEnvironmentPropertySource和ResourcePropertySource类型的对象，如图11-8所示。

![图11-8](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-008.png)

其中，每种类型的对象中封装的信息如下所示。

* PropertiesPropertySource：封装 JVM 环境变量中的键值对。
* SystemEnvironmentPropertySource：封装操作系统环境变量中的键值对。
* ResourcePropertySource：封装项目中application.properties、yml和xml等文件中的键值对。

通过调试PropertySourcesPropertyResolver类的getProperty()方法，可以发现，ResourcePropertySource对象中获取到对应的值，如图11-9所示。

![图11-9](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-03-009.png)

从ResourcePropertySource对象中获取到对应的值就可以设置到被@Value注解标注的字段上。

至此，使用@Value获取属性的值的源码流程分析完毕。

## 六、总结

`@Value注解介绍完了，我们一起总结下吧！`

本章，详细介绍了@Value注解，首先介绍了@Value注解的源码和使用场景，并且对@Value注解的用法进行了简单的介绍。随后，介绍了@Value的使用案例。接下来，从解析并获取 @Value 修饰的属性、为 @Value 修饰属性赋值和使用@Value获取属性值三个方面分别详细介绍了@Value注解在Spring底层执行的源码时序图和源码流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Value注解，通常会有如下几个经典面试题：

* @Value注解的作用是什么？
* @Value注解有哪些使用场景？
* @Value向Bean的字段和方法注入值是如何实现的？
* @Value注解在Spring内部的执行流程？
* @Value注解在Spring源码中的执行流程与@Autowired注解有何区别？
* 你在平时工作中，会在哪些场景下使用@Value注解？
* 你从@Value注解的设计中得到了哪些启发？

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