---
layout: post
category: binghe-code-spring
title: 第17章：深度解析@Scope注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第17章：深度解析@Scope注解
lock: need
---

# 《Spring核心技术》第17章：深度解析@Scope注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-17](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-17)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Scope指定Bean对象作用范围的案例和流程，从源码级别彻底掌握@Scope注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
  * 实现单例Bean
  * 实现多例Bean
* 源码时序图
  * 注册Bean的流程
  * 调用Bean工厂后置处理器
  * 获取Bean的流程
* 源码解析
  * 注册Bean的流程
  * 调用Bean工厂后置处理器
  * 获取Bean的流程
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Scope注解，你真的彻底了解过吗？`

在使用Spring开发项目时，有时需要指定Bean的作用范围，此时我们又该怎么做呢？

## 二、注解说明

`关于@Scope注解的一点点说明~~`

@Scope注解是Spring中提供的一个能够指定Bean的作用范围的注解，通过@Scope注解可以指定创建的Bean是单例的，还是多例的，也可以使用@Scope注解指定Bean在Web中的作用域，还可以自定义作用域。

### 2.1 注解源码

@Scope注解的源码详见：org.springframework.context.annotation.Scope。

```java
/**
 * @author Mark Fisher
 * @author Chris Beams
 * @author Sam Brannen
 * @since 2.5
 * @see org.springframework.stereotype.Component
 * @see org.springframework.context.annotation.Bean
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Scope {
	@AliasFor("scopeName")
	String value() default "";
	/**
	 * @since 4.2
	 */
	@AliasFor("value")
	String scopeName() default "";
	ScopedProxyMode proxyMode() default ScopedProxyMode.DEFAULT;
}
```

从@Scope注解的源码可以看出，@Scope注解是从Spring2.5版本开始提供的注解，并且在@Scope注解中提供了三个属性，具体含义分别如下所示。

* value：表示作用范围，可以取如下值。
  * singleton：表示单例Bean，IOC容器在启动时，就会创建Bean对象。如果标注了@Lazy注解，IOC容器在启动时，就不会创建Bean对象，会在第一次从IOC容器中获取Bean对象时，创建Bean对象。后续每次从IOC容器中获取的都是同一个Bean对象，同时，IOC容器会接管单例Bean对象的生命周期。
  * prototype：表示多例Bean。IOC容器在启动时，不会创建Bean对象，每次从IOC容器中获取Bean对象时，都会创建一个新的Bean对象。并且@Lazy注解对多例Bean不起作用，同时，IOC容器不会接管多例Bean对象的生命周期
  * request：表示作用域是当前请求范围。
  * session：表示作用域是当前会话范围。
  * application：表示作用域是当前应用范围。
* scopeName：Spring4.2版本开始新增的属性，作用与value属性相同。
* proxyMode：指定Bean对象使用的代理方式，可以取如下值。
  * DEFAULT：默认值，作用与NO相同。
  * NO：不使用代理。
  * INTERFACES：使用JDK基于接口的代理。
  * TARGET_CLASS：使用CGLIB基于目标类的子类创建代理对象。

### 2.2 使用场景

大部分场景下，使用Spring的单例Bean就足够了，Spring默认的类型也是单例Bean。单例Bean能够保证在Spring中不会重复创建相同的Bean对象，对性能有所提高。但是，如果单例Bean中存在非静态成员变量，可能会产生线程安全问题。如果设置为多例Bean，则每次从IOC容器中获取Bean对象时，都会重新生成一个新的Bean对象，每次生成新的Bean对象多少都会影响程序的性能。

早期开发中使用比较多的Struts2框架中的Action，由于其模型驱动和OGNL表达式的原因，就必须将Spring中的Bean配置成多例Bean。

## 三、使用案例

`@Scope注解指定Bean作用范围的案例，我们一起实现吧~~`

本章，就基于@Scope注解实现指定Bean的作用范围的案例，总体上会从单例Bean和多例Bean两个作用范围进行说明。

**注意：本章的案例和源码解析都是基于@Scope注解标注到方法上，结合@Bean注解进行分析的。**

### 3.1 实现单例Bean

本节，主要基于@Scope注解实现单例Bean，具体实现步骤如下所示。

**（1）新增ScopeBean类**

ScopeBean类的源码详见：spring-annotation-chapter-17工程下的io.binghe.spring.annotation.chapter17.bean.ScopeBean。

```java
public class ScopeBean {
    public ScopeBean(){
        System.out.println("执行ScopeBean类的构造方法...");
    }
}
```

可以看到，ScopeBean类就是一个普通的Java类，并且在构造方法中打印了日志。

**（2）新增ScopeConfig类**

ScopeConfig类的源码详见：spring-annotation-chapter-17工程下的io.binghe.spring.annotation.chapter17.config.ScopeConfig。

```java
@Configuration
public class ScopeConfig {
    @Bean
    @Scope(value = "singleton")
    public ScopeBean scopeBean(){
        return new ScopeBean();
    }
}
```

可以看到，在ScopeConfig类上标注了@Configuration注解，说明ScopeConfig类是案例程序的配置类。在ScopeConfig类中的scopeBean()方法上使用@Bean注解向IOC容器中注入ScopeBean类的Bean对象。同时，在scopeBean()方法上，使用 @Scope注解指定了Bean的作用范围为singleton，也就是单例Bean。此处，由于Spring默认就是单例Bean，所以，也可以将@Scope注解省略。

**（3）新增ScopeTest类**

ScopeTest类的源码详见：spring-annotation-chapter-17工程下的io.binghe.spring.annotation.chapter17.ScopeTest。

```java
public class ScopeTest {
    public static void main(String[] args) {
        System.out.println("创建IOC容器开始...");
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ScopeConfig.class);
        System.out.println("创建IOC容器结束...");
        System.out.println("从IOC容器中第一次获取Bean对象开始...");
        ScopeBean scopeBean = context.getBean(ScopeBean.class);
        System.out.println(scopeBean);
        System.out.println("从IOC容器中第一次获取Bean对象结束...");
        System.out.println("从IOC容器中第二次获取Bean对象开始...");
        scopeBean = context.getBean(ScopeBean.class);
        System.out.println(scopeBean);
        System.out.println("从IOC容器中第二次获取Bean对象结束...");
    }
}
```

可以看到，在ScopeTest类中，首先创建了IOC容器，随后连续两次从IOC容器中获取ScopeBean类的Bean对象，并打印对应的日志信息。

**（4）运行ScopeTest类**

运行ScopeTest类的main()方法，输出的结果信息如下所示。

```bash
创建IOC容器开始...
执行ScopeBean类的构造方法...
创建IOC容器结束...
从IOC容器中第一次获取Bean对象开始...
io.binghe.spring.annotation.chapter17.bean.ScopeBean@11fc564b
从IOC容器中第一次获取Bean对象结束...
从IOC容器中第二次获取Bean对象开始...
io.binghe.spring.annotation.chapter17.bean.ScopeBean@11fc564b
从IOC容器中第二次获取Bean对象结束...
```

从输出的结果信息可以看出，Spring在IOC容器启动时就会创建单例Bean，随后每次从IOC容器中获取的都是同一个Bean对象。

### 3.2 实现多例Bean

本节实现多例Bean的步骤比较简单，就是在3.1节的基础上进行改造。具体步骤如下所示。

**（1）修改ScopeConfig类**

将ScopeConfig类中的scopeBean()方法上的@Scope注解的value属性值修改为prototype，如下所示。

```java
@Bean
@Scope(value = "prototype")
public ScopeBean scopeBean(){
    return new ScopeBean();
}
```

此时，就会在Spring中创建ScopeBean类型的多例Bean。

**（2）运行ScopeTest类**

运行ScopeTest类的main()方法，输出的结果信息如下所示。

```bash
创建IOC容器开始...
创建IOC容器结束...
从IOC容器中第一次获取Bean对象开始...
执行ScopeBean类的构造方法...
io.binghe.spring.annotation.chapter17.bean.ScopeBean@fa36558
从IOC容器中第一次获取Bean对象结束...
从IOC容器中第二次获取Bean对象开始...
执行ScopeBean类的构造方法...
io.binghe.spring.annotation.chapter17.bean.ScopeBean@672872e1
从IOC容器中第二次获取Bean对象结束...
```

从输出的结果信息可以看出，Spring在IOC容器启动时，并不会创建单例Bean，而是从IOC容器中获取Bean对象时，才会创建Bean对象，并且每次从IOC容器中获取Bean对象时，都会创建新的Bean对象。

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本章，会从注册Bean的流程、调用Bean工厂后置处理器和获取Bean的流程三个方面分析@Scope注解的源码时序图。

### 4.1 注册Bean的流程

@Scope注解涉及到的注册Bean流程的源码时序图如图17-1所示。

![图17-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-12-001.png)

由图17-1可以看出，@Scope注解涉及到的注册Bean流程会涉及到ScopeTest类、AnnotationConfigApplicationContext类、AnnotatedBeanDefinitionReader类、AnnotationScopeMetadataResolver类、BeanDefinitionReaderUtils类和DefaultListableBeanFactory类，具体的源码执行细节参见源码解析部分。 

### 4.2 调用Bean工厂后置处理器

@Scope注解涉及到的调用Bean工厂后置处理器的源码时序图如图17-2~17-3所示。

![图17-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-12-002.png)



![图17-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-12-003.png)

由图17-2~17-3可以看出，@Scope注解涉及到的调用Bean工厂后置处理器的源码时序图会涉及到ScopeTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、ConfigurationClassBeanDefinitionReader类和DefaultListableBeanFactory类，具体的源码执行细节参见源码解析部分。 

### 4.3 获取Bean的流程

由于之前都是以单例Bean的方式分析的创建Bean的流程，这里，我们换一种分析方式，以多例Bean为入口分析获取Bean的流程。@Scope注解涉及到的获取Bean的源码时序图如图17-4所示。

![图17-4](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-12-004.png)

由17-4可以看出，@Scope注解获取Bean的流程涉及到ScopeTest类、AbstractApplicationContext类、DefaultListableBeanFactory类、AbstractBeanFactory类和AbstractAutowireCapableBeanFactory类，具体的源码执行细节参见源码解析部分。 

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

本节，同样以注册Bean的流程、调用Bean工厂的后置处理器和获取Bean的流程三个方面解析源码的执行流程。

### 5.1 注册Bean的流程

@Scope注解在Spring源码层面注册Bean的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图17-1进行理解。

@Scope注解涉及到的注册Bean的源码流程与第7章5.1小节@DependsOn注解涉及到的注册Bean的源码流程大体相同，只是在解析AnnotatedBeanDefinitionReader类的doRegisterBean()方法时，略有不同。本小节，就从AnnotatedBeanDefinitionReader类的doRegisterBean()方法开始解析。

（1）解析AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)。重点关注如下代码片段。

```java
private <T> void doRegisterBean(Class<T> beanClass, @Nullable String name, @Nullable Class<? extends Annotation>[] qualifiers, @Nullable Supplier<T> supplier, @Nullable BeanDefinitionCustomizer[] customizers) {
	/**************省略其他代码*****************/
    ScopeMetadata scopeMetadata = this.scopeMetadataResolver.resolveScopeMetadata(abd);
    abd.setScope(scopeMetadata.getScopeName());
    String beanName = (name != null ? name : this.beanNameGenerator.generateBeanName(abd, this.registry));
	/**************省略其他代码*****************/
    BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(abd, beanName);
    definitionHolder = AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
    BeanDefinitionReaderUtils.registerBeanDefinition(definitionHolder, this.registry);
}
```

可以看到，在AnnotatedBeanDefinitionReader类的doRegisterBean()方法中，会调用scopeMetadataResolver对象的resolveScopeMetadata()方法来获取@Scope注解的元数据，并返回ScopeMetadata类的对象。

（2）解析AnnotationScopeMetadataResolver类的resolveScopeMetadata(BeanDefinition definition)方法

源码详见：org.springframework.context.annotation.AnnotationScopeMetadataResolver#resolveScopeMetadata(BeanDefinition definition)。

```java
@Override
public ScopeMetadata resolveScopeMetadata(BeanDefinition definition) {
    ScopeMetadata metadata = new ScopeMetadata();
    if (definition instanceof AnnotatedBeanDefinition annDef) {
        AnnotationAttributes attributes = AnnotationConfigUtils.attributesFor(annDef.getMetadata(), this.scopeAnnotationType);
        if (attributes != null) {
            metadata.setScopeName(attributes.getString("value"));
            ScopedProxyMode proxyMode = attributes.getEnum("proxyMode");
            if (proxyMode == ScopedProxyMode.DEFAULT) {
                proxyMode = this.defaultProxyMode;
            }
            metadata.setScopedProxyMode(proxyMode);
        }
    }
    return metadata;
}
```

可以看到，在AnnotationScopeMetadataResolver类的resolveScopeMetadata()方法中，会解析传入的BeanDefinition对象中的@Scope注解的信息，将解析出的@Scope注解的信息封装到ScopeMetadata对象中并返回。

（3）回到AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法

在调用AnnotationScopeMetadataResolver类的resolveScopeMetadata()方法获取到scopeMetadata对象后，会将scopeMetadata对象的scopeName属性赋值给abd对象的scope属性。也就是将Bean的作用范围标识赋值给了abd对象的scope属性。

随后的流程就与第7章5.1小节@DependsOn注解涉及到的注册Bean的源码流程相同，这里不再赘述。

至此，@Scope注解在Spring源码层面注册Bean的执行流程分析完毕。

### 5.2 调用Bean工厂后置处理器

@Scope注解在Spring源码层面调用Bean工厂后置处理器的流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图17-2~17-3进行理解。

@Scope注解在Spring源码层面调用Bean工厂后置处理器的流程与@Autowired注解在Spring源码层面调用Bean工厂后置处理器的流程基本相同，只是会多一些实现细节，本节重点介绍@Scope注解在Spring源码层面调用Bean工厂后置处理器的流程时，新增的实现细节。直接从ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForBeanMethod()方法开始解析。

解析ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForBeanMethod(BeanMethod beanMethod)方法

源码详见：org.springframework.context.annotation.ConfigurationClassBeanDefinitionReader#loadBeanDefinitionsForBeanMethod(BeanMethod beanMethod)。此时重点关注如下代码片段。

```java
private void loadBeanDefinitionsForBeanMethod(BeanMethod beanMethod) {
    /****************省略其他代码****************/
    ConfigurationClassBeanDefinition beanDef = new ConfigurationClassBeanDefinition(configClass, metadata, 
    /****************省略其他代码****************/
    // Consider scoping
    ScopedProxyMode proxyMode = ScopedProxyMode.NO;
    AnnotationAttributes attributes = AnnotationConfigUtils.attributesFor(metadata, Scope.class);
    if (attributes != null) {
        beanDef.setScope(attributes.getString("value"));
        proxyMode = attributes.getEnum("proxyMode");
        if (proxyMode == ScopedProxyMode.DEFAULT) {
            proxyMode = ScopedProxyMode.NO;
        }
    }
    // Replace the original bean definition with the target one, if necessary
    BeanDefinition beanDefToRegister = beanDef;
    if (proxyMode != ScopedProxyMode.NO) {
        BeanDefinitionHolder proxyDef = ScopedProxyCreator.createScopedProxy(
            new BeanDefinitionHolder(beanDef, beanName), this.registry,
            proxyMode == ScopedProxyMode.TARGET_CLASS);
        beanDefToRegister = new ConfigurationClassBeanDefinition((RootBeanDefinition) proxyDef.getBeanDefinition(), configClass, metadata, beanName);
    }

    if (logger.isTraceEnabled()) {
        logger.trace(String.format("Registering bean definition for @Bean method %s.%s()",
                                   configClass.getMetadata().getClassName(), beanName));
    }
    this.registry.registerBeanDefinition(beanName, beanDefToRegister);
}
```

可以看到，在ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForBeanMethod()方法中，会处理@Scope注解。具体的逻辑就是会通过AnnotationConfigUtils类的attributesFor()方法获取@Scope注解的属性信息，将其封装到AnnotationAttributes对象中并返回。

如果获取到的attributes不为空，就会解析@Scope注解的value和proxyMode属性，并将解析出来value值设置到beanDef的scope属性中。随后判断解析出来的@Scope注解的proxyMode属性的值如果等于ScopedProxyMode.DEFAULT，则将其赋值为ScopedProxyMode.NO。

随后将beanDef对象赋值给beanDefToRegister对象，判断proxyMode的值如果不等于ScopedProxyMode.NO，则创建beanDefToRegister的代理对象。最终会将beanDefToRegister注册到IOC容器中。

后续流程与@Autowired注解在Spring源码层面调用Bean工厂后置处理器的流程相同，这里不再赘述。

至此，@Scope注解在Spring源码层面调用Bean工厂后置处理器的流程分析完毕。

### 5.3 获取Bean的流程

@Scope注解在Spring源码层面获取Bean的流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图17-4进行理解。

（1）解析ScopeTest类的main()方法

源码详见：spring-annotation-chapter-17工程下的io.binghe.spring.annotation.chapter17.ScopeTest#main()。

```java
public static void main(String[] args) {
    System.out.println("创建IOC容器开始...");
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ScopeConfig.class);
    System.out.println("创建IOC容器结束...");
    System.out.println("从IOC容器中第一次获取Bean对象开始...");
    ScopeBean scopeBean = context.getBean(ScopeBean.class);
    System.out.println(scopeBean);
    System.out.println("从IOC容器中第一次获取Bean对象结束...");
    System.out.println("从IOC容器中第二次获取Bean对象开始...");
    scopeBean = context.getBean(ScopeBean.class);
    System.out.println(scopeBean);
    System.out.println("从IOC容器中第二次获取Bean对象结束...");
}
```

可以看到，在ScopeTest类的main()方法中，会调用context的getBean()方法获取Bean对象。

（2）解析AbstractApplicationContext类的getBean(Class<T> requiredType)方法

源码详见：org.springframework.context.support.AbstractApplicationContext#getBean(Class<T> requiredType)。

```java
@Override
public <T> T getBean(Class<T> requiredType) throws BeansException {
    assertBeanFactoryActive();
    return getBeanFactory().getBean(requiredType);
}
```

可以看到，在AbstractApplicationContext类的getBean(Class<T> requiredType)方法中，会调用beanFactory的getBean()方法获取Bean对象。

（3）解析DefaultListableBeanFactory类的getBean(Class<T> requiredType)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#getBean(Class<T> requiredType)。

```java
@Override
public <T> T getBean(Class<T> requiredType) throws BeansException {
    return getBean(requiredType, (Object[]) null);
}
```

可以看到，在DefaultListableBeanFactory类的getBean(Class<T> requiredType)方法中，会调用另一个重载的getBean()方法。

（4）解析DefaultListableBeanFactory类的getBean(Class<T> requiredType, @Nullable Object... args)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#getBean(Class<T> requiredType, @Nullable Object... args)。

```java
@Override
public <T> T getBean(Class<T> requiredType, @Nullable Object... args) throws BeansException {
    Assert.notNull(requiredType, "Required type must not be null");
    Object resolved = resolveBean(ResolvableType.forRawClass(requiredType), args, false);
    if (resolved == null) {
        throw new NoSuchBeanDefinitionException(requiredType);
    }
    return (T) resolved;
}
```

可以看到，在DefaultListableBeanFactory类的getBean()方法中，会调用resolveBean()方法获取Bean对象。

（5）解析DefaultListableBeanFactory类的resolveBean(ResolvableType requiredType, @Nullable Object[] args, boolean nonUniqueAsNull)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#resolveBean(ResolvableType requiredType, @Nullable Object[] args, boolean nonUniqueAsNull)。

```java
@Nullable
private <T> T resolveBean(ResolvableType requiredType, @Nullable Object[] args, boolean nonUniqueAsNull) {
    NamedBeanHolder<T> namedBean = resolveNamedBean(requiredType, args, nonUniqueAsNull);
    if (namedBean != null) {
        return namedBean.getBeanInstance();
    }
    /************省略其他代码************/
    return null;
}
```

可以看到，在DefaultListableBeanFactory类的resolveBean()方法中，会调用resolveNamedBean()方法获取封装Bean对象NamedBeanHolder对象。

（6）解析DefaultListableBeanFactory类的resolveNamedBean(ResolvableType requiredType, @Nullable Object[] args, boolean nonUniqueAsNull)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#resolveNamedBean(ResolvableType requiredType, @Nullable Object[] args, boolean nonUniqueAsNull)。

```java
@Nullable
private <T> NamedBeanHolder<T> resolveNamedBean(ResolvableType requiredType, @Nullable Object[] args, boolean nonUniqueAsNull) throws BeansException {
    Assert.notNull(requiredType, "Required type must not be null");
    String[] candidateNames = getBeanNamesForType(requiredType);
    /***********省略其他代码*************/
    if (candidateNames.length == 1) {
        return resolveNamedBean(candidateNames[0], requiredType, args);
    }
	/***********省略其他代码*************/
    return null;
}
```

由于在案例程序中的ScopeConfig类中，只提供了一个标注了@Bean注解的方法，所以，这里会进入`candidateNames.length == 1`的条件分支，会调用另一个重载的resolveNamedBean()方法。

（7）解析DefaultListableBeanFactory类的resolveNamedBean(String beanName, ResolvableType requiredType, @Nullable Object[] args)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#resolveNamedBean(String beanName, ResolvableType requiredType, @Nullable Object[] args)。

```java
@Nullable
private <T> NamedBeanHolder<T> resolveNamedBean(String beanName, ResolvableType requiredType, @Nullable Object[] args) throws BeansException {
    Object bean = getBean(beanName, null, args);
    if (bean instanceof NullBean) {
        return null;
    }
    return new NamedBeanHolder<>(beanName, adaptBeanInstance(beanName, bean, requiredType.toClass()));
}
```

可以看到，在DefaultListableBeanFactory类的resolveNamedBean()方法中，会调用getBean方法获取Bean对象。

（8）解析AbstractBeanFactory类的getBean(String name, @Nullable Class<T> requiredType, @Nullable Object... args)方法

源码详见：org.springframework.beans.factory.support.AbstractBeanFactory#getBean(String name, @Nullable Class<T> requiredType, @Nullable Object... args)。

```java
public <T> T getBean(String name, @Nullable Class<T> requiredType, @Nullable Object... args) throws BeansException {
    return doGetBean(name, requiredType, args, false);
}
```

可以看到，在AbstractBeanFactory类的getBean()方法中，会调用doGetBean()方法获取Bean对象。

（9）解析AbstractBeanFactory类的doGetBean(String name, @Nullable Class<T> requiredType, @Nullable Object[] args, boolean typeCheckOnly)方法

源码详见：org.springframework.beans.factory.support.AbstractBeanFactory#doGetBean(String name, @Nullable Class<T> requiredType, @Nullable Object[] args, boolean typeCheckOnly)。

由于AbstractBeanFactory类的doGetBean()方法的源码比较长，这里将源码拆分后进行分析。

首先，分析 if 分支的逻辑，如下所示。

```java
protected <T> T doGetBean(String name, @Nullable Class<T> requiredType, @Nullable Object[] args, boolean typeCheckOnly) throws BeansException {
    String beanName = transformedBeanName(name);
    Object beanInstance;
    Object sharedInstance = getSingleton(beanName);
    if (sharedInstance != null && args == null) {
        if (logger.isTraceEnabled()) {
            if (isSingletonCurrentlyInCreation(beanName)) {
                logger.trace("Returning eagerly cached instance of singleton bean '" + beanName + "' that is not fully initialized yet - a consequence of a circular reference");
            }
            else {
                logger.trace("Returning cached instance of singleton bean '" + beanName + "'");
            }
        }
        beanInstance = getObjectForBeanInstance(sharedInstance, name, beanName, null);
    }
    else {
        /**********省略其他代码************/
    }
    return adaptBeanInstance(name, beanInstance, requiredType);
}
```

在AbstractBeanFactory类的doGetBean()方法中，首先会通过getSingleton()方法从三级缓存中获取单例Bean对象，如果存在单例Bean对象，并且args参数为null，则调用getObjectForBeanInstance()根据给定的Bean实例来返回对象，最终通过adaptBeanInstance()方法来返回适配的Bean对象。

接下来，分析else分支。很显然，不管是单例Bean还是多例Bean，开始进入doGetBean()方法时，都会进入else分支。

```java
protected <T> T doGetBean(String name, @Nullable Class<T> requiredType, @Nullable Object[] args, boolean typeCheckOnly) throws BeansException {
    String beanName = transformedBeanName(name);
    Object beanInstance;
    Object sharedInstance = getSingleton(beanName);
    if (sharedInstance != null && args == null) {
        /**********省略其他代码**************/
    }
    else {
        /**********省略其他代码**************/
        try {
            /**********省略其他代码**************/
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
            /**********省略其他代码**************/
        }
        catch (BeansException ex) {
            /**********省略其他代码**************/
            throw ex;
        }
        finally {
            beanCreation.end();
        }
    }
    return adaptBeanInstance(name, beanInstance, requiredType);
}
```

可以看到，在AbstractBeanFactory类的doGetBean()方法的else分支中，不管是单例Bean还是多例Bean的执行逻辑，都会调用createBean()方法创建Bean对象，并且在多例Bean的情况下，每次都会创建一个新的Bean对象。

（10）解析AbstractAutowireCapableBeanFactory类的createBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#createBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)。重点关注如下代码。

```java
@Override
protected Object createBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args) throws BeanCreationException {
	/**********省略其他代码**************/
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
        throw new BeanCreationException(mbdToUse.getResourceDescription(), beanName, "Unexpected exception during bean creation", ex);
    }
}
```

可以看到，在AbstractAutowireCapableBeanFactory类的createBean()方法中，会调用doCreateBean()方法创建Bean对象。

（11）解析AbstractAutowireCapableBeanFactory类的doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)方法

源码详见：org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory#doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args)。

```java
protected Object doCreateBean(String beanName, RootBeanDefinition mbd, @Nullable Object[] args) throws BeanCreationException {
    // Instantiate the bean.
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

    // Allow post-processors to modify the merged bean definition.
    synchronized (mbd.postProcessingLock) {
        if (!mbd.postProcessed) {
            try {
                applyMergedBeanDefinitionPostProcessors(mbd, beanType, beanName);
            }
            catch (Throwable ex) {
                /*************省略其他代码*************/
            }
            mbd.markAsPostProcessed();
        }
    }
    boolean earlySingletonExposure = (mbd.isSingleton() && this.allowCircularReferences && isSingletonCurrentlyInCreation(beanName));
    if (earlySingletonExposure) {
        /*************省略其他代码*************/
        addSingletonFactory(beanName, () -> getEarlyBeanReference(beanName, mbd, bean));
    }

    // Initialize the bean instance.
    Object exposedObject = bean;
    try {
        populateBean(beanName, mbd, instanceWrapper);
        exposedObject = initializeBean(beanName, exposedObject, mbd);
    }
    catch (Throwable ex) {
       /*************省略其他代码*************/
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
                    /*************省略其他代码*************/
                }
            }
        }
    }
    // Register bean as disposable.
    try {
        registerDisposableBeanIfNecessary(beanName, bean, mbd);
    }
    catch (BeanDefinitionValidationException ex) {
        /*************省略其他代码*************/
    }
    return exposedObject;
}
```

可以看到，AbstractAutowireCapableBeanFactory类的doCreateBean()方法的代码比较长，这里我们主要分析下方法的主体逻辑。

1）判断如果mbd对象中标注的是单例Bean，则通过beanName移除factoryBeanInstanceCache缓存中的BeanWrapper对象，并将其赋值给instanceWrapper变量。

```java
if (mbd.isSingleton()) {
    instanceWrapper = this.factoryBeanInstanceCache.remove(beanName);
}
```

2）如果instanceWrapper变量为null，则直接调用createBeanInstance()方法创建Bean实例对象并将其封装到BeanWrapper对象中，赋值给instanceWrapper变量。

```java
if (instanceWrapper == null) {
    instanceWrapper = createBeanInstance(beanName, mbd, args);
}
```

3）从instanceWrapper变量中取出Bean实例赋值给bean变量，从instanceWrapper变量中取出Bean的Class对象赋值给beanType变量。

```java
Object bean = instanceWrapper.getWrappedInstance();
Class<?> beanType = instanceWrapper.getWrappedClass();
```

4）将bean变量的值赋值给exposedObject变量。

```java
Object exposedObject = bean;
```

5）为Bean对象的属性赋值，并初始化Bean对象。

```java
populateBean(beanName, mbd, instanceWrapper);
exposedObject = initializeBean(beanName, exposedObject, mbd);
```

6）如果是多例Bean，则调用registerDisposableBeanIfNecessary()方法向IOC容器中注入一个可任意处理的Bean后直接返回exposedObject。实际上，默认就是返回的调用createBeanInstance()方法新创建的bean对象。

```java
try {
    registerDisposableBeanIfNecessary(beanName, bean, mbd);
}
catch (BeanDefinitionValidationException ex) {
    throw new BeanCreationException(
        mbd.getResourceDescription(), beanName, "Invalid destruction signature", ex);
}
return exposedObject;
```

所以，Spring中的多例Bean，在每次从IOC容器中获取Bean对象时，都会新建一个Bean对象。

7）如果是单例Bean，则会调用getSingleton()方法获取单例Bean，如果获取的单例Bean不为空，并且exposedObject变量与bean变变量相等，说明在调用initializeBean()方法对Bean对象进行初始化时，并没有改变Bean对象的信息，此时，就会将调用getSingleton()方法获取到的单例Bean赋值给exposedObject。随后调用registerDisposableBeanIfNecessary()方法向IOC容器中注入一个可任意处理的Bean后直接返回exposedObject。

```java
if (earlySingletonExposure) {
    Object earlySingletonReference = getSingleton(beanName, false);
    if (earlySingletonReference != null) {
        if (exposedObject == bean) {
            exposedObject = earlySingletonReference;
        }
        /*************省略其他代码*************/
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
```

所以，如果是单例Bean，没有标注@Lazy注解时，在IOC容器启动的时候就会创建Bean对象。如果单例Bean标注了@Lazy注解，则会在第一次从IOC容器中获取Bean的时，创建Bean对象，随后，每次从IOC容器中获取Bean对象时，都会获取到相同的Bean对象。

至此，@Scope注解在Spring源码层面获取Bean的流程分析完毕。

## 六、总结

`@Scope注解介绍完了，我们一起总结下吧！`

本章，主要介绍了@Scope注解，首先介绍了注解的源码和使用场景。随后，从单例Bean和多例Bean两个方面给出了注解的使用案例。接下来，分别从注册Bean的流程、调用Bean的工厂后置处理器和获取Bean的流程三个方面分析了源码时序图和源码流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Scope注解，通常会有如下几个经典面试题：

* @Scope注解的作用是什么？
* @Scope注解有哪些使用场景？
* @Scope是如何指定Bean的作用范围的？
* @Scope注解在Spring内部的执行流程？
* @Scope是如何创建代理类的？流程是什么？
* 你在平时工作中，会在哪些场景下使用@Scope注解？
* 你从@Scope注解的设计中得到了哪些启发？

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

