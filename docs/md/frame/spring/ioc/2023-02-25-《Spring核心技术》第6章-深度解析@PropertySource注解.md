---
layout: post
category: binghe-code-spring
title: 第06章：深度解析@PropertySource注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第06章：深度解析@PropertySource注解
lock: need
---

# 《Spring核心技术》第6章：深度解析@PropertySource注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-06](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-06)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★☆☆

* **本章重点**：进一步学习并掌握@PropertySource注解加载配置文件的案例和流程，从源码级别彻底掌握@PropertySource注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 注解使用场景
* 使用案例
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`@PropertySource注解是用来干啥的呢？`

在日常开发中，你有没有遇到过这样一种场景：项目中需要编写很多配置文件，将一些系统信息配置化，此时，往往需要编写专门的工具类或者方法来读取并解析这些配置文件，将配置文件中的配置项内容加载到系统内存中。后续在使用这些配置项时，可以直接通过工具类或者方法获取加载到内存中的配置项。

没错，@PropertySource注解就是Spring中提供的一个可以加载配置文件的注解，并且可以将配置文件中的内容存放到Spring的环境变量中。

## 二、注解说明

`简单介绍下@PropertySource注解吧！`

@PropertySource注解是Spring中提供的一个通过指定配置文件位置来加载配置文件的注解，并且可以将配置文件中的内容存放到Spring的环境变量中。除了可以通过Spring的环境变量读取配置项之外，还可以通过@Value注解获取配置项的值。

另外，Spring中还提供了一个@PropertySources注解，在@PropertySources注解注解中，可以引入多个@PropertySource注解。

### 2.1 注解源码

Spring中提供了@PropertySource和@PropertySources两个注解来加载配置文件。

**1.@PropertySource注解**

@PropertySource注解只能标注到类上，能够通过指定配置文件的位置来加载配置文件，@PropertySource注解除了可以加载properties配置文件外，也可以加载xml配置文件和yml配置文件。如果加载yml配置文件时，可以自定义PropertySourceFactory实现yml配置文件的解析操作。

@PropertySource注解的源码详见：org.springframework.context.annotation.PropertySource。

```java
/**
 * @author Chris Beams
 * @author Juergen Hoeller
 * @author Phillip Webb
 * @author Sam Brannen
 * @since 3.1
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Repeatable(PropertySources.class)
public @interface PropertySource {
	String name() default "";
	String[] value();
	/**
	 * @since 4.0
	 */
	boolean ignoreResourceNotFound() default false;
	/**
	 * @since 4.3
	 */
	String encoding() default "";
	/**
	 * @since 4.3
	 */
	Class<? extends PropertySourceFactory> factory() default PropertySourceFactory.class;
}
```

从源码可以看出，@PropertySource注解是从Spring3.1版本开始提供的注解，注解中各个属性的含义如下所示。

* name：表示加载的资源的名称，如果为空，则会根据加载的配置文件自动生成一个名称。
* value：表示加载的资源的路径，这个路径可以是类路径，也可以是文件路径。
* ignoreResourceNotFound：表示当配置文件未找到时，是否忽略文件未找到的错误。默认值为false，也就是说当未找到配置文件时，Spring启动就会报错。
* encoding：表示解析配置文件使用的字符集编码。
* factory：表示读取对应配置文件的工厂类，默认的工厂类是PropertySourceFactory。

**2.@PropertySources注解**

除了@PropertySource注解，Spring中还提供了一个@PropertySources注解。@PropertySources注解中的源码详见：org.springframework.context.annotation.PropertySources。

```java
/**
 * @author Phillip Webb
 * @since 4.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PropertySources {
	PropertySource[] value();
}
```

从源码可以看出，@PropertySources是从Spring4.0版本开始提供的注解，在@PropertySources注解中，只提供了一个PropertySource数组类型的value属性。所以，@PropertySources注解可以引入多个@PropertySource注解。

### 2.2 注解使用场景

在基于Spring的注解开发项目的过程中，由于不再使用Spring的XML文件进行配置，如果将配置项直接写到类中，就会造成配置项与类的紧耦合，后续对于配置项的修改操作非常不方便，不利于项目的维护和扩展。此时，可以将这些配置项写到properties文件或者yml文件中，通过@PropertySource注解加载配置文件。

另外，如果项目本身就存在大量的properties配置文件或者yml配置文件，也可以统一由Spring的@PropertySource注解进行加载。

## 三、使用案例

`结合案例学着印象才会更深刻~~`

本节，主要实现一个通过@PropertySource注解加载properties配置文件，将properties配置文件中的配置项加载到Spring的环境变量中，获取Spring环境变量中配置项的值，并进行打印。案例的具体实现步骤如下所示。

**（1）新增test.properties文件**

在spring-annotation-chapter-06工程的resources目录下新增test.properties文件，文件内容如下所示。

```bash
name=binghe
age=18
```

**（2）新增PropertySourceConfig类**

PropertySourceConfig类的源码详见：spring-annotation-chapter-06工程下的io.binghe.spring.annotation.chapter06.config.PropertySourceConfig。

```java
@Configuration
@PropertySource(value = "classpath:test.properties")
public class PropertySourceConfig {
}
```

可以看到，PropertySourceConfig类是Spring的配置类，并且使用@PropertySource注解指定了test.properties配置文件的路径。

**（3）新增PropertySourceTest类**

PropertySourceTest类的源码详见：spring-annotation-chapter-06工程下的io.binghe.spring.annotation.chapter06.PropertySourceTest。

```java
public class PropertySourceTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(PropertySourceConfig.class);
        ConfigurableEnvironment environment = context.getEnvironment();
        System.out.println(environment.getProperty("name") + " ====>>> " + environment.getProperty("age"));
    }
}
```

可以看到，在PropertySourceTest类的main()方法中，通过AnnotationConfigApplicationContext类的对象获取到ConfigurableEnvironment类型的环境变量对象environment，然后通过environment对象获取配置文件中的name和age的值并进行打印。

**（4）运行PropertySourceTest类**

运行PropertySourceTest类的main()方法，输出的结果信息如下所示。

```bash
binghe ====>>> 18
```

可以看到，正确的输出了配置文件中的值。

**说明：使用@PropertySource注解可以加载properties配置文件中的配置项，并将配置项加载到Spring的环境变量中，通过Spring的环境变量就可以获取到配置项的值。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本节，就以源码时序图的方式，直观的感受下@PropertySource注解在Spring源码层面的执行流程。@PropertySource注解在Spring源码层面的执行流程如图6-1~6-2所示。

![图6-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-25-001.png)


![图6-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-02-25-002.png)

由图6-1~图6-2可以看出，@PropertySource注解在Spring源码层面的执行流程会涉及到PropertySourceTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、PropertySourceRegistry类、PropertySourceProcessor类和DefaultPropertySourceFactory类。具体的源码执行细节参见源码解析部分。

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

@PropertySource注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻。

（1）运行案例程序启动类

案例程序启动类源码详见：spring-annotation-chapter-06工程下的io.binghe.spring.annotation.chapter06.PropertySourceTest，运行PropertySourceTest类的main()方法。

在PropertySourceTest类的main()方法中调用了AnnotationConfigApplicationContext类的构造方法，并传入了PropertySourceConfig类的Class对象来创建IOC容器。接下来，会进入AnnotationConfigApplicationContext类的构造方法。

**注意：@PropertySource注解在Spring源码中的执行流程的（2）~（11）步与第5章的@Import注解相同，这里不再赘述，直接跳到ConfigurationClassParser类的doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)方法。**

（2）解析ConfigurationClassParser类的doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)方法

源码详见：org.springframework.context.annotation.ConfigurationClassParser#doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)，重点关注如下代码片段。

```java
protected final SourceClass doProcessConfigurationClass(
    ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter)
    throws IOException {
    //#############省略其他代码################
    for (AnnotationAttributes propertySource : AnnotationConfigUtils.attributesForRepeatable(
        sourceClass.getMetadata(), PropertySources.class,
        org.springframework.context.annotation.PropertySource.class)) {
        if (this.propertySourceRegistry != null) {
            this.propertySourceRegistry.processPropertySource(propertySource);
        }
    }
	//#############省略其他代码################
}
```

可以看到，在ConfigurationClassParser类的doProcessConfigurationClass()方法中，遍历获取到的@PropertySources注解和@PropertySource注解的属性，并且调用propertySourceRegistry对象的processPropertySource()方法解析注解属性的值。

（3）解析PropertySourceRegistry类的processPropertySource(AnnotationAttributes propertySource)方法

源码详见：org.springframework.context.annotation.PropertySourceRegistry#processPropertySource(AnnotationAttributes propertySource)。

```java
void processPropertySource(AnnotationAttributes propertySource) throws IOException {
    String name = propertySource.getString("name");
    if (!StringUtils.hasLength(name)) {
        name = null;
    }
    String encoding = propertySource.getString("encoding");
    if (!StringUtils.hasLength(encoding)) {
        encoding = null;
    }
    String[] locations = propertySource.getStringArray("value");
    Assert.isTrue(locations.length > 0, "At least one @PropertySource(value) location is required");
    boolean ignoreResourceNotFound = propertySource.getBoolean("ignoreResourceNotFound");
    Class<? extends PropertySourceFactory> factoryClass = propertySource.getClass("factory");
    Class<? extends PropertySourceFactory> factorClassToUse = (factoryClass != PropertySourceFactory.class ? factoryClass : null);
    PropertySourceDescriptor descriptor = new PropertySourceDescriptor(Arrays.asList(locations), ignoreResourceNotFound, name, factorClassToUse, encoding);
    this.propertySourceProcessor.processPropertySource(descriptor);
    this.descriptors.add(descriptor);
}
```

可以看到，在PropertySourceRegistry类的processPropertySource()方法中，解析@PropertySource注解中的属性后，将解析出的属性值封装到PropertySourceDescriptor对象中，调用propertySourceProcessor对象的processPropertySource()方法，并传入PropertySourceDescriptor对象进行进一步处理。

（4）解析PropertySourceProcessor类的processPropertySource(PropertySourceDescriptor descriptor)方法

源码详见：org.springframework.core.io.support.PropertySourceProcessor#processPropertySource(PropertySourceDescriptor descriptor)。

```java
public void processPropertySource(PropertySourceDescriptor descriptor) throws IOException {
    String name = descriptor.name();
    String encoding = descriptor.encoding();
    List<String> locations = descriptor.locations();
    Assert.isTrue(locations.size() > 0, "At least one @PropertySource(value) location is required");
    boolean ignoreResourceNotFound = descriptor.ignoreResourceNotFound();
    PropertySourceFactory factory = (descriptor.propertySourceFactory() != null ? instantiateClass(descriptor.propertySourceFactory()) : DEFAULT_PROPERTY_SOURCE_FACTORY);
    for (String location : locations) {
        try {
            String resolvedLocation = this.environment.resolveRequiredPlaceholders(location);
            Resource resource = this.resourceLoader.getResource(resolvedLocation);
            addPropertySource(factory.createPropertySource(name, new EncodedResource(resource, encoding)));
        }
        catch (IllegalArgumentException | FileNotFoundException | UnknownHostException | SocketException ex) {
			//#########省略其他代码################
        }
    }
}
```

可以看到，在processPropertySource()方法中，会通过@PropertySource注解的属性值解析出配置文件的内容，并且通过factory对象的createPropertySource()方法来创建PropertySource对象。

（5）解析DefaultPropertySourceFactory类的createPropertySource(String name, EncodedResource resource)方法

源码详见：org.springframework.core.io.support.DefaultPropertySourceFactory#createPropertySource(String name, EncodedResource resource)。

```java
@Override
public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
    return (name != null ? new ResourcePropertySource(name, resource) : new ResourcePropertySource(resource));
}
```

createPropertySource()方法的源码比较简单，不再赘述。

（6）回到PropertySourceProcessor类的processPropertySource(PropertySourceDescriptor descriptor)方法

在PropertySourceProcessor类的processPropertySource()方法中，创建完PropertySource对象后，会调用addPropertySource()方法将获取到的属性值添加到Spring的环境变量中。

（7）解析PropertySourceProcessor类的addPropertySource(PropertySource<?> propertySource)方法

源码详见：org.springframework.core.io.support.PropertySourceProcessor#addPropertySource(PropertySource<?> propertySource)。

```java
private void addPropertySource(org.springframework.core.env.PropertySource<?> propertySource) {
    String name = propertySource.getName();
    MutablePropertySources propertySources = this.environment.getPropertySources();
    if (this.propertySourceNames.contains(name)) {
        org.springframework.core.env.PropertySource<?> existing = propertySources.get(name);
        if (existing != null) {
            PropertySource<?> newSource = (propertySource instanceof ResourcePropertySource ?((ResourcePropertySource) propertySource).withResourceName() : propertySource);
            if (existing instanceof CompositePropertySource) {
                ((CompositePropertySource) existing).addFirstPropertySource(newSource);
            }
            else {
                if (existing instanceof ResourcePropertySource) {
                    existing = ((ResourcePropertySource) existing).withResourceName();
                }
                CompositePropertySource composite = new CompositePropertySource(name);
                composite.addPropertySource(newSource);
                composite.addPropertySource(existing);
                propertySources.replace(name, composite);
            }
            return;
        }
    }
    if (this.propertySourceNames.isEmpty()) {
        propertySources.addLast(propertySource);
    }
    else {
        String firstProcessed = this.propertySourceNames.get(this.propertySourceNames.size() - 1);
        propertySources.addBefore(firstProcessed, propertySource);
    }
    this.propertySourceNames.add(name);
}
```

可以看到，在PropertySourceProcessor类的addPropertySource()方法中，会将解析出的配置文件的内容添加到Spring的环境变量中。具体就是在PropertySourceProcessor类的addPropertySource()方法中，获取到ConfigurableEnvironment中的MutablePropertySources对象，用来存储解析出的配置文件中的配置项内容。如果有相同的配置项内容，将existing对象强转为CompositePropertySource类型，把新旧相同的配置项进行合并，再放到MutablePropertySources对象中。

后续就可以通过Spring的环境变量，来获取到配置文件中的配置项内容。

至此，@PropertySource注解在Spring源码中的执行流程分析完毕。

## 六、总结

`@PropertySource注解讲完了，我们一起总结下吧！`

本章，首先介绍了@PropertySource注解的源码和使用场景，随后，简单给出了一个@PropertySource注解的使用案例。接下来，详细分析了@PropertySource注解的源码时序图和@PropertySource注解在Spring源码层面的执行流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@PropertySource注解，通常会有如下几个经典面试题：

* @PropertySource注解的执行流程？
* @PropertySource注解是如何将配置文件加载到环境变量的？
* @PropertySource注解有哪些使用场景？
* Spring中为何会设计一个@PropertySource注解来加载配置文件？
* 从@PropertySource注解的设计中，你得到了哪些启发？

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