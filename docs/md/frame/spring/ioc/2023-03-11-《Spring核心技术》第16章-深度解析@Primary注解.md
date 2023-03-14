---
layout: post
category: binghe-code-spring
title: 第16章：深度解析@Primary注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第16章：深度解析@Primary注解
lock: need
---

# 《Spring核心技术》第16章：深度解析@Primary注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-16](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-16)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Primary注解指定Bean优先级的案例和流程，从源码级别彻底掌握@Primary注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
  * 注册Bean的流程
  * 调用Bean工厂后置处理器
  * 创建Bean的流程
* 源码解析
  * 注册Bean的流程
  * 调用Bean工厂后置处理器
  * 创建Bean的流程
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Primary注解，你真的彻底了解过吗？`

通过前面的文章，我们得知：使用@Autowired装配Bean对象时，如果存在多个类型相同的Bean时，可以使用@Qualifier注解明确指定装配哪个Bean。除了使用@Qualifier注解，也可以使用@Primary注解。

## 二、注解说明

`关于@Primary注解的一点点说明~~`

使用@Autowired装配Bean对象时，如果存在多个类型相同的Bean时，也可以使用@Primary注解指定Bean的优先级。被@Primary注解标注的Bean对象会被优先注入。

### 2.1 注解源码

@Primary注解的源码详见：org.springframework.context.annotation.Primary。

```java
 /*
 * @author Chris Beams
 * @author Juergen Hoeller
 * @since 3.0
 * @see Lazy
 * @see Bean
 * @see ComponentScan
 * @see org.springframework.stereotype.Component
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Primary {
}
```

从@Primary注解的源码可以看出，@Primary注解是从Spring3.0版本开始提供的注解，可以标注到类和方法上，并且在@Primary注解中没有提供任何属性。

### 2.2 使用场景

如果依赖的对象存在多个类型相同的Bean时，使用@Autowired注解已经无法正确完成Bean的装配工作。此时，可以使用@Qualifier注解明确指定要装配的Bean对象。也可以使用@Primary注解优先装配对应的Bean对象。

## 三、使用案例

`@Primary优先注入Bean的案例，我们一起实现吧~~`

本节，就基于@Primary注解与@Bean注解实现向Bean属性中优先注入Bean的案例，具体的实现步骤如下所示。

**（1）新增PrimaryDao类**

PrimaryDao类的源码详见：spring-annotation-chapter-16工程下的io.binghe.spring.annotation.chapter16.dao.PrimaryDao。

```java
public interface PrimaryDao {
}
```

可以看到，PrimaryDao就是一个普通的Java接口。

**（2）新增PrimaryDao1类**

PrimaryDao1类的源码详见：spring-annotation-chapter-16工程下的io.binghe.spring.annotation.chapter16.dao.impl.PrimaryDao1。

```java
public class PrimaryDao1 implements PrimaryDao {
}
```

可以看到，PrimaryDao1类是一个普通的Java类，并且实现了PrimaryDao接口。

**（3）新增PrimaryDao2类**

PrimaryDao2类的源码详见：spring-annotation-chapter-16工程下的io.binghe.spring.annotation.chapter16.dao.impl.PrimaryDao2。

```java
public class PrimaryDao2 implements PrimaryDao {
}
```

可以看到，PrimaryDao2类同样是一个普通的Java类，同样实现了PrimaryDao接口。

**（4）新增PrimaryService类**

PrimaryService类的源码详见：spring-annotation-chapter-16工程下的io.binghe.spring.annotation.chapter16.service.PrimaryService。

```java
@Service
public class PrimaryService {
    @Autowired
    private PrimaryDao primaryDao;
    @Override
    public String toString() {
        return "PrimaryService{" +
                "primaryDao=" + primaryDao +
                '}';
    }
}
```

可以看到，PrimaryService类上标注了@Service注解，说明PrimaryService类的Bean对象在IOC容器启动时就会被注入IOC容器中，在PrimaryService类中使用@Autowired注解注入了PrimaryDao类的Bean对象。

**（5）新增PrimaryConfig类**

PrimaryConfig类的源码详见：spring-annotation-chapter-16工程下的io.binghe.spring.annotation.chapter16.config.PrimaryConfig。

```java
@Configuration
@ComponentScan(basePackages = {"io.binghe.spring.annotation.chapter16"})
public class PrimaryConfig {
    @Bean
    @Primary
    public PrimaryDao primaryDao1(){
        return new PrimaryDao1();
    }
    @Bean
    public PrimaryDao primaryDao2(){
        return new PrimaryDao2();
    }
}
```

可以看到，PrimaryConfig类上标注了@Configuration注解，说明PrimaryConfig类是案例的Spring配置类，并且使用@ComponentScan注解指定了要扫描的包。在PrimaryConfig类中，使用@Bean注解向IOC容器中注入两个PrimaryDao类型的Bean，一个Bean的默认名称为primaryDao1，另一个Bean的默认名称为primaryDao2。

**（6）新增PrimaryTest类**

PrimaryTest类的源码详见：spring-annotation-chapter-16工程下的io.binghe.spring.annotation.chapter16.PrimaryTest。

```java
public class PrimaryTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(PrimaryConfig.class);
        PrimaryService primaryService = context.getBean(PrimaryService.class);
        System.out.println(primaryService);
    }
}
```

可以看到，在PrimaryTest类的main()方法中，从IOC容器中获取PrimaryService对象后并进行打印。

**（7）运行PrimaryTest类**

运行PrimaryTest类的main()方法，输出的结果信息如下所示。

```java
PrimaryService{primaryDao=io.binghe.spring.annotation.chapter16.dao.impl.PrimaryDao1@429bffaa}
```

从输出的结果信息可以看出，使用@Primary注解后，向PrimaryService类中优先成功注入了PrimaryDao1类的Bean对象。

大家可以自行在PrimaryConfig类中将@Primary注解标注到primaryDao2()方法上，运行运行PrimaryTest类的main()方法，观察输出的结果，此时向PrimaryService类中就会成功注入PrimaryDao2类的Bean对象，这里不再赘述。

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本章，会从注册Bean的流程、调用Bean工厂后置处理器和创建Bean的流程三个方面分析@Primary注解的源码时序图。

### 4.1 注册Bean的流程

@Primary注解涉及到的注册Bean流程的源码时序图如图16-1所示。

![图16-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-10-001.png)



由图16-1可以看到，注册Bean的流程会涉及到PrimaryTest类、AnnotationConfigApplicationContext类、AnnotatedBeanDefinitionReader类、AnnotationConfigUtils类、BeanDefinitionReaderUtils类和DefaultListableBeanFactory类，具体的源码执行细节参见源码解析部分。 

### 4.2 调用Bean工厂后置处理器

@Primary注解涉及到的调用Bean工厂后置处理器的源码时序图如图16-2~16~3所示。

![图16-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-10-002.png)

![图16-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-10-003.png)

由图16-2~16-3可以看出，调用Bean工厂后置处理器的源码时序图涉及到PrimaryTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、ConfigurationClassBeanDefinitionReader类和DefaultListableBeanFactory类，具体的源码执行细节参见源码解析部分。 

### 4.3 创建Bean的流程

@Primary注解涉及到的创建Bean的源码时序图如图16-4~16~5所示。

![图16-4](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-10-004.png)



![图16-5](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-10-005.png)

有图16-4~16-5可以看出，创建Bean的源码时序图会涉及到PrimaryTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、DefaultListableBeanFactory类、AbstractBeanFactory类、AbstractAutowireCapableBeanFactory类、AutowiredAnnotationBeanPostProcessor类、InjectionMetadata类、AutowiredFieldElement类和QualifierAnnotationAutowireCandidateResolver类，具体的源码执行细节参见源码解析部分。 

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

### 5.1 注册Bean的流程

@Primary注解在Spring源码层面注册Bean的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图16-1进行理解。

@Primary注解涉及到的注册Bean的源码流程与第7章5.1小节@DependsOn注解涉及到的注册Bean的源码流程大体相同，只是在解析AnnotatedBeanDefinitionReader类的doRegisterBean()方法时，略有不同。本小节，就从AnnotatedBeanDefinitionReader类的doRegisterBean()方法开始解析。

（1）解析AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)。重点关注如下代码片段。

```java
private <T> void doRegisterBean(Class<T> beanClass, @Nullable String name, @Nullable Class<? extends Annotation>[] qualifiers, @Nullable Supplier<T> supplier, @Nullable BeanDefinitionCustomizer[] customizers) {
	/*************省略其他代码***********/
    AnnotationConfigUtils.processCommonDefinitionAnnotations(abd);
    if (qualifiers != null) {
        for (Class<? extends Annotation> qualifier : qualifiers) {
            if (Primary.class == qualifier) {
                abd.setPrimary(true);
            }
            /*************省略其他代码***********/
        }
    }
    /*************省略其他代码***********/
    BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(abd, beanName);
    definitionHolder = AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
    BeanDefinitionReaderUtils.registerBeanDefinition(definitionHolder, this.registry);
}
```

可以看到，在AnnotatedBeanDefinitionReader类的doRegisterBean()方法中，调用了AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法。

（2）解析AnnotationConfigUtils类的processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd)方法

源码详见：org.springframework.context.annotation.AnnotationConfigUtils#processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd)。

```java
public static void processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd) {
    processCommonDefinitionAnnotations(abd, abd.getMetadata());
}
```

可以看到，在AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法中，直接调用了另一个重载的processCommonDefinitionAnnotations()方法。

（3）解析AnnotationConfigUtils类的processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata)方法

源码详见：org.springframework.context.annotation.AnnotationConfigUtils#processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata)。

```java
static void processCommonDefinitionAnnotations(AnnotatedBeanDefinition abd, AnnotatedTypeMetadata metadata) {
    /***********省略其他代码************/
    if (metadata.isAnnotated(Primary.class.getName())) {
        abd.setPrimary(true);
    }
    /***********省略其他代码************/
}
```

可以看到，在processCommonDefinitionAnnotations()方法中，会判断如果传递进来的metadata参数被标注了@Primary注解，则会将abd对象的primary属性设置为true。

（4）回到AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法。

在AnnotatedBeanDefinitionReader类的doRegisterBean()方法中，会循环遍历qualifiers，如果遍历出的Class对象qualifier与@Primary注解的Class对象相等，则会将abd的primary属性设置为true。

**后续的执行流程就与第7章5.1小节的执行流程相同，不再赘述。**

至此，@Primary注解涉及到的注册Bean的源码流程分析完毕。

### 5.2 调用Bean工厂后置处理器

本节的源码解析流程与第3章深度解析@Bean注解的源码解析流程基本相同，这里不再赘述，大家可参考第3章的源码解析过程。本节的源码执行流程可以结合图16-2~16-3进行理解。

### 5.3 创建Bean的流程

@Primary注解在Spring源码层面创建Bean的流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图16-4~16-5进行理解。

@Primary注解在Spring源码层面创建Bean的流程与@Autowired注解在Spring源码层面创建Bean的流程基本相同，只是会多一些实现细节，本节重点介绍@Primary注解在Spring源码层面创建Bean的流程时，新增的实现细节。直接从DefaultListableBeanFactory类的doResolveDependency()方法开始解析。

（1）解析DefaultListableBeanFactory类的doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName,  @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName,  @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)。

```java
@Nullable
public Object doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter) throws BeansException {
    InjectionPoint previousInjectionPoint = ConstructorResolver.setCurrentInjectionPoint(descriptor);
    try {
		/**************省略其他代码************/
        Map<String, Object> matchingBeans = findAutowireCandidates(beanName, type, descriptor);
        if (matchingBeans.isEmpty()) {
            if (isRequired(descriptor)) {
                raiseNoMatchingBeanFound(type, descriptor.getResolvableType(), descriptor);
            }
            return null;
        }
        String autowiredBeanName;
        Object instanceCandidate;

        if (matchingBeans.size() > 1) {
            autowiredBeanName = determineAutowireCandidate(matchingBeans, descriptor);
            if (autowiredBeanName == null) {
                if (isRequired(descriptor) || !indicatesMultipleBeans(type)) {
                    return descriptor.resolveNotUnique(descriptor.getResolvableType(), matchingBeans);
                }
                /**************省略其他代码************/
            }
            instanceCandidate = matchingBeans.get(autowiredBeanName);
        }
        /**************省略其他代码************/
        return result;
    }
    finally {
        ConstructorResolver.setCurrentInjectionPoint(previousInjectionPoint);
    }
}
```

可以看到，在DefaultListableBeanFactory类的doResolveDependency()方法中，通过调用findAutowireCandidates()方法获取到的Map对象matchingBeans会被传入determineAutowireCandidate()中最终得到一个要被注入的Bean的名称。

（2）解析DefaultListableBeanFactory类的determineAutowireCandidate(Map<String, Object> candidates, DependencyDescriptor descriptor)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#determineAutowireCandidate(Map<String, Object> candidates, DependencyDescriptor descriptor)

```java
@Nullable
protected String determineAutowireCandidate(Map<String, Object> candidates, DependencyDescriptor descriptor) {
    Class<?> requiredType = descriptor.getDependencyType();
    String primaryCandidate = determinePrimaryCandidate(candidates, requiredType);
    if (primaryCandidate != null) {
        return primaryCandidate;
    }
 	/**********省略其他代码*************/
    return null;
}
```

可以看到，在DefaultListableBeanFactory类的determineAutowireCandidate()方法中，会调用determinePrimaryCandidate()方法来解析被@Primary标注的类或者方法，最终返回一个被@Primary注解标注的Bean的名称。

（3）解析DefaultListableBeanFactory类的determinePrimaryCandidate(Map<String, Object> candidates, Class<?> requiredType)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#determinePrimaryCandidate(Map<String, Object> candidates, Class<?> requiredType)。

```java
@Nullable
protected String determinePrimaryCandidate(Map<String, Object> candidates, Class<?> requiredType) {
    String primaryBeanName = null;
    for (Map.Entry<String, Object> entry : candidates.entrySet()) {
        String candidateBeanName = entry.getKey();
        Object beanInstance = entry.getValue();
        if (isPrimary(candidateBeanName, beanInstance)) {
            if (primaryBeanName != null) {
                boolean candidateLocal = containsBeanDefinition(candidateBeanName);
                boolean primaryLocal = containsBeanDefinition(primaryBeanName);
                if (candidateLocal && primaryLocal) {
                    throw new NoUniqueBeanDefinitionException(requiredType, candidates.size(),  "more than one 'primary' bean found among candidates: " + candidates.keySet());
                }
                else if (candidateLocal) {
                    primaryBeanName = candidateBeanName;
                }
            }
            else {
                primaryBeanName = candidateBeanName;
            }
        }
    }
    return primaryBeanName;
}
```

DefaultListableBeanFactory类的determinePrimaryCandidate()方法就是处理@Primary注解最核心的逻辑。

可以看到，在DefaultListableBeanFactory类的determinePrimaryCandidate()方法中，获取被@Primary注解标注的Bean的名称的逻辑比较简单。首先定义一个String类型的变量primaryBeanName，用于接收最终的结果数据，并且赋值为null。由于之前已经将被@Bean注解标注的方法生成的Bean存放到了一个Map结构candidates中。在determinePrimaryCandidate()方法中，会遍历Map结构candidates，会根据遍历出的每一个元素的Key赋值给candidateBeanName变量，将Value赋值给beanInstance变量，并且通过Key和Value来判断是否是被@Primary注解标注的Bean。

如果不是被@Primary注解标注的Bean，则继续下一次循环。否则，判断primaryBeanName是否为空，如果为空，则将candidateBeanName赋值给primaryBeanName。否则，会判断IOC容器中是否同时存在以candidateBeanName命名的Bean和以primaryBeanName命名的Bean，如果存在，则抛出NoUniqueBeanDefinitionException异常。这主要是限定Spring中对于同一种类型的Bean，不能使用@Primary注解标注多个Bean。如果IOC容器中存在以candidateBeanName命名的Bean，并且不存在以primaryBeanName命名的Bean，则将candidateBeanName赋值给primaryBeanName。最终，返回primaryBeanName。

**注意：@Primary注解在Spring源码层面创建Bean的其他流程与@Autowired注解相同，这里不再赘述。**

至此，@Primary注解在Spring源码层面创建Bean的流程分析完毕。

## 六、总结

`@Primary注解介绍完了，我们一起总结下吧！`

本章，主要介绍了@Primary注解，首先介绍了注解的源码和使用场景。随后，给出了注解的使用案例。接下来，分别从注册Bean的流程、调用Bean的工厂后置处理器和创建Bean的流程三个方面分析了源码时序图和源码流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Primary注解，通常会有如下几个经典面试题：

* @Primary注解的作用是什么？
* @Primary注解有哪些使用场景？
* @Primary是如何实现Bean的优先级的？
* @Primary注解在Spring内部的执行流程？
* @Primary注解与@Qualifier注解有何区别？
* 你在平时工作中，会在哪些场景下使用@Primary注解？
* 你从@Primary注解的设计中得到了哪些启发？

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