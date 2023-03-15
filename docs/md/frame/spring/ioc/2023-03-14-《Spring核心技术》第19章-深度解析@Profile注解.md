---
layout: post
category: binghe-code-spring
title: 第19章：深度解析@Profile注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第19章：深度解析@Profile注解
lock: need
---

# 《Spring核心技术》第19章-环境变量型注解：深度解析@Profile注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-19](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-19)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Profile注解隔离环境的案例和流程，从源码级别彻底掌握@Profile注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
  * 注解标注到方法上
  * 注解标注到类上
  * 使用默认的环境
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Profile注解，你真的彻底了解过吗？`

在实际开发项目的过程中，往往会将环境分为开发环境、测试环境和生产环境，每个环境基本上都是互相隔离的。在以前的开发过程中，如果开发人员完成相应的功能模块并通过单元测试后，会通过手动修改配置文件的方式，将配置修改成测试环境，发布到测试环境进行测试。测试通过后，再将配置修改成生产环境，发布到生产环境。这样通过手动修改配置文件的方式，一方面会增加项目开发和运维的工作量，另一方面，每次都需要手动修改配置文件就非常容易出问题。

## 二、注解说明

`关于@Profile注解的一点点说明~~`

在实际开发过程中，可以使用@Profile隔离开发环境、测试环境和生产环境。也就是说，如果在IOC容器中存在多个类型相同的Bean，就可以使用@Profile注解标识使用哪个Bean，在开发环境、测试环境和生产环境可以在不修改代码的前提下，使用@Profile注解切换要使用的Bean。例如，在开发环境、测试环境和生产环境需要连接不同的数据库，此时就可以使用@Profile注解实现。

### 2.1 注解源码

@Profile注解的源码详见：org.springframework.context.annotation.Profile。

```java
/**
 * @author Chris Beams
 * @author Phillip Webb
 * @author Sam Brannen
 * @since 3.1
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Conditional(ProfileCondition.class)
public @interface Profile {
	String[] value();
}
```

从@Profile注解的源码可以看出，@Profile注解是从Spring3.1版本开始提供的注解，可以将注解标注到类上和方法上，在注解中提供了一个Spring数组类型的value属性，含义如下所示。

* value：指定环境的标识。

**注意：@Profile不仅可以标注在方法上，也可以标注在配置类上。如果标注在配置类上，只有在指定的环境时，整个配置类里面的所有配置才会生效。如果一个Bean上没有使用@Profile注解进行标注，那么这个Bean在任何环境下都会被注册到IOC容器中。**

### 2.2 使用场景

在项目的开发过程中，往往会分成开发环境、测试环境和生产环境，可以使用@Profile注解针对不同的环境配置不同的运行时参数，从而使得程序不用修改代码就能在不同的环境下运行。例如，可以使用@Profile注解切换不同环境下的数据库连接和配置信息等。

## 三、使用案例

`一起实现@Profile注解的案例，怎么样?`

本章，使用@Profile注解模拟实现开发环境、测试环境和生产环境的配置。在具体实现中，会按照@Profile注解标注到方法上、标注到类上和使用默认的环境三个方面实现案例。

### 3.1 注解标注到方法上

本节，主要将@Profile注解标注到方法上来模拟实现开发环境、测试环境和生产环境的配置，具体实现的步骤如下所示。

**（1）新增ProfileBean类**

ProfileBean类的源码详见：spring-annotation-chapter-19工程下的io.binghe.spring.annotation.chapter19.bean.ProfileBean。

```java
public class ProfileBean {
    private String env;
    public ProfileBean(String env) {
        this.env = env;
    }
    @Override
    public String toString() {
        return "ProfileBean{" +  "env='" + env + '}';
    }
}
```

可以看到，ProfileBean类就是一个普通的Java类，在ProfileBean类中，提供了一个String类型的成员变量env，表示当前的环境信息，并通过ProfileBean类的构造方法赋值，最后提供了toString()方法，打印ProfileBean类的信息。

**（2）新增ProfileConfig类**

ProfileConfig类的源码详见：spring-annotation-chapter-19工程下的io.binghe.spring.annotation.chapter19.config.ProfileConfig。

```java
@Configuration
public class ProfileConfig {
    @Profile("dev")
    @Bean("profileBeanDev")
    public ProfileBean profileBeanDev(){
        return new ProfileBean("开发环境");
    }
    @Profile("test")
    @Bean("profileBeanTest")
    public ProfileBean profileBeanTest(){
        return new ProfileBean("测试环境");
    }
    @Profile("prod")
    @Bean("profileBeanProd")
    public ProfileBean profileBeanProd(){
        return new ProfileBean("生产环境");
    }
}
```

可以看到，在ProfileConfig类上标注了@Configuration注解，说明ProfileConfig类是案例程序的配置类，并且在ProfileConfig类中使用@Bean注解结合@Profile注解向IOC容器中，根据不同的环境向IOC容器中注入对应的Bean对象。模拟实现开发环境、测试环境和生产环境。

**（3）新增ProfileTest类**

ProfileTest类的源码详见：spring-annotation-chapter-19工程下的io.binghe.spring.annotation.chapter19.ProfileTest。

```java
public class ProfileTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().setActiveProfiles("dev");
        context.register(ProfileConfig.class);
        context.refresh();
        ProfileBean profileBean = context.getBean(ProfileBean.class);
        System.out.println(profileBean);
    }
}
```

可以看到，在ProfileTest类的main()方法中，会在IOC容器的环境中指定环境标识dev，也就是说，指定的环境是开发环境。然后在IOC容器中注册ProfileConfig类的Class对象，刷新IOC容器后，从IOC容器中获取ProfileBean类的Bean对象并进行打印。

**（4）运行ProfileTest类**

运行ProfileTest类的main()方法，输出的结果信息如下所示。

```java
ProfileBean{env='开发环境}
```

从输出的结果信息可以看出，此时打印的环境信息是开发环境。

**说明@Profile注解标注到方法上，能够根据不同的环境指定使用不同的Bean。**

### 3.2 注解标注到类上

本节的案例程序会在3.1节的基础上实现将@Profile注解标注到类上。具体实现步骤如下所示。

**（1）修改ProfileConfig类**

在ProfileConfig类上标注@Profile注解，并指定环境标识为prod，如下所示。

```java
@Profile("prod")
@Configuration
public class ProfileConfig {
    @Profile("dev")
    @Bean("profileBeanDev")
    public ProfileBean profileBeanDev(){
        return new ProfileBean("开发环境");
    }
    @Profile("test")
    @Bean("profileBeanTest")
    public ProfileBean profileBeanTest(){
        return new ProfileBean("测试环境");
    }
    @Profile("prod")
    @Bean("profileBeanProd")
    public ProfileBean profileBeanProd(){
        return new ProfileBean("生产环境");
    }
}
```

可以看到，尽管在ProfileConfig类中使用@Profile注解指定了开发环境dev，测试环境test和生产环境prod，但是在ProfileConfig类上使用@Profile注解指定的是生产环境prod。

**（2）运行ProfileTest类**

运行ProfileTest类的main()方法，输出的结果信息如下所示。

```bash
Exception in thread "main" org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type 'io.binghe.spring.annotation.chapter19.bean.ProfileBean' available
```

可以看到，结果信息中输出了ProfileBean类的Bean对象不存在的异常。

**（3）修改ProfileTest类**

将ProfileTest类的main()方法中的环境标识修改成prod，如下所示。

```java
public static void main(String[] args) {
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
    context.getEnvironment().setActiveProfiles("prod");
    context.register(ProfileConfig.class);
    context.refresh();
    ProfileBean profileBean = context.getBean(ProfileBean.class);
    System.out.println(profileBean);
}
```

可以看到，在ProfileTest类的main()方法中，已经将环境标识由dev修改成了prod。

**（4）运行ProfileTest类**

再次运行ProfileTest类的main()方法，输出的结果信息如下所示。

```java
ProfileBean{env='生产环境}
```

可以看到，输出的结果信息是生产环境。

**说明：当@Profile注解标注到类上时，虽然类中的方法上也标注了@Profile注解，但是整体上会以类上标注的@Profile注解为准。如果设置的环境标识与类上标注的@Profile注解中的环境标识不匹配，则整个类中的配置都不会生效。否则，类中没有使用@Profile注解标识的Bean和环境标识与方法上使用@Profile注解指定的环境标识匹配的Bean才会生效。**

### 3.3 使用默认的环境

当使用@Profile注解指定了环境标识时，如果在启动IOC容器时，没有设置对应的环境标识就会抛异常。此时可以提供一个默认的环境配置，使得启动IOC容器时，如果没有设置对应的环境标识，就使默认的环境配置生效。案例的具体实现步骤如下所示。

**（1）修改ProfileTest类**

修改ProfileTest类的main()方法，去除指定的环境标识，如下所示。

```java
public static void main(String[] args) {
    AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ProfileConfig.class);
    ProfileBean profileBean = context.getBean(ProfileBean.class);
    System.out.println(profileBean);
}
```

可以看到，在ProfileTest类的main()方法中，传入ProfileConfig类的Class对象创建IOC容器后，直接从IOC容器中获取ProfileBean类的Bean对象并打印。

**（2）运行ProfileTest类**

运行ProfileTest类的main()方法，输出的结果信息如下所示。

```bash
Exception in thread "main" org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type 'io.binghe.spring.annotation.chapter19.bean.ProfileBean' available
```

可以看到，当配置类中的Bean使用@Profile注解指定了环境标识时，如果程序运行时，未指定环境标识从IOC容器中获取Bean，就会抛出NoSuchBeanDefinitionException异常。

**（3）修改ProfileConfig类**

去除ProfileConfig类上的@Profile注解，并在ProfileConfig类中使用@Profile注解提供一个默认的环境配置，如下所示。

```java
@Profile("default")
@Bean("profileBeanDefault")
public ProfileBean profileBeanDefault(){
    return new ProfileBean("默认环境");
}
```

**（4）运行ProfileTest类**

运行ProfileTest类的main()方法，输出的结果信息如下所示。

```java
ProfileBean{env='默认环境}
```

可以看到，正确输出了默认的环境信息。

**说明：当Bean使用@Profile注解指定了环境信息时，如果程序运行时，未指定环境标识从IOC容器中获取Bean，就会抛出NoSuchBeanDefinitionException异常。此时，可以使用@Profile注解提供一个默认的环境配置，随后在IOC容器启动时，就会使默认的环境配置生效，此后未指定环境标识从IOC容器中获取Bean，就会获取到默认环境配置的Bean对象。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本章，就简单介绍下@Profile注解的源码时序图。@Profile注解的源码时序图如图19-1~19-2所示。

![图19-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-14-001.png)



![图19-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-14-002.png)

由图19-1~19-2可以看出，@Profile注解在Spring底层的执行流程会涉及到ProfileTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、ConfigurationClassBeanDefinitionReader类、ConditionEvaluator类、ProfileCondition类和DefaultListableBeanFactory类，具体的源码执行细节参见源码解析部分。 

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

@Profile注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻，本节的源码执行流程可以结合图19-1~19-2进行理解。

本节对@Profile注解的源码分析大体流程与第3章中5.1节注册Bean的源码分析流程相同，只是部分细节不同。本节，只介绍与第3章中5.1节中不同的部分。直接从ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForBeanMethod()方法开始解析。

（1）解析ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForBeanMethod(BeanMethod beanMethod)方法

源码详见：org.springframework.context.annotation.ConfigurationClassBeanDefinitionReader#loadBeanDefinitionsForBeanMethod(BeanMethod beanMethod)。关于@Profile注解的解析重点关注如下代码片段。

```java
private void loadBeanDefinitionsForBeanMethod(BeanMethod beanMethod) {
    ConfigurationClass configClass = beanMethod.getConfigurationClass();
    MethodMetadata metadata = beanMethod.getMetadata();
    String methodName = metadata.getMethodName();
    if (this.conditionEvaluator.shouldSkip(metadata, ConfigurationPhase.REGISTER_BEAN)) {
        configClass.skippedBeanMethods.add(methodName);
        return;
    }
    /************省略其他代码*************/
    this.registry.registerBeanDefinition(beanName, beanDefToRegister);
}
```

可以看到，在ConfigurationClassBeanDefinitionReader类的loadBeanDefinitionsForBeanMethod()方法中，会调用conditionEvaluator对象的shouldSkip()方法判断是否忽略当前Bean，如果返回true，也就是忽略当前Bean，就会将要忽略的方法名称存入到skippedBeanMethods中，直接返回。

（2）解析ConditionEvaluator类的shouldSkip(@Nullable AnnotatedTypeMetadata metadata, @Nullable ConfigurationPhase phase)方法

源码详见：org.springframework.context.annotation.ConditionEvaluator#shouldSkip(@Nullable AnnotatedTypeMetadata metadata, @Nullable ConfigurationPhase phase)。

```java
public boolean shouldSkip(@Nullable AnnotatedTypeMetadata metadata, @Nullable ConfigurationPhase phase) {
    if (metadata == null || !metadata.isAnnotated(Conditional.class.getName())) {
        return false;
    }
	/*************省略其他代码*************/
    List<Condition> conditions = new ArrayList<>();
    for (String[] conditionClasses : getConditionClasses(metadata)) {
        for (String conditionClass : conditionClasses) {
            Condition condition = getCondition(conditionClass, this.context.getClassLoader());
            conditions.add(condition);
        }
    }
    AnnotationAwareOrderComparator.sort(conditions);
    for (Condition condition : conditions) {
        ConfigurationPhase requiredPhase = null;
        if (condition instanceof ConfigurationCondition) {
            requiredPhase = ((ConfigurationCondition) condition).getConfigurationPhase();
        }
        if ((requiredPhase == null || requiredPhase == phase) && !condition.matches(this.context, metadata)) {
            return true;
        }
    }

    return false;
}
```

可以看到，在ConditionEvaluator类的shouldSkip()方法中，首先判断如果metadata为null，或者没有标注@Conditional注解，则直接返回false。接下来，会通过getConditionClasses()方法获取@Conditional注解的value属性指定的Class，并实例化成Condition对象放入conditions集合中。随后遍历conditions集合，判断condition对象是否是ConfigurationCondition类型，如果是ConfigurationCondition类型，则会为requiredPhase赋值。随后会判断，如果requiredPhase为null，或者requiredPhase等于传递进来的phase，同时调用condition对象的matches()方法不匹配规则，则返回true，表示忽略当前Bean，不会将Bean注册到IOC容器中。否则，返回false，表示不会忽略当前Bean，会将当前Bean注册到IOC容器中。

调用遍历出的condition对象的matches()方法时，就会调用ProfileCondition类的matches()方法。

（3）解析ProfileCondition类的matches(ConditionContext context, AnnotatedTypeMetadata metadata)方法

源码详见：org.springframework.context.annotation.ProfileCondition#matches(ConditionContext context, AnnotatedTypeMetadata metadata)。

```java
@Override
public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
    MultiValueMap<String, Object> attrs = metadata.getAllAnnotationAttributes(Profile.class.getName());
    if (attrs != null) {
        for (Object value : attrs.get("value")) {
            if (context.getEnvironment().acceptsProfiles(Profiles.of((String[]) value))) {
                return true;
            }
        }
        return false;
    }
    return true;
}
```

可以看到，ProfileCondition类的matches()方法的逻辑比较简单，就是获取所有@Profile注解中的属性，随后遍历@Profile注解中的value属性，如果IOC容器的环境变量中存在对应的value属性值，则返回true，表示匹配规则，否则返回false，表示不匹配规则。默认为返回true，匹配规则。

**注意：在ProfileCondition类的matches()方法中，如果返回true，表示匹配规则，不会忽略当前Bean，会将Bean注册到IOC容器中。否则，表示不匹配规则，会忽略当前Bean，不会将Bean注册到IOC容器中。**

其他源码的执行流程与第3章中5.1节注册Bean的源码执行流程相同，这里不再赘述。

至此，@Profile注解的源码执行流程分析完毕。

## 六、总结

`@Profile注解介绍完了，我们一起总结下吧！`

本章，主要对@Profile注解进行了简单的介绍。首先介绍了注解的源码和使用场景。随后，分别介绍了将注解标注到方法上、将注解标注到类上和使用默认环境三个案例。接下来，分析了@Profile注解在Spring中执行的源码时序图和源码流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Profile注解，通常会有如下几个经典面试题：

* @Profile注解的作用是什么？
* @Profile注解有哪些使用场景？
* @Profile注解是如何做到隔离不同环境的配置的？
* @Profile注解在Spring内部的执行流程？
* 你在平时工作中，会在哪些场景下使用@Profile注解？
* 你从Profile注解的设计中得到了哪些启发？

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

