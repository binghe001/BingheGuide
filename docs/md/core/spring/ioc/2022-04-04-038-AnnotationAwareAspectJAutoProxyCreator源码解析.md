---
layout: post
category: binghe-spring-ioc
title: 第37章：Spring AOP核心类解析
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 最近，不少小伙伴在催更【Spring注解驱动开发】专题，好吧，【Spring注解驱动开发】专题确实有很长时间没更新了。那我们从今天开始更新【Spring注解驱动开发】专题，同样的，我们还是以源码解析为主。
lock: need
---

# 《Spring注解驱动开发》第37章：Spring AOP核心类解析

## 写在前面

> 最近，不少小伙伴在催更【Spring注解驱动开发】专题，好吧，【Spring注解驱动开发】专题确实有很长时间没更新了。那我们从今天开始更新【Spring注解驱动开发】专题，同样的，我们还是以源码解析为主。
>
> 文章已同步收录到：https://github.com/sunshinelyz/technology-binghe 和 https://gitee.com/binghe001/technology-binghe 。如果文件对你有点帮助，别忘记给个Star哦！
>
> 关注【冰河技术】微信公众号，回复“Spring注解”领取工程源码。

## 类结构图

我们先来看下AnnotationAwareAspectJAutoProxyCreator类的结构图。

![013](https://binghe.gitcode.host/assets/images/core/spring/ioc/2022-04-04-038-001.png)

上图中一些 **类/接口** 的介绍：

**AspectJAwareAdvisorAutoProxyCreator** : 公开了AspectJ的调用上下文，并弄清楚来自同一切面的多个Advisor在AspectJ中的优先级规则。

**AbstractAdvisorAutoProxyCreator** : 通用自动代理创建器，它基于检测到的每个顾问程序为特定bean构建AOP代理。

**AbstractAutoProxyCreator** : 扩展了  ProxyProcessorSupport，实现了SmartInstantiationAwareBeanPostProcessor、BeanFactoryAware 接口，是BeanPostProcessor 实现，该实现使用AOP代理包装每个合格的bean，并在调用bean本身之前委派给指定的拦截器。

**BeanFactoryAware** : 实现了该接口的Bean可以知道它属于那个 BeanFactory，Bean可以通过Spring容器查找它的协同者（依赖查找），但大多数的Bean是通过构造器参数和Bean方法（依赖注入）来获取它的协同者。

**BeanPostProcessor** ：工厂钩子，允许自定义修改新的bean实例。例如，检查标记接口或使用代理包装bean。**如果我们需要在Spring容器中完成Bean的实例化，配置和其初始化前后添加一些自己的逻辑处理，我们就可以定义一个或多个BeanPostProcessor接口的实现，然后注册到容器中。**

**InstantiationAwareBeanPostProcessor** : BeanPostProcessor  的子接口，它添加了实例化之前的回调，以及实例化之后但设置了显式属性或自动装配之前的回调。它内部提供了3个方法，再加上BeanPostProcessor接口内部的2个方法，实现这个接口需要实现5个方法。InstantiationAwareBeanPostProcessor 接口的主要作用在于目标对象的实例化过程中需要处理的事情，包括实例化对象的前后过程以及实例的属性设置。

**SmartInstantiationAwareBeanPostProcessor** : InstantiationAwareBeanPostProcessor 接口的扩展，多出了3个方法，添加了用于预测已处理bean的最终类型的回调，再加上父接口的5个方法，所以实现这个接口需要实现8个方法，主要作用也是在于目标对象的实例化过程中需要处理的事情。

**总之：**AspectJAwareAdvisorAutoProxyCreator为 AspectJ 切面类创建自动代理。

## 核心类解析

**BeanPostProcessor** 接口中的两个方法 postProcessBeforeInitialization 和 postProcessAfterInitialization，作用是对**Bean初始化前后**添加一些自己的逻辑。

```java
@Nullable
default Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
    return bean;
}

@Nullable
default Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
    return bean;
}
```

**InstantiationAwareBeanPostProcessor** 是 **BeanPostProcessor** 的子接口，它额外增加了3个新的方法：postProcessBeforeInstantiation（ 目标对象被**实例化之前**调用的方法，可以返回目标实例的一个代理用来代替目标实例 ）、postProcessAfterInstantiation（该方法在Bean**实例化之后**执行，返回false，会忽略属性值的设置；如果返回true，会按照正常流程设置属性值） 和 postProcessPropertyValues（对属性值进行修改，未来版本将会删除）

```java
@Nullable
default Object postProcessBeforeInstantiation(Class<?> beanClass, String beanName) throws BeansException {
    return null;
}

default boolean postProcessAfterInstantiation(Object bean, String beanName) throws BeansException {
    return true;
}

@Nullable
default PropertyValues postProcessPropertyValues(
    PropertyValues pvs, PropertyDescriptor[] pds, Object bean, String beanName) throws BeansException {
    return pvs;
}
```

**SmartInstantiationAwareBeanPostProcessor**接口继承InstantiationAwareBeanPostProcessor接口，里面定义了3个方法：predictBeanType（预测Bean的类型）、determineCandidateConstructors（选择合适的构造器）、getEarlyBeanReference（解决循环引用问题）。

```java
@Nullable
default Class<?> predictBeanType(Class<?> beanClass, String beanName) throws BeansException {
    return null;
}

@Nullable
default Constructor<?>[] determineCandidateConstructors(Class<?> beanClass, String beanName) throws BeansException {
    return null;
}

default Object getEarlyBeanReference(Object bean, String beanName) throws BeansException {
    return bean;
}
```

**AbstractAutoProxyCreator** 是AOP的一个核心类，它实现了SmartInstantiationAwareBeanPostProcessor、BeanFactoryAware 接口，实现了代理创建的逻辑，使用AOP代理包装每个合格的bean，并在调用bean本身之前委派给指定的拦截器。

**AbstractAdvisorAutoProxyCreator** 通用自动代理创建器，它基于检测每个bean的增强器，为特殊的bean构建AOP代理。子类可以重写此findCandidateAdvisors()方法，以返回适用于任何对象的advisor的自定义列表，子类还可以重写继承的AbstractAutoProxyCreator.shouldSkip()方法，以将某些对象排除在自动代理之外。

```java
protected List<Advisor> findCandidateAdvisors() {
       Assert.state(this.advisorRetrievalHelper != null, "No BeanFactoryAdvisorRetrievalHelper available");
     return this.advisorRetrievalHelper.findAdvisorBeans();
}
```

**AspectJAwareAdvisorAutoProxyCreator** 扩展 AbstractAdvisorAutoProxyCreator，公开了AspectJ的调用上下文，并在多个增强器来自同一切面时搞清楚AspectJ的建议优先级顺序。按AspectJ优先级排序其余部分：

```java
@Override
@SuppressWarnings("unchecked")
protected List<Advisor> sortAdvisors(List<Advisor> advisors) {
    List<PartiallyComparableAdvisorHolder> partiallyComparableAdvisors = new ArrayList<>(advisors.size());
    for (Advisor element : advisors) {
        partiallyComparableAdvisors.add(
            new PartiallyComparableAdvisorHolder(element, DEFAULT_PRECEDENCE_COMPARATOR));
    }
    List<PartiallyComparableAdvisorHolder> sorted = PartialOrder.sort(partiallyComparableAdvisors);
    if (sorted != null) {
        List<Advisor> result = new ArrayList<>(advisors.size());
        for (PartiallyComparableAdvisorHolder pcAdvisor : sorted) {
            result.add(pcAdvisor.getAdvisor());
        }
        return result;
    }
    else {
        return super.sortAdvisors(advisors);
    }
}
```

在增强链头部增加一个ExposeInvocationInterceptor，使用AspectJ表达式切入点和使用AspectJ样式的advisor时，需要这些附加advisor。

```java
protected void extendAdvisors(List<Advisor> candidateAdvisors) {
      AspectJProxyUtils.makeAdvisorChainAspectJCapableIfNecessary(candidateAdvisors);
}
```

如果此后处理器不应该考虑将给定的bean用于自动代理，子类应重写此方法以返回true

```java
@Override
protected boolean shouldSkip(Class<?> beanClass, String beanName) {
    // TODO: Consider optimization by caching the list of the aspect names
    List<Advisor> candidateAdvisors = findCandidateAdvisors();
    for (Advisor advisor : candidateAdvisors) {
        if (advisor instanceof AspectJPointcutAdvisor &&
            ((AspectJPointcutAdvisor) advisor).getAspectName().equals(beanName)) {
            return true;
        }
    }
    return super.shouldSkip(beanClass, beanName);
}
```

**AspectJAwareAdvisorAutoProxyCreator** 还有一个子类叫 **AnnotationAwareAspectJAutoProxyCreator**，子类AnnotationAwareAspectJAutoProxyCreator是用于处理当前应用程序上下文中的所有AspectJ注释方面以及Spring Advisor。如果Spring  AOP的基于代理的模型能够应用任何AspectJ注释的类，它们的advisor将被自动识别，这涵盖了方法执行连接点，Spring  Advisor的处理遵循AbstractAdvisorAutoProxyCreator中建立的规则。

## 生成代理对象

从使用<aop:xxx>标签来自动生成代理的话，先看看AopNamespaceHandler，使用<aop:config>标签则使用 ConfigBeanDefinitionParser 解析，使用了<aop:aspectj-autoproxy>标签则使用 AspectJAutoProxyBeanDefinitionParser 解析，依次类推。

```java
@Override
public void init() {
    // In 2.0 XSD as well as in 2.1 XSD.
    registerBeanDefinitionParser("config", new ConfigBeanDefinitionParser());
    registerBeanDefinitionParser("aspectj-autoproxy", new AspectJAutoProxyBeanDefinitionParser());
    registerBeanDefinitionDecorator("scoped-proxy", new ScopedProxyBeanDefinitionDecorator());

    // Only in 2.0 XSD: moved to context namespace as of 2.1
    registerBeanDefinitionParser("spring-configured", new SpringConfiguredBeanDefinitionParser());
}
```

- <aop:config>方式使用 AspectJAwareAdvisorAutoProxyCreator 创建代理
- <aop:aspectj-autoproxy>使用 AnnotationAwareAspectJAutoProxyCreator 创建代理

ConfigBeanDefinitionParser.java

```java
@Override
@Nullable
public BeanDefinition parse(Element element, ParserContext parserContext) {
    CompositeComponentDefinition compositeDef =
        new CompositeComponentDefinition(element.getTagName(), parserContext.extractSource(element));
    parserContext.pushContainingComponent(compositeDef);

    configureAutoProxyCreator(parserContext, element); // 注册AspectJAwareAdvisorAutoProxyCreator

    List<Element> childElts = DomUtils.getChildElements(element);
    for (Element elt: childElts) {
        String localName = parserContext.getDelegate().getLocalName(elt);
        if (POINTCUT.equals(localName)) {
            parsePointcut(elt, parserContext);
        }
        else if (ADVISOR.equals(localName)) {
            parseAdvisor(elt, parserContext);
        }
        else if (ASPECT.equals(localName)) {
            parseAspect(elt, parserContext);
        }
    }

    parserContext.popAndRegisterContainingComponent();
    return null;
}

private void configureAutoProxyCreator(ParserContext parserContext, Element element) {
    AopNamespaceUtils.registerAspectJAutoProxyCreatorIfNecessary(parserContext, element);
}
```

AopConfigUtils.java

```java
@Override
@Nullable
public BeanDefinition parse(Element element, ParserContext parserContext) {
    CompositeComponentDefinition compositeDef =
        new CompositeComponentDefinition(element.getTagName(), parserContext.extractSource(element));
    parserContext.pushContainingComponent(compositeDef);

    configureAutoProxyCreator(parserContext, element); // 注册AspectJAwareAdvisorAutoProxyCreator

    List<Element> childElts = DomUtils.getChildElements(element);
    for (Element elt: childElts) {
        String localName = parserContext.getDelegate().getLocalName(elt);
        if (POINTCUT.equals(localName)) {
            parsePointcut(elt, parserContext);
        }
        else if (ADVISOR.equals(localName)) {
            parseAdvisor(elt, parserContext);
        }
        else if (ASPECT.equals(localName)) {
            parseAspect(elt, parserContext);
        }
    }

    parserContext.popAndRegisterContainingComponent();
    return null;
}

private void configureAutoProxyCreator(ParserContext parserContext, Element element) {
    AopNamespaceUtils.registerAspectJAutoProxyCreatorIfNecessary(parserContext, element);
}
```

AopConfigUtils.java

```java
public static void registerAspectJAutoProxyCreatorIfNecessary(
    ParserContext parserContext, Element sourceElement) {
    // 在这里注册的是AspectJAwareAdvisorAutoProxyCreator
    BeanDefinition beanDefinition = AopConfigUtils.registerAspectJAutoProxyCreatorIfNecessary(
        parserContext.getRegistry(), parserContext.extractSource(sourceElement));
    useClassProxyingIfNecessary(parserContext.getRegistry(), sourceElement);
    registerComponentIfNecessary(beanDefinition, parserContext); // 注册组件
}
```

```java
@Nullable
public static BeanDefinition registerAspectJAutoProxyCreatorIfNecessary(
    BeanDefinitionRegistry registry, @Nullable Object source) {

    return registerOrEscalateApcAsRequired(AspectJAwareAdvisorAutoProxyCreator.class, registry, source);
}
```

**AspectJAwareAdvisorAutoProxyCreator** 实现了 **BeanPostProcessor** 等上面介绍的接口，主要作用于Bean初始化前后，实例化前后，所有的Bean都被作用到。**InstantiationAwareBeanPostProcessor** 是 **BeanPostProcessor**的子接口，但它的调用时间点发生在Bean实例化前，在真正调用doCreateBean()创建bean实例之前执行postProcessBeforeInstantiation()。

AbstractAutoProxyCreator.java

```java
@Override
public Object postProcessBeforeInstantiation(Class<?> beanClass, String beanName) throws BeansException {
    Object cacheKey = getCacheKey(beanClass, beanName);　　// 得到一个缓存的唯一key（根据beanClass和beanName生成唯一key）
    // 如果当前targetSourcedBeans（通过自定义TargetSourceCreator创建的TargetSource）不包含cacheKey
    if (!StringUtils.hasLength(beanName) || !this.targetSourcedBeans.contains(beanName)) {
        if (this.advisedBeans.containsKey(cacheKey)) {　　//advisedBeans（已经被增强的Bean，即AOP代理对象）中包含当前cacheKey，返回null，即走Spring默认流程
            return null;
        }
        if (isInfrastructureClass(beanClass) || shouldSkip(beanClass, beanName)) {// 如果是基础设施类（如Advisor、Advice、AopInfrastructureBean的实现）不进行处理;（略）
            this.advisedBeans.put(cacheKey, Boolean.FALSE);
            return null;
        }
    }

    // 如果有自定义的TargetSource，在此处创建代理
    // 禁止目标Bean的不必要的默认实例化：
    // TargetSource将以自定义方式处理目标实例。
    TargetSource targetSource = getCustomTargetSource(beanClass, beanName);
    if (targetSource != null) {
        if (StringUtils.hasLength(beanName)) {
            this.targetSourcedBeans.add(beanName);
        }
        Object[] specificInterceptors = getAdvicesAndAdvisorsForBean(beanClass, beanName, targetSource);
        Object proxy = createProxy(beanClass, beanName, specificInterceptors, targetSource);
        this.proxyTypes.put(cacheKey, proxy.getClass());
        return proxy;
    }

    return null;
}
```

通过 AbstractAutoProxyCreator 中的 postProcessAfterInitialization() 创建AOP代理。

```java
@Override
public Object postProcessAfterInitialization(@Nullable Object bean, String beanName) throws BeansException {
    if (bean != null) {
        Object cacheKey = getCacheKey(bean.getClass(), beanName);
        if (!this.earlyProxyReferences.contains(cacheKey)) {　　// 如果之前调用过getEarlyBeanReference获取包装目标对象到AOP代理对象（如果需要），则不再执行
            return wrapIfNecessary(bean, beanName, cacheKey);　　// 包装目标对象到AOP代理对象（如果需要）
        }
    }
    return bean;
}

protected Object wrapIfNecessary(Object bean, String beanName, Object cacheKey) {
    if (StringUtils.hasLength(beanName) && this.targetSourcedBeans.contains(beanName)) { // 通过TargetSourceCreator进行自定义TargetSource不需要包装
        return bean;
    }
    if (Boolean.FALSE.equals(this.advisedBeans.get(cacheKey))) {　　// 不应该被增强对象不需要包装
        return bean;
    }
    if (isInfrastructureClass(bean.getClass()) || shouldSkip(bean.getClass(), beanName)) { // 基础设施或应该skip的不需要保证
        this.advisedBeans.put(cacheKey, Boolean.FALSE);
        return bean;
    }

    // 如果有advise则创建代理。
    Object[] specificInterceptors = getAdvicesAndAdvisorsForBean(bean.getClass(), beanName, null);
    if (specificInterceptors != DO_NOT_PROXY) {
        this.advisedBeans.put(cacheKey, Boolean.TRUE);
        Object proxy = createProxy(
            bean.getClass(), beanName, specificInterceptors, new SingletonTargetSource(bean)); // 创建代理对象
        this.proxyTypes.put(cacheKey, proxy.getClass());
        return proxy;
    }

    this.advisedBeans.put(cacheKey, Boolean.FALSE);
    return bean;
}
```

**好了，今天就到这儿吧，我是冰河，我们下期见~~**

## 冰河原创PDF

关注 **冰河技术** 微信公众号：

回复 “**并发编程**” 领取《深入理解高并发编程（第1版）》PDF文档。

回复 “**并发源码**” 领取《并发编程核心知识（源码分析篇 第1版）》PDF文档。

回复 ”**限流**“ 领取《亿级流量下的分布式解决方案》PDF文档。

回复 “**设计模式**” 领取《深入浅出Java23种设计模式》PDF文档。

回复 “**Java8新特性**” 领取 《Java8新特性教程》PDF文档。

回复 “**分布式存储**” 领取《跟冰河学习分布式存储技术》 PDF文档。

回复 “**Nginx**” 领取《跟冰河学习Nginx技术》PDF文档。

回复 “**互联网工程**” 领取《跟冰河学习互联网工程技术》PDF文档。

## 重磅福利

微信搜一搜【冰河技术】微信公众号，关注这个有深度的程序员，每天阅读超硬核技术干货，公众号内回复【PDF】有我准备的一线大厂面试资料和我原创的超硬核PDF技术文档，以及我为大家精心准备的多套简历模板（不断更新中），希望大家都能找到心仪的工作，学习是一条时而郁郁寡欢，时而开怀大笑的路，加油。如果你通过努力成功进入到了心仪的公司，一定不要懈怠放松，职场成长和新技术学习一样，不进则退。如果有幸我们江湖再见！       

另外，我开源的各个PDF，后续我都会持续更新和维护，感谢大家长期以来对冰河的支持！！

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)