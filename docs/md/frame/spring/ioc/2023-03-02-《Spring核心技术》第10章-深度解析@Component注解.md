---
layout: post
category: binghe-code-spring
title: 第10章：深度解析@Component注解（含@Repository、@Service和@Controller）
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第10章：深度解析@Component注解（含@Repository、@Service和@Controller）
lock: need
---

# 《Spring核心技术》第10章：深度解析@Component注解（含@Repository、@Service和@Controller）

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-10](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-10)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Component注解向IOC容器中注入Bean的案例和流程，从源码级别彻底掌握@Component注解在Spring底层的执行流程。

------

本节目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`Spring中的@Component注解，你真的彻底了解过吗？`

@Component注解可以说是Spring中使用的比较频繁的一个注解了。在项目开发过程中，我们自己编写的类如果想注入到Spring中，由Spring来管理Bean的生命周期，就可以使用@Component注解将其注入到IOC容器中。并且@Component注解还有三个衍生注解，那就是@Repository、@Service和@Controller注解，并且衍生出的注解通常会在使用MVC架构开发项目时，标注到MVC架构的分层类上。比如：@Repository通常会被标注到表示dao层的类上，@Service注解通常会被标注到表示Service层的类上，而@Controller注解通常会被标注到表示Controller层的类上。

## 二、注解说明

`关于@Component注解的一点点说明~~`

使用Spring开发项目时，如果类上标注了@Component注解，当启动IOC容器时，Spring扫描到标注了@Component注解的单例Bean，就会创建对应的Bean对象并注入到IOC容器中。

### 2.1 注解源码

IOC容器在启动时，如果扫描到被标注了@Component注解的类，则会将这些类的类定义信息自动注入IOC容器，并创建这些类的对象。

@Component注解的源码详见：org.springframework.stereotype.Component。

```java
/**
 * @author Mark Fisher
 * @since 2.5
 * @see Repository
 * @see Service
 * @see Controller
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Indexed
public @interface Component {
	String value() default "";
}
```

从源码可以看出，@Component注解是从Spring2.5版本开始提供的注解，并且@Component注解只能标注到类上。其中只含有一个String类型的value属性，具体含义如下所示。

* value：用于指定注入容器时Bean的id。如果没有指定Bean的id，默认值为当前类的名称。

@Component注解提供了三个衍生注解：分别是：@Repository、@Service和@Controller注解。

（1）@Repository注解

@Repository注解的源码详见：org.springframework.stereotype.Repository。

```java
/**
 * @author Rod Johnson
 * @author Juergen Hoeller
 * @since 2.0
 * @see Component
 * @see Service
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Component
public @interface Repository {
	@AliasFor(annotation = Component.class)
	String value() default "";
}
```

（2）@Service注解

@Service注解的源码详见：org.springframework.stereotype.Service。

```java
/**
 * @author Juergen Hoeller
 * @since 2.5
 * @see Component
 * @see Repository
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Component
public @interface Service {
	@AliasFor(annotation = Component.class)
	String value() default "";

}
```

（3）@Controller注解

@Controller注解注解的源码详见：org.springframework.stereotype.Controller。

```java
/**
 * @author Arjen Poutsma
 * @author Juergen Hoeller
 * @since 2.5
 * @see Component
 * @see org.springframework.web.bind.annotation.RequestMapping
 * @see org.springframework.context.annotation.ClassPathBeanDefinitionScanner
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Component
public @interface Controller {
	@AliasFor(annotation = Component.class)
	String value() default "";
}
```

可以看到，@Repository、@Service和@Controller注解本质上还是@Component注解，这里不再赘述。

### 2.2 使用场景

在Spring开发项目的过程中，如果需要将自己创建的类注入到IOC容器中，就可以使用@Component注解，也可以使用@Repository、@Service和@Controller注解。其中，@Component注解一般会被标注到非三层（非MVC架构）类上，而@Repository、@Service和@Controller注解通常会被标注到三层架构的类上。并且@Repository通常会被标注到表示dao层的类上，@Service注解通常会被标注到表示Service层的类上，而@Controller注解通常会被标注到表示Controller层的类上。

**这里，需要注意的是，基于Spring的注解开发项目时，必须先将类对象交给Spring管理，然后Spring会处理类中的属性和方法。如果类没有被Spring接管，那么类里面的属性和方法上的注解都不会被解析。**

## 三、使用案例

`@Component的实现案例，我们一起实现吧~~`

本节，就基于@Component注解、@Repository、@Service和@Controller注解实现简单的案例程序，观察被上述四个注解标注的类是否注入到IOC容器中。具体实现步骤如下所示。

**（1）新建ComponentBean类**

ComponentBean类的源码详见：spring-annotation-chapter-10工程下的io.binghe.spring.annotation.chapter10.component.ComponentBean。

```java
@Component
public class ComponentBean {
}
```

可以看到，ComponentBean就是一个标注了@Component注解的普通类。

**（2）新建RepositoryBean类**

RepositoryBean类的源码详见：spring-annotation-chapter-10工程下的io.binghe.spring.annotation.chapter10.component.RepositoryBean。

```java
@Repository
public class RepositoryBean {
}
```

可以看到，RepositoryBean类就是一个标注了@Repository注解的普通类。

**（3）新建ServiceBean类**

ServiceBean类的源码详见：spring-annotation-chapter-10工程下的io.binghe.spring.annotation.chapter10.component.ServiceBean。

```java
@Service
public class ServiceBean {
}
```

可以看到，ServiceBean类就是一个标注了@Service注解的普通类。

**（4）新建ControllerBean类**

ControllerBean类的源码详见：spring-annotation-chapter-10工程下的io.binghe.spring.annotation.chapter10.component.ControllerBean。

```java
@Controller
public class ControllerBean {
}
```

可以看到，ControllerBean类就是一个标注了@Controller注解的普通类。

**（5）新建ComponentConfig类**

ComponentConfig类的源码详见：spring-annotation-chapter-10工程下的io.binghe.spring.annotation.chapter10.config.ComponentConfig。

```java
@Configuration
@ComponentScan(value = {"io.binghe.spring.annotation.chapter10"})
public class ComponentConfig {
}
```

可以看到，ComponentConfig类上标注了@Configuration，说明ComponentConfig类是一个Spring的配置类，并且使用@ComponentScan注解指定了扫描的包名是io.binghe.spring.annotation.chapter10。

**（6）新建ComponentTest类**

ComponentTest类的源码详见：spring-annotation-chapter-10工程下的io.binghe.spring.annotation.chapter10.ComponentTest。

```java
public class ComponentTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ComponentConfig.class);
        String[] definitionNames = context.getBeanDefinitionNames();
        Arrays.stream(definitionNames).forEach((definitionName) -> System.out.println(definitionName));
    }
}
```

可以看到，在ComponentTest类的main()方法中打印了IOC容器中注入的Bean对象的名称。

**（7）运行ComponentTest类**

运行ComponentTest类的main()方法，输出的结果信息如下所示。

```java
org.springframework.context.annotation.internalConfigurationAnnotationProcessor
org.springframework.context.annotation.internalAutowiredAnnotationProcessor
org.springframework.context.event.internalEventListenerProcessor
org.springframework.context.event.internalEventListenerFactory
componentConfig
componentBean
controllerBean
repositoryBean
serviceBean
```

从输出的结果信息可以看出，打印出了被@Component、@Repository、@Service和@Controller注解标注的Bean的名称。

**说明：使用Spring开发项目时，如果Spring扫描到类上标注了@Component、@Repository、@Service和@Controller注解的单例Bean，就会创建对应的Bean对象并注入到IOC容器中。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

本节，就以源码时序图的方式，直观的感受下@Component注解在Spring源码层面的执行流程。@Component注解在Spring源码层面执行的时序图如图10-1~10~3所示。

**注意：@Repository、@Service和@Controller注解本质上还是@Component注解，这里就不再单独分析@Repository、@Service和@Controller注解的执行流程。**

![图10-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-02-001.png)



![图10-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-02-002.png)



![图10-3](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-02-003.png)


由图10-1~10-3可以看出，@Component注解在注册Bean的流程中涉及到ComponentTest类、AnnotationConfigApplicationContext类、AbstractApplicationContext类、PostProcessorRegistrationDelegate类、ConfigurationClassPostProcessor类、ConfigurationClassParser类、SourceClass类、ComponentScanAnnotationParser类、ClassPathBeanDefinitionScanner类、ClassPathScanningCandidateComponentProvider类、AnnotationConfigUtils类、BeanDefinitionReaderUtils类、和DefaultListableBeanFactory类。具体的源码执行细节参见源码解析部分。 

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

本节，主要分析@Component注解在Spring源码层面的执行流程，结合源码执行的时序图，会理解的更加深刻。

**注意：本节的源码分析流程与第9章5.2小节的源码分析流程大体相同，只是多了一个更加细节的分析，这里，只对这些细节点进行详细的分析。所以，本节的源码分析可以结合第9章5.2小节的源码分析共同理解。**

（1）解析AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法

源码详见：org.springframework.context.annotation.AnnotatedBeanDefinitionReader#doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)。

```java
protected final SourceClass doProcessConfigurationClass(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter) throws IOException {
    if (configClass.getMetadata().isAnnotated(Component.class.getName())) {
        processMemberClasses(configClass, sourceClass, filter);
    }
    /**************省略其他代码****************/
    Set<AnnotationAttributes> componentScans = AnnotationConfigUtils.attributesForRepeatable(
        sourceClass.getMetadata(), ComponentScans.class, ComponentScan.class);
    if (!componentScans.isEmpty() &&
        !this.conditionEvaluator.shouldSkip(sourceClass.getMetadata(), ConfigurationPhase.REGISTER_BEAN)) {
        for (AnnotationAttributes componentScan : componentScans) {
            Set<BeanDefinitionHolder> scannedBeanDefinitions = this.componentScanParser.parse(componentScan, sourceClass.getMetadata().getClassName());
            for (BeanDefinitionHolder holder : scannedBeanDefinitions) {
                BeanDefinition bdCand = holder.getBeanDefinition().getOriginatingBeanDefinition();
                if (bdCand == null) {
                    bdCand = holder.getBeanDefinition();
                }
                if (ConfigurationClassUtils.checkConfigurationClassCandidate(bdCand, this.metadataReaderFactory)) {
                    parse(bdCand.getBeanClassName(), holder.getBeanName());
                }
            }
        }
    }
	/**************省略其他代码****************/
    return null;
}
```

可以看到，在AnnotatedBeanDefinitionReader类的doRegisterBean()方法，判断如果本质上是@Component注解（@Repository、@Service和@Controller注解），会调用processMemberClasses()方法处理内部类。

（2）解析ConfigurationClassParser类的processMemberClasses(ConfigurationClass configClass, SourceClass sourceClass,Predicate<String> filter)方法

源码详见：org.springframework.context.annotation.ConfigurationClassParser#processMemberClasses(ConfigurationClass configClass, SourceClass sourceClass,Predicate<String> filter)。

```java
private void processMemberClasses(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter) throws IOException {
    Collection<SourceClass> memberClasses = sourceClass.getMemberClasses();
    /*****************省略其他代码***************/
}
```

可以看到，在processMemberClasses()方法中，会调用sourceClass的getMemberClasses()方法获取SourceClass的集合。

（3）解析SourceClass类的getMemberClasses()方法

源码详见：org.springframework.context.annotation.ConfigurationClassParser.SourceClass#getMemberClasses()。

```java
public Collection<SourceClass> getMemberClasses() throws IOException {
    Object sourceToProcess = this.source;
    if (sourceToProcess instanceof Class<?> sourceClass) {
        try {
            Class<?>[] declaredClasses = sourceClass.getDeclaredClasses();
            List<SourceClass> members = new ArrayList<>(declaredClasses.length);
            for (Class<?> declaredClass : declaredClasses) {
                members.add(asSourceClass(declaredClass, DEFAULT_EXCLUSION_FILTER));
            }
            return members;
        }
        catch (NoClassDefFoundError err) {
            sourceToProcess = metadataReaderFactory.getMetadataReader(sourceClass.getName());
        }
    }
    MetadataReader sourceReader = (MetadataReader) sourceToProcess;
    String[] memberClassNames = sourceReader.getClassMetadata().getMemberClassNames();
    List<SourceClass> members = new ArrayList<>(memberClassNames.length);
    for (String memberClassName : memberClassNames) {
        try {
            members.add(asSourceClass(memberClassName, DEFAULT_EXCLUSION_FILTER));
        }
        catch (IOException ex) {
            if (logger.isDebugEnabled()) {
                logger.debug("Failed to resolve member class [" + memberClassName + "] - not considering it as a configuration class candidate");
            }
        }
    }
    return members;
}
```

getMemberClasses()方法的主要作用就是处理标注了@Component、@Repository、@Service和@Controller注解的类的内部类，因为内部类也有可能会标注这些注解。在getMemberClasses()方法中，利用反射拿到类的内部类，将内部类封装成SourceClass，存放到members集合中并返回。

（4）返回ConfigurationClassParser类的processMemberClasses(ConfigurationClass configClass, SourceClass sourceClass,Predicate<String> filter)方法

此时重点关注如下代码。

```java
private void processMemberClasses(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter) throws IOException {
    /*******************省略其他代码*****************/
    if (!memberClasses.isEmpty()) {
        List<SourceClass> candidates = new ArrayList<>(memberClasses.size());
        for (SourceClass memberClass : memberClasses) {
            if (ConfigurationClassUtils.isConfigurationCandidate(memberClass.getMetadata()) && !memberClass.getMetadata().getClassName().equals(configClass.getMetadata().getClassName())) {
                candidates.add(memberClass);
            }
        }
      /*******************省略其他代码*****************/
    }
}
```

可以看到，在ConfigurationClassParser类的processMemberClasses()方法中，如果获取到的内部类集合memberClasses不为空，则遍历获取到的memberClasses集合，使用ConfigurationClassUtils类的isConfigurationCandidate()方法判断内部类上是否有需要处理的注解，如果有需要处理的注解，则将类添加到candidates集合中。

（5）解析ConfigurationClassUtils类的isConfigurationCandidate(AnnotationMetadata metadata)方法

源码详见：org.springframework.context.annotation.ConfigurationClassUtils#isConfigurationCandidate(AnnotationMetadata metadata)。

```java
static boolean isConfigurationCandidate(AnnotationMetadata metadata) {
    if (metadata.isInterface()) {
        return false;
    }
    for (String indicator : candidateIndicators) {
        if (metadata.isAnnotated(indicator)) {
            return true;
        }
    }
    return hasBeanMethods(metadata);
}
```

isConfigurationCandidate()方法的作用主要是判断内部类上面是否有需要处理的注解，具体的判断逻辑是：如果是接口，则直接返回false，如果是@Component（含@Repository、@Service和@Controller）、@ComponentScan、@Import、@ImportResource等注解，则返回true。最后判断方法上是否标注了@Bean注解，如果标注了@Bean注解，则返回true。否则，返回false。

（6）返回ConfigurationClassParser类的processMemberClasses(ConfigurationClass configClass, SourceClass sourceClass,Predicate<String> filter)方法

此时重点关注如下代码。

```java
private void processMemberClasses(ConfigurationClass configClass, SourceClass sourceClass, Predicate<String> filter) throws IOException {
    /**********省略其他代码**************/
    if (!memberClasses.isEmpty()) {
        /**********省略其他代码**************/
        OrderComparator.sort(candidates);
        for (SourceClass candidate : candidates) {
            if (this.importStack.contains(configClass)) {
                this.problemReporter.error(new CircularImportProblem(configClass, this.importStack));
            }
            else {
                this.importStack.push(configClass);
                try {
                    processConfigurationClass(candidate.asConfigClass(configClass), filter);
                }
                finally {
                    this.importStack.pop();
                }
            }
        }
    }
}
```

在processMemberClasses()方法中，首先对获取到的内部类进行排序，随后遍历内部类集合，调用candidate的asConfigClass()方法将内部类封装成ConfigurationClass对象。并传入processConfigurationClass()方法中解析内部类的注解信息。

（7）返回AnnotatedBeanDefinitionReader类的doRegisterBean(Class<T> beanClass, String name, Class<? extends Annotation>[] qualifiers, Supplier<T> supplier, BeanDefinitionCustomizer[] customizers)方法。

继续分析如下代码片段。

```java
Set<BeanDefinitionHolder> scannedBeanDefinitions = this.componentScanParser.parse(componentScan, sourceClass.getMetadata().getClassName());
```

其他分析流程省略，直接来到ClassPathBeanDefinitionScanner类的doScan(String... basePackages)方法。

（8）解析ClassPathBeanDefinitionScanner类的doScan(String... basePackages)方法

源码详见：org.springframework.context.annotation.ClassPathBeanDefinitionScanner#doScan(String... basePackages)。

```java
protected Set<BeanDefinitionHolder> doScan(String... basePackages) {
    Assert.notEmpty(basePackages, "At least one base package must be specified");
    Set<BeanDefinitionHolder> beanDefinitions = new LinkedHashSet<>();
    for (String basePackage : basePackages) {
        Set<BeanDefinition> candidates = findCandidateComponents(basePackage);
        /***************省略其他代码*****************/
    }
    return beanDefinitions;
}
```

可以看到，在ClassPathBeanDefinitionScanner类的doScan()中，会遍历传入的扫描包路径数组，调用findCandidateComponents()方法加载符合一定条件的BeanDefinition。

（9）解析ClassPathScanningCandidateComponentProvider类的findCandidateComponents(String basePackage)方法

源码详见：org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider#findCandidateComponents(String basePackage)

```java
public Set<BeanDefinition> findCandidateComponents(String basePackage) {
    if (this.componentsIndex != null && indexSupportsIncludeFilters()) {
        return addCandidateComponentsFromIndex(this.componentsIndex, basePackage);
    }
    else {
        return scanCandidateComponents(basePackage);
    }
}
```

在findCandidateComponents()方法中，会调用scanCandidateComponents()方法来扫描basePackage包下标注了注解的类。

（10）解析ClassPathScanningCandidateComponentProvider类的scanCandidateComponents(String basePackage)方法

源码详见：org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider#scanCandidateComponents(String basePackage)。

```java
private Set<BeanDefinition> scanCandidateComponents(String basePackage) {
    Set<BeanDefinition> candidates = new LinkedHashSet<>();
    try {
        String packageSearchPath = ResourcePatternResolver.CLASSPATH_ALL_URL_PREFIX +
            resolveBasePackage(basePackage) + '/' + this.resourcePattern;
        Resource[] resources = getResourcePatternResolver().getResources(packageSearchPath);
        boolean traceEnabled = logger.isTraceEnabled();
        boolean debugEnabled = logger.isDebugEnabled();
        for (Resource resource : resources) {
            String filename = resource.getFilename();
            if (filename != null && filename.contains(ClassUtils.CGLIB_CLASS_SEPARATOR)) {
                continue;
            }
            if (traceEnabled) {
                logger.trace("Scanning " + resource);
            }
            try {
                MetadataReader metadataReader = getMetadataReaderFactory().getMetadataReader(resource);
                if (isCandidateComponent(metadataReader)) {
                    ScannedGenericBeanDefinition sbd = new ScannedGenericBeanDefinition(metadataReader);
                    sbd.setSource(resource);
                    if (isCandidateComponent(sbd)) {
                        if (debugEnabled) {
                            logger.debug("Identified candidate component class: " + resource);
                        }
                        candidates.add(sbd);
                    }
                /***************省略其他代码*************/
            }
            catch (FileNotFoundException ex) {
                if (traceEnabled) {
                    logger.trace("Ignored non-readable " + resource + ": " + ex.getMessage());
                }
            }
            catch (Throwable ex) {
                throw new BeanDefinitionStoreException(
                    "Failed to read candidate component class: " + resource, ex);
            }
        }
    }
    catch (IOException ex) {
        throw new BeanDefinitionStoreException("I/O failure during classpath scanning", ex);
    }
    return candidates;
}
```

可以看到，在ClassPathScanningCandidateComponentProvider类的scanCandidateComponents()方法中，会加载basePackage包路径下的资源，将其封装成ScannedGenericBeanDefinition类的对象，并传入isCandidateComponent()方法中对类进行过滤。符合条件时，会将当前ScannedGenericBeanDefinition类的对象存入candidates集合中，最终返回candidates集合。

（11）解析ClassPathScanningCandidateComponentProvider类的isCandidateComponent(MetadataReader metadataReader)方法

源码详见：org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider#isCandidateComponent(MetadataReader metadataReader)。

```java
protected boolean isCandidateComponent(MetadataReader metadataReader) throws IOException {
    for (TypeFilter tf : this.excludeFilters) {
        if (tf.match(metadataReader, getMetadataReaderFactory())) {
            return false;
        }
    }
    for (TypeFilter tf : this.includeFilters) {
        if (tf.match(metadataReader, getMetadataReaderFactory())) {
            return isConditionMatch(metadataReader);
        }
    }
    return false;
}
```

可以看到，在isCandidateComponent()方法中，首先遍历excludeFilters规则列表，如果匹配到excludeFilters规则，则直接返回false。否则，遍历includeFilters规则，如果匹配到includeFilters规则，则调用isConditionMatch()方法来匹配@Conditional注解的规则。

这里，注意的是在IOC容器启动调用AnnotationConfigApplicationContext类的构造方法时，就会对includeFilters规则列表进行初始化。源码详见：org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider#registerDefaultFilters()

```java
protected void registerDefaultFilters() {
    this.includeFilters.add(new AnnotationTypeFilter(Component.class));
    ClassLoader cl = ClassPathScanningCandidateComponentProvider.class.getClassLoader();
    try {
        this.includeFilters.add(new AnnotationTypeFilter(
            ((Class<? extends Annotation>) ClassUtils.forName("jakarta.annotation.ManagedBean", cl)), false));
        logger.trace("JSR-250 'jakarta.annotation.ManagedBean' found and supported for component scanning");
    }
    catch (ClassNotFoundException ex) {
        // JSR-250 1.1 API (as included in Jakarta EE) not available - simply skip.
    }
    try {
        this.includeFilters.add(new AnnotationTypeFilter(
            ((Class<? extends Annotation>) ClassUtils.forName("jakarta.inject.Named", cl)), false));
        logger.trace("JSR-330 'jakarta.inject.Named' annotation found and supported for component scanning");
    }
    catch (ClassNotFoundException ex) {
        // JSR-330 API not available - simply skip.
    }
}
```

可以看到，在registerDefaultFilters()方法中，默认会将@Component注解封装成AnnotationTypeFilter对象并存入includeFilters规则列表中。

（12）返回ClassPathBeanDefinitionScanner类的doScan(String... basePackages)方法

源码详见：org.springframework.context.annotation.ClassPathBeanDefinitionScanner#doScan(String... basePackages)。此时重点关注如下代码片段。

```java
protected Set<BeanDefinitionHolder> doScan(String... basePackages) {
    Assert.notEmpty(basePackages, "At least one base package must be specified");
    Set<BeanDefinitionHolder> beanDefinitions = new LinkedHashSet<>();
    for (String basePackage : basePackages) {
        Set<BeanDefinition> candidates = findCandidateComponents(basePackage);
        for (BeanDefinition candidate : candidates) {
            /***********省略其他代码***********/
            if (candidate instanceof AnnotatedBeanDefinition) {
                AnnotationConfigUtils.processCommonDefinitionAnnotations((AnnotatedBeanDefinition) candidate);
            }
            if (checkCandidate(beanName, candidate)) {
                BeanDefinitionHolder definitionHolder = new BeanDefinitionHolder(candidate, beanName);
                definitionHolder =  AnnotationConfigUtils.applyScopedProxyMode(scopeMetadata, definitionHolder, this.registry);
                beanDefinitions.add(definitionHolder);
                registerBeanDefinition(definitionHolder, this.registry);
            }
        }
    }
    return beanDefinitions;
}
```

后续解析AnnotationConfigUtils类的processCommonDefinitionAnnotations()方法和解析registerBeanDefinition()方法的流程与第9章5.2小节的源码分析流程一致，这里不再赘述。

至此，@Component注解在Spring源码层面的执行流程分析完毕。

## 六、总结

`@Component注解介绍完了，我们一起总结下吧！`

本章，首先介绍了@Component注解的源码和使用场景，随后介绍了@Component注解的使用案例。接下来，详细介绍了@Component在Spring中执行的源码时序图和源码流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Component注解，通常会有如下几个经典面试题：

* @Component注解的作用是什么？
* @Component注解有哪些使用场景？
* @Component注解是如何将Bean注入到IOC容器的？
* @Component注解在Spring内部的执行流程？
* 你在平时工作中，会在哪些场景下使用@Component注解？
* 你从@Component注解的设计中得到了哪些启发？

## 八、VIP服务

**强烈推荐阅读：《[原来大厂面试官也会在这里偷偷学习！](https://mp.weixin.qq.com/s/Zp0nI2RyFb_UCYpSsUt2OQ)》，如果文中优惠券过期，可长按或扫码下面优惠券二维码加入星球。**

<div align="center">
    <img src="https://binghe.gitcode.host/assets/images/microservices/springcloudalibaba/sa-2022-04-18-008.png?raw=true" width="70%">
    <div style="font-size: 18px;">星球优惠券</div>
    <br/>
</div>

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