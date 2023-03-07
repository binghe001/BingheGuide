---
layout: post
category: binghe-code-spring
title: 第12章：深度解析@Autowired注解
tagline: by 冰河
tag: [spring,ioc,aop,transaction,springmvc]
excerpt: 第12章：深度解析@Autowired注解
lock: need
---

# 《Spring核心技术》第12章：深度解析@Autowired注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-12](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-12)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Autowired注解向Bean中注入值的案例和流程，从源码级别彻底掌握@Autowired注解在Spring底层的执行流程。

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

`Spring中的@Autowired注解，你真的彻底了解过吗？`

@Autowired注解可以说是Spring当中使用的非常频繁的一个注解，我们自己写的类如果需要注入IOC容器，就可以使用@Autowired注解进行注入。本章，就简单介绍下@Autowired注解。

## 二、注解说明

`关于@Autowired注解的一点点说明~~`

@Autowired注解能够自动按照类型注入。当IOC容器中有且仅有一个类型匹配时，使用@Autowired注解可以直接注入成功。当超过一个类型匹配时，则使用变量名称（写在方法上就是方法名称）作为Bean的id，在符合类型的多个Bean中再次进行匹配，如果能匹配上就可以注入成功。如果匹配不上，是否报错要看required属性的取值。

### 2.1 注解源码

@Autowired注解的源码详见：org.springframework.beans.factory.annotation.Autowired。

```java
/**
 * @author Juergen Hoeller
 * @author Mark Fisher
 * @author Sam Brannen
 * @since 2.5
 * @see AutowiredAnnotationBeanPostProcessor
 * @see Qualifier
 * @see Value
 */
@Target({ElementType.CONSTRUCTOR, ElementType.METHOD, ElementType.PARAMETER, ElementType.FIELD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Autowired {
	boolean required() default true;
}
```

从源码可以看出，@Autowired注解是从Spring 2.5版本开始提供的注解，可以标注到构造方法、方法、参数、字段和其他注解上。在@Autowired注解中，只提供了一个boolean类型的required属性。具体含义如下所示。

* required：表示是否必须注入成功，取值为true或false。默认值是true，表示必须注入成功。当取值为true时，注入不成功会报错，否则，注入不成功不会报错。

### 2.2 使用场景

在实际开发中@Autowired注解的应用非常广泛。在开发过程中，将我们自己写的类注入到另一个类的字段、方法参数、方法、构造方法时，就可以使用@Autowired注解。

## 三、使用案例

`@Autowired的实现案例，我们一起实现吧~~`

本节，就基于@Autowired注解实现向Bean属性中赋值的案例，具体的实现步骤如下所示。

**（1）新增AutowiredDao类**

AutowiredDao的源码详见：spring-annotation-chapter-12工程下的io.binghe.spring.annotation.chapter12.dao.AutowiredDao。

```java
@Repository
public class AutowiredDao {
}
```

可以看到，AutowiredDao类模拟的是dao层的代码，在类上标注了@Repository注解。

**（2）新增AutowiredService类**

AutowiredService类的源码详见：spring-annotation-chapter-12工程下的io.binghe.spring.annotation.chapter12.service.AutowiredService。

```java
@Service
public class AutowiredService {
    @Autowired
    private AutowiredDao autowiredDao;
    @Override
    public String toString() {
        return "AutowiredService{" +
                "autowiredDao=" + autowiredDao +
                '}';
    }
}
```

可以看到，AutowiredService类模拟的是service层的代码，并且在类上标注了@Service注解。在AutowiredService类中，使用@Autowired注解注入了AutowiredDao类的Bean对象。

**（3）新增AutowiredConfig类**

AutowiredConfig类的源码详见：spring-annotation-chapter-12工程下的io.binghe.spring.annotation.chapter12.config.AutowiredConfig。

```java
@Configuration
@ComponentScan(value = {"io.binghe.spring.annotation.chapter12"})
public class AutowiredConfig {
}
```

可以看到，AutowiredConfig类表示Spring的配置类，在AutowiredConfig类上标注了@Configuration注解，并且使用@ComponentScan注解指定了扫描的基础包名为io.binghe.spring.annotation.chapter12。

**（4）新增AutowiredTest类**

AutowiredTest类的源码详见：spring-annotation-chapter-12工程下的io.binghe.spring.annotation.chapter12.AutowiredTest。

```java
public class AutowiredTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AutowiredConfig.class);
        AutowiredDao autowiredDao = context.getBean(AutowiredDao.class);
        System.out.println("autowiredDao===>>>" + autowiredDao);
        AutowiredService autowiredService = context.getBean(AutowiredService.class);
        System.out.println("autowiredService=>>>" + autowiredService);
    }
}
```

可以看到，在AutowiredTest类的main()方法中，会从IOC容器中获取AutowiredDao类的Bean对象并打印，并且从IOC容器中获取AutowiredService类的Bean对象并打印。

**（5）运行AutowiredTest类**

运行AutowiredTest类的main()方法，输出的结果信息如下所示。

```bash
autowiredDao===>>>io.binghe.spring.annotation.chapter12.dao.AutowiredDao@1ba9117e
autowiredService=>>>AutowiredService{autowiredDao=io.binghe.spring.annotation.chapter12.dao.AutowiredDao@1ba9117e}
```

可以看到，打印了从IOC容器中获取到的AutowiredDao类的Bean对象和AutowiredService类的Bean对象，并且向AutowiredService类中注入的AutowiredDao类的Bean对象和直接从IOC容器中获取的AutowiredDao类的Bean对象是同一个对象。

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

注意：本章也可以从解析并获取 @Autowired修饰的属性、为 @Autowired修饰属性赋值和使用@Autowired获取属性值三个方面分析源码时序图。获取 @Autowired修饰的属性、为 @Autowired修饰属性赋值的源码时序图基本与@Value注解相同，使用@Autowired注解获取属性值的源码时序图略有差异。使用@Autowired注解获取属性值的源码时序图如图12-1~12-2所示。

![图12-1](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-06-001.png)



![图12-2](https://binghe.gitcode.host/assets/images/frame/spring/ioc/spring-core-2023-03-06-002.png)

## 五、源码解析

`源码时序图整清楚了，那就整源码解析呗！`

注意：本章也可以从解析并获取 @Autowired修饰的属性、为 @Autowired修饰属性赋值和使用@Autowired获取属性值三个方面分析源码的执行流程。其中，解析并获取 @Autowired修饰的属性、为 @Autowired修饰属性赋值的源码流程基本与@Value相同，只是使用@Autowired获取属性值的源码流程略有差异。使用@Autowired获取属性值的源码流程具体分析步骤如下所示。

（1）直接来到AutowiredAnnotationBeanPostProcessor类的inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs)方法。

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

可以看到，在AutowiredAnnotationBeanPostProcessor类的inject()方法中，会调用resolveFieldValue()方法处理字段的值，

（2）解析AutowiredFieldElement类的resolveFieldValue(Field field, Object bean, @Nullable String beanName)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.AutowiredFieldElement#resolveFieldValue(Field field, Object bean, @Nullable String beanName)。

```java
@Nullable
private Object resolveFieldValue(Field field, Object bean, @Nullable String beanName) {
    DependencyDescriptor desc = new DependencyDescriptor(field, this.required);
    desc.setContainingClass(bean.getClass());
    Set<String> autowiredBeanNames = new LinkedHashSet<>(1);
    Assert.state(beanFactory != null, "No BeanFactory available");
    TypeConverter typeConverter = beanFactory.getTypeConverter();
    Object value;
    try {
        value = beanFactory.resolveDependency(desc, beanName, autowiredBeanNames, typeConverter);
    }
    catch (BeansException ex) {
        throw new UnsatisfiedDependencyException(null, beanName, new InjectionPoint(field), ex);
    }
    /************省略其他代码*************/
    return value;
}
```

可以看到，在resolveFieldValue()方法中，会调用beanFactory对象的resolveDependency()方法处理Bean的依赖。

（3）解析DefaultListableBeanFactory类的resolveDependency(DependencyDescriptor descriptor, @Nullable String requestingBeanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#resolveDependency(DependencyDescriptor descriptor, @Nullable String requestingBeanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)。

```java
@Override
@Nullable
public Object resolveDependency(DependencyDescriptor descriptor, @Nullable String requestingBeanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter) throws BeansException {
    /**********省略其他代码***********/
    else {
        Object result = getAutowireCandidateResolver().getLazyResolutionProxyIfNecessary(
            descriptor, requestingBeanName);
        if (result == null) {
            result = doResolveDependency(descriptor, requestingBeanName, autowiredBeanNames, typeConverter);
        }
        return result;
    }
}
```

可以看到，在DefaultListableBeanFactory类的resolveDependency()方法中，调用了doResolveDependency()方法来处理Bean的依赖。

（4）解析DefaultListableBeanFactory类的doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)。重点关注如下代码.

```java
@Nullable
public Object doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName,  @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter) throws BeansException {

    InjectionPoint previousInjectionPoint = ConstructorResolver.setCurrentInjectionPoint(descriptor);
    try {
        Object shortcut = descriptor.resolveShortcut(this);
        if (shortcut != null) {
            return shortcut;
        }

        Class<?> type = descriptor.getDependencyType();
        Object value = getAutowireCandidateResolver().getSuggestedValue(descriptor);
        if (value != null) {
            if (value instanceof String strValue) {
                String resolvedValue = resolveEmbeddedValue(strValue);
                BeanDefinition bd = (beanName != null && containsBean(beanName) ? getMergedBeanDefinition(beanName) : null);
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

        Object multipleBeans = resolveMultipleBeans(descriptor, beanName, autowiredBeanNames, typeConverter);
        if (multipleBeans != null) {
            return multipleBeans;
        }

        Map<String, Object> matchingBeans = findAutowireCandidates(beanName, type, descriptor);
        if (matchingBeans.isEmpty()) {
            if (isRequired(descriptor)) {
                raiseNoMatchingBeanFound(type, descriptor.getResolvableType(), descriptor);
            }
            return null;
        }
		/************省略其他代码**************/
}
```

可以看到，在DefaultListableBeanFactory类的doResolveDependency()方法中，调用了findAutowireCandidates()方法来查找符合条件的被@Autowired注解注入的Bean。

（5）解析DefaultListableBeanFactory类的findAutowireCandidates(@Nullable String beanName, Class<?> requiredType, DependencyDescriptor descriptor)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#findAutowireCandidates(@Nullable String beanName, Class<?> requiredType, DependencyDescriptor descriptor)。重点关注如下代码。

```java
protected Map<String, Object> findAutowireCandidates(@Nullable String beanName, Class<?> requiredType, DependencyDescriptor descriptor) {
    /***********省略其他代码***********/
    for (String candidate : candidateNames) {
        if (!isSelfReference(beanName, candidate) && isAutowireCandidate(candidate, descriptor)) {
            addCandidateEntry(result, candidate, descriptor, requiredType);
        }
    }
    if (result.isEmpty()) {
        boolean multiple = indicatesMultipleBeans(requiredType);
        DependencyDescriptor fallbackDescriptor = descriptor.forFallbackMatch();
        for (String candidate : candidateNames) {
            if (!isSelfReference(beanName, candidate) && isAutowireCandidate(candidate, fallbackDescriptor) && (!multiple || getAutowireCandidateResolver().hasQualifier(descriptor))) {
                addCandidateEntry(result, candidate, descriptor, requiredType);
            }
        }
        if (result.isEmpty() && !multiple) {
            for (String candidate : candidateNames) {
                if (isSelfReference(beanName, candidate) &&
                    (!(descriptor instanceof MultiElementDescriptor) || !beanName.equals(candidate)) &&
                    isAutowireCandidate(candidate, fallbackDescriptor)) {
                    addCandidateEntry(result, candidate, descriptor, requiredType);
                }
            }
        }
    }
    return result;
}
```

可以看到，在DefaultListableBeanFactory类的findAutowireCandidates()的方法中，会调用isAutowireCandidate()方法判断是否要注入的Bean。

（6）解析DefaultListableBeanFactory类的isAutowireCandidate(String beanName, DependencyDescriptor descriptor)方法。

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#isAutowireCandidate(String beanName, DependencyDescriptor descriptor)。

```java
@Override
public boolean isAutowireCandidate(String beanName, DependencyDescriptor descriptor) throws NoSuchBeanDefinitionException {
    return isAutowireCandidate(beanName, descriptor, getAutowireCandidateResolver());
}
```

可以看到，在DefaultListableBeanFactory类的isAutowireCandidate()方法中调用了一个重载的isAutowireCandidate()方法。

（7）解析DefaultListableBeanFactory类的isAutowireCandidate(String beanName, DependencyDescriptor descriptor, AutowireCandidateResolver resolver)。

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#isAutowireCandidate(String beanName, DependencyDescriptor descriptor, AutowireCandidateResolver resolver)。

```java
protected boolean isAutowireCandidate( String beanName, DependencyDescriptor descriptor, AutowireCandidateResolver resolver) throws NoSuchBeanDefinitionException {
    String bdName = BeanFactoryUtils.transformedBeanName(beanName);
    if (containsBeanDefinition(bdName)) {
        return isAutowireCandidate(beanName, getMergedLocalBeanDefinition(bdName), descriptor, resolver);
    }
    else if (containsSingleton(beanName)) {
        return isAutowireCandidate(beanName, new RootBeanDefinition(getType(beanName)), descriptor, resolver);
    }
	/**********省略其他代码***********/
}
```

可以看到，在重载的isAutowireCandidate()方法中，还会调用另一个重载的isAutowireCandidate()方法。

（9）解析DefaultListableBeanFactory类的isAutowireCandidate(String beanName, RootBeanDefinition mbd,  DependencyDescriptor descriptor, AutowireCandidateResolver resolver)方法

源码详见：org.springframework.beans.factory.support.DefaultListableBeanFactory#isAutowireCandidate(String beanName, RootBeanDefinition mbd,  DependencyDescriptor descriptor, AutowireCandidateResolver resolver)。

```java
protected boolean isAutowireCandidate(String beanName, RootBeanDefinition mbd, DependencyDescriptor descriptor, AutowireCandidateResolver resolver) {
    /***********省略其他代码************/
    return resolver.isAutowireCandidate(holder, descriptor);
}
```

可以看到，在DefaultListableBeanFactory类的isAutowireCandidate()方法中，会调用resolver对象的isAutowireCandidate()方法。

（10）解析QualifierAnnotationAutowireCandidateResolver类的isAutowireCandidate(BeanDefinitionHolder bdHolder, DependencyDescriptor descriptor)方法

源码详见：org.springframework.beans.factory.annotation.QualifierAnnotationAutowireCandidateResolver#isAutowireCandidate(BeanDefinitionHolder bdHolder, DependencyDescriptor descriptor)。

```java
@Override
public boolean isAutowireCandidate(BeanDefinitionHolder bdHolder, DependencyDescriptor descriptor) {
    boolean match = super.isAutowireCandidate(bdHolder, descriptor);
    if (match) {
        match = checkQualifiers(bdHolder, descriptor.getAnnotations());
        if (match) {
            MethodParameter methodParam = descriptor.getMethodParameter();
            if (methodParam != null) {
                Method method = methodParam.getMethod();
                if (method == null || void.class == method.getReturnType()) {
                    match = checkQualifiers(bdHolder, methodParam.getMethodAnnotations());
                }
            }
        }
    }
    return match;
}
```

可以看到，在QualifierAnnotationAutowireCandidateResolver类的isAutowireCandidate()方法中，会调用checkQualifiers()方法来检验是否标注了@Qualifier注解，并注入@Qualifier注解指定的Bean。

（11）QualifierAnnotationAutowireCandidateResolver类的checkQualifiers(BeanDefinitionHolder bdHolder, Annotation[] annotationsToSearch)方法

源码详见：org.springframework.beans.factory.annotation.QualifierAnnotationAutowireCandidateResolver#checkQualifiers(BeanDefinitionHolder bdHolder, Annotation[] annotationsToSearch)。

```java
protected boolean checkQualifiers(BeanDefinitionHolder bdHolder, Annotation[] annotationsToSearch) {
    if (ObjectUtils.isEmpty(annotationsToSearch)) {
        return true;
    }
    SimpleTypeConverter typeConverter = new SimpleTypeConverter();
    for (Annotation annotation : annotationsToSearch) {
        Class<? extends Annotation> type = annotation.annotationType();
        boolean checkMeta = true;
        boolean fallbackToMeta = false;
        if (isQualifier(type)) {
            if (!checkQualifier(bdHolder, annotation, typeConverter)) {
                fallbackToMeta = true;
            }
            else {
                checkMeta = false;
            }
        }
        if (checkMeta) {
            boolean foundMeta = false;
            for (Annotation metaAnn : type.getAnnotations()) {
                Class<? extends Annotation> metaType = metaAnn.annotationType();
                if (isQualifier(metaType)) {
                    foundMeta = true;
                    if ((fallbackToMeta && ObjectUtils.isEmpty(AnnotationUtils.getValue(metaAnn))) ||
                        !checkQualifier(bdHolder, metaAnn, typeConverter)) {
                        return false;
                    }
                }
            }
            if (fallbackToMeta && !foundMeta) {
                return false;
            }
        }
    }
    return true;
}
```

QualifierAnnotationAutowireCandidateResolver类的checkQualifiers()方法主要处理@Qualifier注解，向类的字段中注入@Qualifier注解指定的Bean。

（12）返回DefaultListableBeanFactory类的doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName, @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter)方法

此时重点关注如下代码片段。

```java
@Nullable
public Object doResolveDependency(DependencyDescriptor descriptor, @Nullable String beanName,  @Nullable Set<String> autowiredBeanNames, @Nullable TypeConverter typeConverter) throws BeansException {
    InjectionPoint previousInjectionPoint = ConstructorResolver.setCurrentInjectionPoint(descriptor);
    try {
        /*************省略*************/
        String autowiredBeanName;
        Object instanceCandidate;

        if (matchingBeans.size() > 1) {
            autowiredBeanName = determineAutowireCandidate(matchingBeans, descriptor);
            if (autowiredBeanName == null) {
                if (isRequired(descriptor) || !indicatesMultipleBeans(type)) {
                    return descriptor.resolveNotUnique(descriptor.getResolvableType(), matchingBeans);
                }
                else {
                    return null;
                }
            }
            instanceCandidate = matchingBeans.get(autowiredBeanName);
        }
        else {
            // We have exactly one match.
            Map.Entry<String, Object> entry = matchingBeans.entrySet().iterator().next();
            autowiredBeanName = entry.getKey();
            instanceCandidate = entry.getValue();
        }

        if (autowiredBeanNames != null) {
            autowiredBeanNames.add(autowiredBeanName);
        }
        if (instanceCandidate instanceof Class) {
            instanceCandidate = descriptor.resolveCandidate(autowiredBeanName, type, this);
        }
        Object result = instanceCandidate;
        if (result instanceof NullBean) {
            if (isRequired(descriptor)) {
                raiseNoMatchingBeanFound(type, descriptor.getResolvableType(), descriptor);
            }
            result = null;
        }
        if (!ClassUtils.isAssignableValue(type, result)) {
            throw new BeanNotOfRequiredTypeException(autowiredBeanName, type, instanceCandidate.getClass());
        }
        return result;
    }
    finally {
        ConstructorResolver.setCurrentInjectionPoint(previousInjectionPoint);
    }
}
```

可以看到，DefaultListableBeanFactory类的doResolveDependency()方法中会根据findAutowireCandidates()方法的返回结果，解析出要向类的字段中注入的Bean对象并返回。

（13）返回AutowiredFieldElement类的resolveFieldValue(Field field, Object bean, @Nullable String beanName)方法

源码详见：org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.AutowiredFieldElement#resolveFieldValue(Field field, Object bean, @Nullable String beanName)。此时重点关注如下代码。

```java
@Nullable
private Object resolveFieldValue(Field field, Object bean, @Nullable String beanName) {
   /**********省略其他代码************/
    synchronized (this) {
        if (!this.cached) {
            Object cachedFieldValue = null;
            if (value != null || this.required) {
                cachedFieldValue = desc;
                registerDependentBeans(beanName, autowiredBeanNames);
                if (autowiredBeanNames.size() == 1) {
                    String autowiredBeanName = autowiredBeanNames.iterator().next();
                    if (beanFactory.containsBean(autowiredBeanName) &&  beanFactory.isTypeMatch(autowiredBeanName, field.getType())) {
                        cachedFieldValue = new ShortcutDependencyDescriptor( desc, autowiredBeanName, field.getType());
                    }
                }
            }
            this.cachedFieldValue = cachedFieldValue;
            this.cached = true;
        }
    }
    return value;
}
```

可以看到，在AutowiredFieldElement类的resolveFieldValue()方法中，会将通过beanFactory对象的resolveDependency()方法解析出的Bean注入到IOC容器中，并返回解析的Bean。

（14）返回AutowiredAnnotationBeanPostProcessor类的inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs)方法。重点关注如下代码。

```java
@Override
protected void inject(Object bean, @Nullable String beanName, @Nullable PropertyValues pvs) throws Throwable {
    /*********省略其他代码***********/
    if (value != null) {
        ReflectionUtils.makeAccessible(field);
        field.set(bean, value);
    }
}
```

可以看到，在AutowiredAnnotationBeanPostProcessor类的inject()方法中，将获取到的依赖Bean会设置到对应的字段上。

至此，@Autowired注解的源码流程执行完毕。

## 六、总结

`@Autowired注解介绍完了，我们一起总结下吧！`

本章，主要对Spring中的@Autowired注解进行了简单的介绍。首先，介绍了@Autowired注解的源码和使用场景，随后便给出了@Autowired注解的使用案例。由于@Autowired注解的源码时序图和源码流程与第11章中@Value注解的源码时序图和源码流程基本相同，本章不再赘述，小伙伴们可以按照第11章中的源码时序图和源码流程来分析@Autowired注解在Spring底层的执行流程。

## 七、思考

`既然学完了，就开始思考几个问题吧？`

关于@Autowired注解，通常会有如下几个经典面试题：

* @Autowired注解的作用是什么？
* @Autowired注解有哪些使用场景？
* @Autowired向Bean的字段和方法注入值是如何实现的？
* @Autowired注解在Spring内部的执行流程？
* @Autowired注解在Spring源码中的执行流程与@Autowired注解有何区别？
* 你在平时工作中，会在哪些场景下使用@Autowired注解？
* 你从@Autowired注解的设计中得到了哪些启发？

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

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
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





