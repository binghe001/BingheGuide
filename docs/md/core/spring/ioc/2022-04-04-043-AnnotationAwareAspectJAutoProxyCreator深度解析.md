---
layout: post
category: binghe-spring-ioc
title: AnnotationAwareAspectJAutoProxyCreator深度解析
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在《Spring注解驱动开发》系列中的《[Spring中这么重要的AnnotationAwareAspectJAutoProxyCreator类是干嘛的？](https://binghe.blog.csdn.net/article/details/114650073)》一文中，我们简单分析了AnnotationAwareAspectJAutoProxyCreator类的作用，接下来，我们就以debug的方式来深入分析AnnotationAwareAspectJAutoProxyCreator的执行流程。同样的，我们还是以debug的形式来分析AnnotationAwareAspectJAutoProxyCreator类的执行流程，在`io.mykit.spring.plugins.register.config`包下创建AopConfig类，然后在AopConfig类中创建mathHandler()方法，如下所示。
lock: need
---

# AnnotationAwareAspectJAutoProxyCreator深度解析

**大家好，我是冰河~~**

在《Spring注解驱动开发》系列中的《[Spring中这么重要的AnnotationAwareAspectJAutoProxyCreator类是干嘛的？](https://binghe.blog.csdn.net/article/details/114650073)》一文中，我们简单分析了AnnotationAwareAspectJAutoProxyCreator类的作用，接下来，我们就以debug的方式来深入分析AnnotationAwareAspectJAutoProxyCreator的执行流程。

同样的，我们还是以debug的形式来分析AnnotationAwareAspectJAutoProxyCreator类的执行流程，在`io.mykit.spring.plugins.register.config`包下创建AopConfig类，然后在AopConfig类中创建mathHandler()方法，如下所示。

```java
package io.mykit.spring.plugins.register.config;
import io.mykit.spring.plugins.register.aop.MathHandler;
import io.mykit.spring.plugins.register.aspect.LogAspect;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试AOP
 */
@Configuration
@EnableAspectJAutoProxy
public class AopConfig {
    @Bean
    public MathHandler mathHandler(){
        return new MathHandler();
    }
}
```

接下来，在`AopConfig#mathHandler()`方法中打上断点，如下所示。

![001](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-001.png)

接下来，启动`io.mykit.spring.test`包下的`AopTest#testAop01()`方法。

```java
package io.mykit.spring.test;
import io.mykit.spring.plugins.register.aop.MathHandler;
import io.mykit.spring.plugins.register.config.AopConfig;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
/**
 * @author binghe
 * @version 1.0.0
 * @description 测试切面
 */
public class AopTest {

    @Test
    public void testAop01(){
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(AopConfig.class);
        MathHandler mathHandler = context.getBean(MathHandler.class);
        mathHandler.add(1, 2);
        context.close();
    }
}
```

发现断点会进入`org.springframework.context.annotation`包下的`AnnotationConfigApplicationContext#AnnotationConfigApplicationContext()`方法，如下所示。

![003](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-003.png)

而此时的断点是定位到`AnnotationConfigApplicationContext#AnnotationConfigApplicationContext()`方法中调用`refresh()`方法的代码行。`refresh()`方法会刷新Spring容器。接下来，我们可以通过IDEA左下角的方法调用堆栈进入`refresh()`方法内部，如下所示。

![004](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-004.png)

此时发现`refresh()`方法位于`org.springframework.context.support`包下的`AbstractApplicationContext`类中。此时，会发现代码调用流程会定位在`AbstractApplicationContext#refresh()`方法中调用的`registerBeanPostProcessors()`方法代码行。如下所示。

![005](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-005.png)

`registerBeanPostProcessors()`方法的作用就是注册bean的后置处理器来拦截bean的创建。

接下来，进入`registerBeanPostProcessors()`方法，发现`registerBeanPostProcessors()`方法位于`org.springframework.context.support`包下的`AbstractApplicationContext`类中，如下所示。

![006](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-006.png)

接下来，进入`PostProcessorRegistrationDelegate#registerBeanPostProcessors()`方法，这个方法的作用就是注册bean的后置处理器。在这个方法中按照顺序依次做了如下操作：

（1）先获取容器中已经定义的需要创建对象的所有BeanPostProcessor

（2）为容器中添加别的BeanPostProcessor

（3）注册实现了`PriorityOrdered`接口的BeanPostProcessor

（4）注册实现了`Ordered`接口的BeanPostProcessor

（5）注册没有实现优先级接口的BeanPostProcessor

（6）注册BeanPostProcessor，也就是创建BeanPostProcessor对象保存到容器中，创建`interalAutoProxyCreator`的BeanPostProcessor对象（AnnotationAwareAspectJAutoProxyCreator类型的对象）。

在（6）中又会依次执行如下几个步骤。

1) 调用`createBeanInstance(String, RootBeanDefinition, Object[])`方法，创建Bean的实例

2) 调用`populateBean(String, RootBeanDefinition, BeanWrapper) `方法，为bean的属性赋值。

3) 调用`initializeBean(String, Object ,RootBeanDefinition mbd)`方法，初始化bean。

这三个方法都位于`org.springframework.beans.factory.support`包下的`AbstractAutowireCapableBeanFactory`类中。

而第3)步的执行又会依次执行如下几个步骤。

* 调用`invokeAwareMethods(String, Object)`方法，处理Aware接口的方法回调。
* 调用`applyBeanPostProcessorsBeforeInitialization(Object, String)`方法，应用后置处理器的`PostProcessorsBeforeInitialization()`方法。
* 调用`invokeInitMethods(String, Object, RootBeanDefinition)`方法，执行自定义的初始化方法。
* 调用`applyBeanPostProcessorsAfterInitialization(Object, String)`方法，执行后置处理器的`postProcessAfterInitialization(Object, String)`方法。如下所示。

4) `BeanPostProcessor(AnnotationAwareAspectJAutoProxyCreator)`创建成功，名称为`aspectJAdvisorsBuilder`。

![018](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-018.png)



接下来，我们看看方法的调用信息。

![007](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-007.png)

会发现此时逻辑调用会定位在`BeanPostProcessor pp = beanFactory.getBean(ppName, BeanPostProcessor.class);` 这行代码上。

同样的，我们进入`beanFactory.getBean(ppName, BeanPostProcessor.class);`方法。发现会进入`org.springframework.beans.factory.support`包下的`AbstractBeanFactory#getBean(String,Class)`方法。

![008](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-008.png)

继续进入`doGetBean()`方法，会发现逻辑执行定位到`doGetBean()`中如下代码处。

```java
sharedInstance = getSingleton(beanName, () -> {
    try {
        return createBean(beanName, mbd, args);
    }
    catch (BeansException ex) {
        // Explicitly remove instance from singleton cache: It might have been put there
        // eagerly by the creation process, to allow for circular reference resolution.
        // Also remove any beans that received a temporary reference to the bean.
        destroySingleton(beanName);
        throw ex;
    }
});
```

![009](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-009.png)

而在IOC容器中第一次调用`getSingleton()`方法时，不会存在实例，所以，第一次调用`getSingleton()`方法会返回null。

进入`getSingleton()`方法，如下所示。

![010](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-010.png)

此时，发现Spring会调用`singletonFactory.getObject()`方法，继续往下执行，会发现逻辑定位到`doGetBean()`方法的如下代码。

![011](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-011.png)

继续执行断点，会发现逻辑进入`org.springframework.beans.factory.support`包下的`AbstractAutowireCapableBeanFactory#createBean(String, RootBeanDefinition, Object[])`方法中，如下所示。

![012](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-012.png)

继续进入`doCreateBean(String,RootBeanDefinition,Object[])`方法，如下所示。

![013](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-013.png)

此时，会发现bean已经实例化完成了，如下所示。

![014](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-014.png)

接下来，就会初始化bean的信息。那具体bean是在哪里进行实例化的呢？我们找到`doCreateBean(String,RootBeanDefinition,Object[])`方法的如下代码片段。

![015](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-015.png)

同时，我们也会发现此时实例化的bean的类型为`org.springframework.aop.config.internalAutoProxyCreator`。

![016](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-016.png)

实例化完成之后就会在`doCreateBean(String,RootBeanDefinition,Object[])`方法的如下代码处进行初始化。

![013](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-013.png)

进入`initializeBean(String, Object ,RootBeanDefinition mbd)`方法。

![017](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-017.png)

会发现代码执行逻辑定位在`invokeAwareMethods(beanName, bean);`处。进入`invokeAwareMethods(beanName, bean);`方法。

![019](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-019.png)

这个方法就比较简单了，相信点击都能看懂，这里就不再赘述这个方法的逻辑了。此时，代码的执行逻辑会定位到`((BeanFactoryAware) bean).setBeanFactory(AbstractAutowireCapableBeanFactory.this);`。

继续执行会发现逻辑进入了`org.springframework.aop.framework.autoproxy`包下的`AbstractAdvisorAutoProxyCreator#setBeanFactory()`方法，如下所示。

![002](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-002.png)

首先，会调用父类的`setBeanFactory(BeanFactory)`方法，然后会调用`initBeanFactory(ConfigurableListableBeanFactory) `方法初始化BeanFactory。

继续往下执行，我们会发现调用的是`org.springframework.aop.aspectj.annotation`包下的`AnnotationAwareAspectJAutoProxyCreator#initBeanFactory(ConfigurableListableBeanFactory)`方法。

![020](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-020.png)

继续往下执行，代码逻辑会执行到`org.springframework.beans.factory.support`包下的`AbstractAutowireCapableBeanFactory#createBean(String, RootBeanDefinition, Object[])`方法中，并且会定位到`Object beanInstance = doCreateBean(beanName, mbdToUse, args);`代码行。

![021](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-021.png)

执行完会回到`org.springframework.beans.factory.support`包下的`DefaultSingletonBeanRegistry#getSingleton(String, ObjectFactory<?>)`方法，并且会执行`addSingleton(beanName, singletonObject);代码行，如下所示。

![022](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-044-022.png)

将bean放入容器中。

至此，整个bean的创建，实例化，初始化，添加到容器的过程就介绍完了。


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)




