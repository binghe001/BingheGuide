---
layout: post
category: binghe-spring-ioc
title: 【Spring注解驱动开发】@PostConstruct与@PreDestroy源码的执行过程
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 在前面的《[【String注解驱动开发】你真的了解@PostConstruct注解和@PreDestroy注解吗？](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247485015&idx=1&sn=d9b98808a43f72655bf2be51270c4587&chksm=cee5199af992908c45e3801904013f17714b79dc60f6272c699361f7af4681f7ce3548fb8abf&token=1099992343&lang=zh_CN#rd)》一文中，我们简单的介绍了@PostConstruct注解与@PreDestroy注解的用法，有不少小伙伴纷纷留言说：在Spring中，@PostConstruct注解与@PreDestroy注解标注的方法是在哪里调用的呀？相信大家应该都挺好奇的吧，那今天我们就来一起分析下@PostConstruct注解与@PreDestroy注解的执行过程吧！
lock: need
---

# 【Spring注解驱动开发】@PostConstruct与@PreDestroy源码的执行过程

## 写在前面

> 在前面的《[【String注解驱动开发】你真的了解@PostConstruct注解和@PreDestroy注解吗？](https://mp.weixin.qq.com/s?__biz=Mzg3MzE1NTIzNA==&mid=2247485015&idx=1&sn=d9b98808a43f72655bf2be51270c4587&chksm=cee5199af992908c45e3801904013f17714b79dc60f6272c699361f7af4681f7ce3548fb8abf&token=1099992343&lang=zh_CN#rd)》一文中，我们简单的介绍了@PostConstruct注解与@PreDestroy注解的用法，有不少小伙伴纷纷留言说：在Spring中，@PostConstruct注解与@PreDestroy注解标注的方法是在哪里调用的呀？相信大家应该都挺好奇的吧，那今天我们就来一起分析下@PostConstruct注解与@PreDestroy注解的执行过程吧！
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 注解说明

@PostConstruct，@PreDestroy是Java规范JSR-250引入的注解，定义了对象的创建和销毁工作，同一期规范中还有注解@Resource，Spring也支持了这些注解。

在Spring中，@PostConstruct，@PreDestroy注解的解析是通过BeanPostProcessor实现的，具体的解析类是org.springframework.context.annotation.CommonAnnotationBeanPostProcessor，其父类是org.springframework.beans.factory.annotation.InitDestroyAnnotationBeanPostProcessor，Spring官方说明了该类对JSR-250中@PostConstruct，@PreDestroy，@Resource注解的支持。

> Spring's org.springframework.context.annotation.CommonAnnotationBeanPostProcessor supports the JSR-250 javax.annotation.PostConstruct and javax.annotation.PreDestroy annotations out of the box, as init annotation and destroy annotation, respectively. Furthermore, it also supports the javax.annotation.Resource annotation for annotation-driven injection of named beans.

## 调用过程

具体过程是，IOC容器先解析各个组件的定义信息，解析到@PostConstruct，@PreDestroy的时候，定义为生命周期相关的方法，组装组件的定义信息等待初始化；在创建组件时，创建组件并且属性赋值完成之后，在执行各类初始化方法之前，从容器中找出所有BeanPostProcessor的实现类，其中包括InitDestroyAnnotationBeanPostProcessor，执行所有BeanPostProcessor的postProcessBeforeInitialization方法，在InitDestroyAnnotationBeanPostProcessor中就是找出被@PostConstruct修饰的方法的定义信息，并执行被@PostConstruct标记的方法。

## 调用分析

**@PostConstruct的调用链如下：**

![](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-005.png)

org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.initializeBean(String, Object, RootBeanDefinition)初始化流程中，先执行org.springframework.beans.factory.config.BeanPostProcessor.postProcessBeforeInitialization(Object, String)方法，然后再执行初始化方法：

```java
protected Object initializeBean(final String beanName, final Object bean, RootBeanDefinition mbd) {
	if (System.getSecurityManager() != null) {
		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			@Override
			public Object run() {
				invokeAwareMethods(beanName, bean);
				return null;
			}
		}, getAccessControlContext());
	}
	else {
		invokeAwareMethods(beanName, bean);
	}
 
	Object wrappedBean = bean;
	if (mbd == null || !mbd.isSynthetic()) {
		// 在执行初始化方法之前：先执行org.springframework.beans.factory.config.BeanPostProcessor.postProcessBeforeInitialization(Object, String)方法
		wrappedBean = applyBeanPostProcessorsBeforeInitialization(wrappedBean, beanName);
	}
 
	try {
		//执行InitializingBean的初始化方法和init-method指定的初始化方法
		invokeInitMethods(beanName, wrappedBean, mbd);
	}
	catch (Throwable ex) {
		throw new BeanCreationException(
				(mbd != null ? mbd.getResourceDescription() : null),
				beanName, "Invocation of init method failed", ex);
	}
 
	if (mbd == null || !mbd.isSynthetic()) {
		wrappedBean = applyBeanPostProcessorsAfterInitialization(wrappedBean, beanName);
	}
	return wrappedBean;
}
```

org.springframework.beans.factory.config.BeanPostProcessor.postProcessBeforeInitialization(Object, String)的说明如下：

> Apply this BeanPostProcessor to the given new bean instance before any bean initialization callbacks (like InitializingBean's afterPropertiesSet or a custom init-method). The bean will already be populated with property values. The returned bean instance may be a wrapper around the original.

调用时机： 在组件创建完属性复制完成之后，调用组件初始化方法之前；

org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.applyBeanPostProcessorsBeforeInitialization(Object, String)的具体流程如下。

```java
@Override
public Object applyBeanPostProcessorsBeforeInitialization(Object existingBean, String beanName)
		throws BeansException {
	
	Object result = existingBean;
	for (BeanPostProcessor beanProcessor : getBeanPostProcessors()) {
		//遍历所有BeanPostProcessor的实现类，执行BeanPostProcessor的postProcessBeforeInitialization
		//在InitDestroyAnnotationBeanPostProcessor中的实现是找出@PostConstruct标记的方法的定义信息，并执行
		result = beanProcessor.postProcessBeforeInitialization(result, beanName);
		if (result == null) {
			return result;
		}
	}
	return result;
}
```

**@PreDestroy调用链如下：**

![](https://binghe001.github.io/assets/images/core/spring/ioc/2022-04-04-005.png)

@PreDestroy是通过org.springframework.beans.factory.config.DestructionAwareBeanPostProcessor.postProcessBeforeDestruction(Object, String)被调用（InitDestroyAnnotationBeanPostProcessor实现了该接口），该方法的说明如下：

> Apply this BeanPostProcessor to the given bean instance before its destruction. Can invoke custom destruction callbacks.
>
> Like DisposableBean's destroy and a custom destroy method, this callback just applies to singleton beans in the factory (including inner beans).

**调用时机： 该方法在组件的销毁之前调用；**

org.springframework.beans.factory.support.DisposableBeanAdapter.destroy()的执行流程如下：

```java
@Override
public void destroy() {
	if (!CollectionUtils.isEmpty(this.beanPostProcessors)) {
		//调用所有DestructionAwareBeanPostProcessor的postProcessBeforeDestruction方法
		for (DestructionAwareBeanPostProcessor processor : this.beanPostProcessors) {
			processor.postProcessBeforeDestruction(this.bean, this.beanName);
		}
	}
 
	if (this.invokeDisposableBean) {
		if (logger.isDebugEnabled()) {
			logger.debug("Invoking destroy() on bean with name '" + this.beanName + "'");
		}
		try {
			if (System.getSecurityManager() != null) {
				AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() {
					@Override
					public Object run() throws Exception {
						((DisposableBean) bean).destroy();
						return null;
				}
				}, acc);
			}
			else {
				//调用DisposableBean的销毁方法
				((DisposableBean) bean).destroy();
			}
		}
		catch (Throwable ex) {
				String msg = "Invocation of destroy method failed on bean with name '" + this.beanName + "'";
			if (logger.isDebugEnabled()) {
				logger.warn(msg, ex);
			}
			else {
				logger.warn(msg + ": " + ex);
			}
		}
	}
 
	//调用自定义的销毁方法
	if (this.destroyMethod != null) {
		invokeCustomDestroyMethod(this.destroyMethod);
	}
	else if (this.destroyMethodName != null) {
		Method methodToCall = determineDestroyMethod();
		if (methodToCall != null) {
			invokeCustomDestroyMethod(methodToCall);
		}
	}
}
```

所以是先调用DestructionAwareBeanPostProcessor的postProcessBeforeDestruction(@PreDestroy标记的方法被调用)，再是DisposableBean的destory方法，最后是自定义销毁方法。

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。


> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)






