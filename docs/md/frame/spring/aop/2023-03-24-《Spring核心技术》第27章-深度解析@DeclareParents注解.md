---
title: 【付费】第27章：深度解析@DeclareParents注解
pay: https://articles.zsxq.com/id_rw597583o4jg.html
---

# 《Spring核心技术》第27章：深度解析@DeclareParents注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-27](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-27)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@DeclareParents注解加入新方法的案例和流程，从源码级别彻底掌握@DeclareParents注解在Spring底层的执行流程。

------

本章目录如下所示：

* 学习指引
* 注解说明
  * 注解源码
  * 使用场景
* 使用案例
  * 原有功能的实现
  * 基于手写逻辑实现校验
  * 基于前置通知实现校验
* 源码时序图
* 源码解析
* 总结
* 思考
* VIP服务

## 一、学习指引

`在Spring AOP中，你了解过@DeclareParents注解吗？`

很多小伙伴用了很多年的Spring，但是对@DeclareParents注解了解的非常少。那我说一个场景，你多多少少会有点体会：比如你接手了一个基于Spring开发的项目，这个项目的业务比较复杂，代码也比较乱。你想在某个类中新增一个方法来校验某些逻辑，但是这个类不知道在多少地方被使用，改动一个地方有点牵一发动全身的感觉，没错，代码就是犹如“屎山”一样，根本就没有办法在原来的类上新增方法。此时，如果你了解Spring的@DeclareParents注解，就能够轻松应对这种情况。

## 二、注解说明

`关于@DeclareParents注解的一点点说明~~`

在实际工作过程中，难免会遇到突然接手其他人写的项目，或者接手的某个项目已经经历“几代人”的手，妥妥的“屎山”，改代码牵一发动全身，此时就可以使用到@DeclareParents注解给被增强的类提供一些新的方法。

### 2.1 注解源码

@DeclareParents注解可以为被增强的类实现新的接口，并且可以添加新的方法。@DeclareParents注解的源码详见：org.aspectj.lang.annotation.DeclareParents。

```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface DeclareParents {
    String value();
    Class defaultImpl() default DeclareParents.class;
}
```

从源码可以看出，@DeclareParents注解可以标注到字段上，并且提供了一个String类型的value属性和一个Class类型的defaultImpl属性。

* value：指定目标类型的表达式，如果在全类名的后面添加 + ，则表示的是当前类及其子类。
* defaultImpl：指定方法或者字段的默认实现类。

### 2.2 使用场景

除了前面说的接手“屎山”项目，改代码牵一发动全身的场景外。还有一个场景就是：在正常开发业务项目的过程中，当项目已经开发到某个阶段时，此时突然发现某个类少一个功能，想在某个类中添加新的方法。但是这个类比较复杂，同样会涉及到牵一发动全身的感觉，改动起来比较麻烦。此时，也可以使用@DeclareParents注解，在不改动原有代码的前提下实现新增方法的功能。

## 三、使用案例

`一起实现@DeclareParents注解的案例，怎么样?`

在案例的实现中，模拟一个原来就基于接口实现好的保存或者更新某个对象的功能，此时，需要在不改动原有代码的基础上在保存或者更新对象之前，先校验下待保存或者更新的对象中属性值的合法性，如果合法，则正常执行保存操作，如果不合法，则抛出异常。

### 3.1 原有功能的实现

本节，先来完成原有的模拟保存或者更新对象的功能，具体的实现步骤如下所示。

**（1）新增DeclareParentsBean类**

DeclareParentsBean类的源码详见：spring-annotation-chapter-27工程下的io.binghe.spring.annotation.chapter27.bean.DeclareParentsBean。

```java
public class DeclareParentsBean {
    public static final String NAME = "binghe";
    private String name;
    public DeclareParentsBean() {
    }
    public DeclareParentsBean(String name) {
        this.name = name;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    @Override
    public String toString() {
        return "DeclareParentsBean{" +
                "name='" + name + '\'' +
                '}';
    }
}
```

可以看到，DeclareParentsBean类就是一个普通的Java类，在DeclareParentsBean类中提供了一个name属性。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码