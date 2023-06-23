---
title: 【付费】 第15章：深度解析@Inject注解
pay: https://articles.zsxq.com/id_2lbs516korwe.html
---

# 《Spring核心技术》第15章-注入数据型注解：深度解析@Inject注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-15](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-15)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Inject注解注入Bean的案例和流程，从源码级别彻底掌握@Inject注解在Spring底层的执行流程。

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

`Spring中的@Inject注解，你真的彻底了解过吗？`

@Inject注解是JSR330规范中提供的注解，可以将Bean装配到类的方法，构造方法和字段中，也可以配合@Qualifier注解使用。

## 二、注解说明

`关于@Inject注解的一点点说明~~`

@Inject注解是JSR330规范中提供的注解，在@Inject注解中不提供任何属性，可以配合@Qualifier注解使用。也就是说，存在多个类型相同的Bean时，通过@Qualifier注解可以明确指定注入哪个Bean。

@Inject注解与@Autowired的区别：

（1）@Inject是JSR330规范实现的，@Autowired是spring自带的。

（2）@Autowired、@Inject用法基本一样，不同的是@Autowired有一个required属性。

### 2.1 注解源码

@Inject注解的源码详见：javax.inject.Inject。

```java
@Target({ METHOD, CONSTRUCTOR, FIELD })
@Retention(RUNTIME)
@Documented
public @interface Inject {}
```

可以看到，@Inject注解并没有提供任何属性，并且@Inject注解可以标注到方法、构造方法和字段上。

### 2.2 使用场景

在一定程度上，@Inject注解和@Autowired注解的使用场景基本相同，如果需要将Bean装配到类中的方法、构造方法和字段中，可以使用@Inject注解实现。

## 三、使用案例

`@Inject的实现案例，我们一起实现吧~~`

本节，就基于@Inject注解实现向Bean属性中赋值的案例，具体的实现步骤如下所示。

**（1）新增InjectDao类**

InjectDao类的源码详见：spring-annotation-chapter-15工程下的io.binghe.spring.annotation.chapter15.dao.InjectDao。

```java
@Repository
public class InjectDao {
}
```

可以看到，InjectDao类就是一个普通的dao类。

**（2）新增InjectService类**

InjectService类的源码详见：spring-annotation-chapter-15工程下的io.binghe.spring.annotation.chapter15.service.InjectService。

```java
@Service
public class InjectService {
    @Inject
    private InjectDao injectDao;
    @Override
    public String toString() {
        return "InjectService{" +
                "injectDao=" + injectDao +
                '}';
    }
}
```

可以看到，InjectService类是service层的实现类，并且在InjectService类中使用@Inject注解向injectDao成员变量中装配InjectDao类型的Bean对象。

**（3）新增InjectConfig类**

InjectConfig类的源码详见：spring-annotation-chapter-15工程下的io.binghe.spring.annotation.chapter15.config.InjectConfig。

```java
@Configuration
@ComponentScan(basePackages = {"io.binghe.spring.annotation.chapter15"})
public class InjectConfig {
}
```

可以看到，InjectConfig类上标注了@Configuration注解，说明InjectConfig类是案例的配置类，并且在InjectConfig类上使用@ComponentScan注解指定了要扫描的包名。

**（4）新增InjectTest类**

InjectTest类的源码详见：spring-annotation-chapter-15工程下的io.binghe.spring.annotation.chapter15.InjectTest。

```java
public class InjectTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(InjectConfig.class);
        InjectService injectService = context.getBean(InjectService.class);
        System.out.println(injectService);
    }
}
```

可以看到，在InjectTest类的main()方法中，从IOC容器中获取InjectService对象并打印。

**（5）运行InjectTest类**

运行InjectTest类的main()方法，输出的结果信息如下所示。

```bash
InjectService{injectDao=io.binghe.spring.annotation.chapter15.dao.InjectDao@a3d8174}
```

可以看到，通过@Inject注解成功向InjectService类的injectDao成员变量中装配了Bean对象。

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码