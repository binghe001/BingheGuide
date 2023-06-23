---
title: 【付费】 第12章：深度解析@Autowired注解
pay: https://articles.zsxq.com/id_xodqwm77k51b.html
---

# 《Spring核心技术》第12章-注入数据型注解：深度解析@Autowired注解

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

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
