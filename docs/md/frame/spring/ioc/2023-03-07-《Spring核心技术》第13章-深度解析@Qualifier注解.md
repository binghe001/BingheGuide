---
title: 【付费】 第13章：深度解析@Qualifier注解
pay: https://articles.zsxq.com/id_tro8zjto40zn.html
---

# 《Spring核心技术》第13章-注入数据型注解：深度解析@Qualifier注解

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-13](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-13)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★★☆

* **本章重点**：进一步学习并掌握@Qualifier注解指定注入Bean的案例和流程，从源码级别彻底掌握@Qualifier注解在Spring底层的执行流程。

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

`Spring中的@Qualifier注解，你真的彻底了解过吗？`

如果Spring中存在多个类型相同但名称不同的Bean时，使用@Autowired注解向类的构造方法、方法、参数、字段中注入Bean对象时，如果需要向类的构造方法、方法、参数、字段中注入特定的Bean对象，就可以使用@Qualifier注解指定Bean的名称。

## 二、注解说明

`关于@Qualifier注解的一点点说明~~`

如果Spring中存在多个类型相同但名称不同的Bean时，使用@Autowired注解向类的构造方法、方法、参数、字段中注入Bean对象时，首先会根据Bean的类型注入，如果存在多个类型相同的Bean时，会根据Bean的名称注入，如果找不到对应名称的Bean时，就会抛出异常。此时，就可以通过@Qualifier注解明确指定要注入的Bean。

### 2.1 注解源码

@Qualifier注解的源码详见：org.springframework.beans.factory.annotation.Qualifier。

```java
/**
 * @author Mark Fisher
 * @author Juergen Hoeller
 * @since 2.5
 * @see Autowired
 */
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Qualifier {
	String value() default "";
}
```

从@Qualifier注解的源码可以看出，@Qualifier注解是从Spring 2.5版本开始提供的注解，可以标注到字段、方法、参数、类和其他注解上。在@Qualifier注解中只提供了一个String类型的value属性，具体含义如下所示。

* value：表示Bean的唯一标识。当使用Spring自动按照类型注入时，存在多个类型相同的Bean的时候，就可以使用此注解来明确注入哪个bean对象。

**注意：@Qualifier注解通常会和@Autowired注解一起使用。**

### 2.2 使用场景

在项目开发过程中，有这样一个场景会经常使用到@Qualifier注解。比如在项目中集成了多个消息中间件，包含：RocketMQ、Kafka、RabbitMQ和ActiveMQ，对外提供统一发送消息的接口，并且基于RocketMQ、Kafka、RabbitMQ和ActiveMQ实现的消息发送类上分别标注了不同的Bean名称。如果在业务系统中需要指定使用某种消息中间件来发送消息时，就需要使用@Qualifier注解明确指定Bean的名称。

总之，如果Spring中存在多个类型相同但名称不同的Bean时，使用@Autowired注解向类的构造方法、方法、参数、字段中注入Bean对象时，首先会根据Bean的类型注入，如果存在多个类型相同的Bean时，会根据Bean的名称注入，如果找不到对应名称的Bean时，就可以通过@Qualifier注解明确指定要注入的Bean。

## 三、使用案例

`@Qualifier的使用案例，我们一起实现吧~~`

本节，就简单介绍下当Spring中存在多个类型相同的Bean时，使用@Qualifier注解明确指定注入的Bean的案例。在案例的实现过程中，采用简单的MVC架构模式实现。具体案例实现步骤如下所示。

**（1）新增QualifierDao接口**

QualifierDao接口的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.dao.QualifierDao。

```java
public interface QualifierDao {
}
```

可以看到，QualifierDao接口就是一个简单的Java接口。

**（2）新增QualifierDao1类**

QualifierDao1类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.dao.impl.QualifierDao1。

```java
@Repository(value = "qualifierDao1")
public class QualifierDao1 implements QualifierDao {
    public QualifierDao1(){
        System.out.println("执行了QualifierDao1的构造方法...");
    }
}
```

可以看到，QualifierDao1类实现了QualifierDao接口，并使用@Repository注解执行了Bean的名称为qualifierDao1。

**（3）新增QualifierDao2类**

QualifierDao2类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.dao.impl.QualifierDao2。

```java
@Repository(value = "qualifierDao2")
public class QualifierDao2 implements QualifierDao {
    public QualifierDao2(){
        System.out.println("执行了QualifierDao2的构造方法...");
    }
}
```

可以看到，QualifierDao2类实现了QualifierDao接口，并使用@Repository注解执行了Bean的名称为qualifierDao2。

**（4）新增QualifierService类**

QualifierService类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.service.QualifierService。

```java
@Service
public class QualifierService {
    @Autowired
    @Qualifier("qualifierDao1")
    private QualifierDao qualifierDao;
    @Override
    public String toString() {
        return "QualifierService{" +
                "qualifierDao=" + qualifierDao +
                '}';
    }
}
```

可以看到，在QualifierService类上标注了@Service注解，当IOC容器启动扫描到QualifierService类时，就会将QualifierService类的Bean对象注入IOC容器。在QualifierService类中，使用@Autowired注解和 @Qualifier注解注入QualifierDao类的Bean对象。并且使用@Qualifier注解明确指定注入名称为qualifierDao1的QualifierDao对象。

**（5）新增QualifierConfig类**

QualifierConfig类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.config.QualifierConfig。

```java
@Configuration
@ComponentScan(value = {"io.binghe.spring.annotation.chapter13"})
public class QualifierConfig {
}
```

可以看到，在QualifierConfig类上标注了@Configuration注解，说明QualifierConfig类是Spring的配置类，同时在QualifierConfig类上使用@ComponentScan注解指定要扫描的包是io.binghe.spring.annotation.chapter13。

**（6）新增QualifierTest类**

QualifierTest类的源码详见：spring-annotation-chapter-13工程下的io.binghe.spring.annotation.chapter13.QualifierTest。

```java
public class QualifierTest {
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(QualifierConfig.class);
        QualifierService qualifierService = context.getBean(QualifierService.class);
        System.out.println("qualifierService===>>> " + qualifierService);
    }
}
```

可以看到，在QualifierTest类中的main()方法中，会从IOC容器中获取QualifierService类的Bean对象并进行打印。

**（7）运行QualifierTest类**

运行QualifierTest类的main()方法，输出的结果信息如下所示。

```bash
执行了QualifierDao1的构造方法...
执行了QualifierDao2的构造方法...
qualifierService===>>> QualifierService{qualifierDao=io.binghe.spring.annotation.chapter13.dao.impl.QualifierDao1@6631f5ca}
```

从输出的结果信息中可以看到，执行了QualifierDao1类和QualifierDao2类的构造方法，并向QualifierService类中使用@Qualifier注解指定注入了QualifierDao1类的Bean对象。

另外，大家可以自行将QualifierService类中@Qualifier注解中的值修改为qualifierDao2，并测试结果，这里不再赘述。

**说明：当存在多个类型相同的Bean时，可以使用@Qualifier注解明确指定要注入的Bean。**

## 四、源码时序图

`结合时序图理解源码会事半功倍，你觉得呢？`

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码


