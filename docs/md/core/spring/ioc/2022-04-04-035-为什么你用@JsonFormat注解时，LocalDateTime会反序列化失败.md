---
layout: post
category: binghe-spring-ioc
title: 为啥你用@JsonFormat注解时，LocalDateTime会反序列化失败？
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 最近，有个小伙伴问我：我在SpringBoot项目中，使用@JsonFormat注解标注LocalDateTime类型的字段时，LocalDateTime反序列化失败，这个我该怎么处理呢？别急，我们一起来解决这个问题。
lock: need
---

# 为啥你用@JsonFormat注解时，LocalDateTime会反序列化失败？

## 写在前面

> 最近，有个小伙伴问我：我在SpringBoot项目中，使用@JsonFormat注解标注LocalDateTime类型的字段时，LocalDateTime反序列化失败，这个我该怎么处理呢？别急，我们一起来解决这个问题。

## 小伙伴的疑问

![001](/assets/images/core/spring/ioc/2022-04-04-035-001.jpg)

## 解答小伙伴的疑问

我们可以使用SpringBoot依赖中的@JsonFormat注解，将前端通过json传上来的时间，通过@RequestBody自动绑定到Bean里的LocalDateTime成员上。具体的绑定注解使用方法如下所示。

```java
@JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", locale = "zh", timezone = "GMT+8")
```

### 出现问题的版本

我使用Spring Boot 2.0.0 时，直接在字段上加上@JsonFormat 注解就可以完成数据的绑定。

而在使用Spring Boot 1.5.8时，只在字段上加上@JsonFormat 注解，在数据绑定时无法将Date类型的数据自动转化为字符串类型的数据。

### 解决方法

**1.将SpringBoot版本升级为2.0.0及以上。**

**2.如果不升级SpringBoot版本，可以按照下面的方式解决问题。**

不升级SpringBoot版本，添加Jackson对Java Time的支持后，就能解决这个问题。

在pom.xml中添加：

```xml
<dependency>
    <groupId>com.fasterxml.jackson.module</groupId>
    <artifactId>jackson-module-parameter-names</artifactId>
</dependency>
<dependency>
    <groupId>com.fasterxml.jackson.datatype</groupId>
    <artifactId>jackson-datatype-jdk8</artifactId>
</dependency>
<dependency>
    <groupId>com.fasterxml.jackson.datatype</groupId>
    <artifactId>jackson-datatype-jsr310</artifactId>
</dependency>
```

添加JavaConfig，自动扫描新添加的模块：

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
 
import com.fasterxml.jackson.databind.ObjectMapper;
 
@Configuration
public class JacksonConfig {
 
    @Bean
    public ObjectMapper serializingObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        return objectMapper;
    }
}
```

或者在application.properties添加如下配置：

```bash
spring.jackson.serialization.write-dates-as-timestamps=false
```

或者只注册JavaTimeModule，添加下面的Bean

```java
@Bean
public ObjectMapper serializingObjectMapper() {
  ObjectMapper objectMapper = new ObjectMapper();
  objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
  objectMapper.registerModule(new JavaTimeModule());
  return objectMapper;
}
```

## 重磅福利

微信搜一搜【冰河技术】微信公众号，关注这个有深度的程序员，每天阅读超硬核技术干货，公众号内回复【PDF】有我准备的一线大厂面试资料和我原创的超硬核PDF技术文档，以及我为大家精心准备的多套简历模板（不断更新中），希望大家都能找到心仪的工作，学习是一条时而郁郁寡欢，时而开怀大笑的路，加油。如果你通过努力成功进入到了心仪的公司，一定不要懈怠放松，职场成长和新技术学习一样，不进则退。如果有幸我们江湖再见！       

另外，我开源的各个PDF，后续我都会持续更新和维护，感谢大家长期以来对冰河的支持！！

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)

