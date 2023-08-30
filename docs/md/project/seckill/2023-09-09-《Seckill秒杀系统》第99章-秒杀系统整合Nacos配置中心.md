---
title: 第99章：秒杀系统整合Nacos配置中心
pay: https://articles.zsxq.com/id_az4qpenpf439.html
---

# 《Seckill秒杀系统》第99章：秒杀系统整合Nacos配置中心

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码获取地址：[https://t.zsxq.com/0dhvFs5oR](https://t.zsxq.com/0dhvFs5oR)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：了解配置中心的实现原理，重点掌握配置中心在实际项目中的落地实现方案，熟练掌握业务系统整合Nacos配置中心的方法与落地方案，并能够灵活将实现方案应用到自身实际项目中。

**大家好，我是冰河~~**

将一个系统拆分成微服务之后，每个微服务都各自维护一套配置文件，当修改服务配置后，还需要重启微服务。这种方式不仅增加了微服务维护的成本，而且还存在漏改配置项的风险。

## 一、前言

随着秒杀系统拆分的微服务越来越多，我们需要一个统一的方式来管理和维护各个微服的配置内容，以便能够及时有效的更新各个微服务的状态配置，此时Nacos配置中心就能够满足我们的需求。

## 二、本章诉求

将秒杀系统的各个微服务的配置整合进Nacos配置中心，在Nacos配置中心里统一维护和管理。重点掌握配置中心在实际项目中的落地实现方案，熟练掌握业务系统整合Nacos配置中心的方法与落地方案，并能够灵活将实现方案应用到自身实际项目中。

## 三、整合Nacos配置中心

本节，我们以用户微服务整合Nacos配置中心为例进行说明，其他微服务整合Nacos配置中心的方式与用户微服务整合Nacos配置中心的方式相同，这里不再赘述。大家可以拿到本章对应的源码后，自行查看代码即可。另外，本章涉及到的各个微服务整合进Nacos的配置，已经放到本章源码分支的`environment/config/nacos/chapter99`目录下，大家根据具体需要，自行将配置导入Nacos即可，也可以根据本章的内容自行在Nacos中进行配置。

**注意：将微服务的配置放在Nacos中时，就暂时不用微服务中的application.properties配置文件了，而是在项目中新建一个bootstrap.properties文件。因为配置文件的优先级从高到低依次为：bootstrap.properties -> bootstrap.yml -> application.properties -> application.yml。**

### 3.1 新增配置

**（1）新增Maven依赖**

在秒杀系统的父工程中的pom.xml文件中添加如下依赖。

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-bootstrap</artifactId>
</dependency>
```

**（2）新增bootstrap.properties配置文件**

在seckill-user-starter工程下的`src/main/resources`目录下新增bootstrap.properties配置文件，文件内容如下所示。

```properties
# application
spring.application.name=seckill-user
# Nacos Config
spring.cloud.nacos.config.server-addr=127.0.0.1:8848
spring.cloud.nacos.config.file-extension=properties
spring.cloud.nacos.config.namespace=seckill-config
spring.cloud.nacos.config.access-key=nacos
spring.cloud.nacos.config.secret-key=nacos
spring.cloud.nacos.config.group=seckill-user-group
# spring active
spring.profiles.active=dev
```

### 3.2 配置Nacos

**（1）启动Nacos，进入配置列表页**

启动Nacos，在浏览器中输入`http://localhost:8848/nacos` 并登录Nacos，选择Nacos菜单中的配置管理-配置列表，如图99-1所示。

<div align="center">
    <img src="https://binghe.gitcode.host/images/project/seckill/seckill-2023-09-09-001.png?raw=true" width="60%">
    <br/>
</div>

这里需要注意的是选择seckill-config命名空间。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码