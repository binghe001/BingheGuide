---
layout: post
category: binghe-spring-ioc
title: 第09章：将Service注入到Servlet中
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 最近，一位读者出去面试前准备了很久，信心满满的去面试。没想到面试官的一个问题把他难住了。面试官的问题是这样的：如何使用Spring将Service注入到Servlet中呢？这位读者平时也是很努力的，看什么源码啊、多线程啊、高并发啊、设计模式啊等等。没想到却在一个很简单的问题上栽了跟头，这就说明学习知识要系统化，要有条理，切忌东学一点，西记一点，否则，到头来，啥也学不到。
lock: need
---

# 《Spring注解驱动开发》第09章：将Service注入到Servlet中

## 写在前面

> 最近，一位读者出去面试前准备了很久，信心满满的去面试。没想到面试官的一个问题把他难住了。面试官的问题是这样的：如何使用Spring将Service注入到Servlet中呢？这位读者平时也是很努力的，看什么源码啊、多线程啊、高并发啊、设计模式啊等等。没想到却在一个很简单的问题上栽了跟头，这就说明学习知识要系统化，要有条理，切忌东学一点，西记一点，否则，到头来，啥也学不到。
>
> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## 如何实现将Service注入到Servlet中？？

这里，我们列举两种解决方法（推荐使用第二种）

### 方法一：

直接重写Servlet的Init()方法，代码如下：

```java
public void init(ServletConfig servletConfig) throws ServletException {
	ServletContext servletContext = servletConfig.getServletContext();
	WebApplicationContext webApplicationContext = WebApplicationContextUtils
			.getWebApplicationContext(servletContext);
	AutowireCapableBeanFactory autowireCapableBeanFactory = webApplicationContext
			.getAutowireCapableBeanFactory();
	autowireCapableBeanFactory.configureBean(this, BEAN_NAME);
}
```

这里的BEAN_NAME即为我们需要注入到Spring容器中的服务，但这并不是一个好的方法，因为我们需要在每一个Servlet中都进行这样的操作。

### 方法二：

我们可以写一个类似于“org.springframework.web.struts.DelegatingRequestProcessor”的委托的Bean，然后通过配置的方法把我们的服务注入到servlet中，具体方法如下，

**Step 1：编写委托类DelegatingServletProxy**

```java
package com.telek.pba.base.util;

import java.io.IOException;
import javax.servlet.GenericServlet;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * 以下是类似org.springframework.web.struts.DelegatingRequestProcessor的一个委托
 * 用于通过配置的方法，在Servlet中注入Service
 * @author binghe
 * */
public class DelegatingServletProxy extends GenericServlet{
    private static final long serialVersionUID = 1L;
    private String targetBean;
    private Servlet proxy;

   @Override
   public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException{
   		proxy.service(req, res);
   }
     /**
      * 初始化
      */
      public void init() throws ServletException {
          this.targetBean = getServletName();
          getServletBean();
          proxy.init(getServletConfig());
      }

     /**
      * 获取Bean
      */
      private void getServletBean() {
          WebApplicationContext wac = WebApplicationContextUtils.getRequiredWebApplicationContext(getServletContext());
          this.proxy = (Servlet) wac.getBean(targetBean);
      }
}
```

**Step 2：修改Web.xml配置**

在纯Servlet模式下，我们的配置方式如下（以下由于代码高亮插件的问题，请将代码中的#替换成尖括号）

```xml
<servlet>
  <description>活动发起模块活动查询分页Servlet</description>
  <display-name>launchActivityQueryServlet</display>
  <servlet-name>LaunchActivityQueryServlet</servlet-name>
  <servlet-class>com.telek.pba.launch.servlet.LaunchActivityQueryServlet</servlet-class>
<servlet>

<servlet-mapping>
  <servlet-name>LaunchActivityQueryServlet</servlet-name>
  <url-pattern>/servlet/launch/LaunchActivityQueryServlet</url-pattern>
</servlet-mapping>
</servlet>
```

如果采用我们这种代理的方法，则配置应该修改为：

```xml
<servlet>
  <description>活动发起模块活动查询分页Servlet</description>
  <display-name>launchActivityQueryServlet</display>
  <servlet-name>launchActivityQueryServlet</servlet-name>
  <servlet-class>com.telek.pba.base.util.DelegatingServletProxy</servlet-class>
<servlet>

<servlet-mapping>
  <servlet-name>launchActivityQuery</servlet-name>
  <url-pattern>/servlet/launch/LaunchActivityQueryServlet</url-pattern>
</servlet-mapping>
</servlet> 
```

**注意：默认情况下，Servlet的配置中，LaunchActivityQuery的首字母一般为大写，而我们的标题中已注明，我们采用Spring的注解模式，如果是自动扫描注解的话，默认情况下，注解的value值为首字母小写，即：launchActivityQuery，因此，在我们新的配置中，要注意将首字母改为小写，否则会报无法找到Bean的错误。**

**Step 3：至此，我们就可以像SSH的注入方式一样，注入Servlet了，以下是个小示例：**

```java
package com.telek.pba.launch.servlet;

import java.io.IOException;
import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import com.telek.pba.base.model.PbaUserInfo;
import com.telek.pba.launch.dao.IPbaActivityInfoCurrentDAO;

@Component
public class LaunchActivityQueryServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	 
	//注入IPbaActivityInfoCurrentDAO
	@Resource
	private IPbaActivityInfoCurrentDAO pbaActivityInfoCurrentDAO;

	public LaunchActivityQueryServlet() {
		super();
	}
	 
	public void destroy() {
		super.destroy(); // Just puts "destroy" string in log
		// Put your code here
	}
	 
	public void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		//sth to do
	}
	 
	public void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		//sth to do
	}
	 
	public void init() throws ServletException {
		// Put your code here
	}
}
```

最后，请留心在Spring配置文件中，配置上自动扫描包的路径：

```xml
<context:component -scan base-package="com.telek.pba.*.dao.impl,
 					com.telek.pba.*.service.impl,
 					com.telek.pba.*.servlet"></context:component>
```

大功告成！

<font color="#FF0000">**好了，咱们今天就聊到这儿吧！别忘了给个在看和转发，让更多的人看到，一起学习一起进步！！**</font>

> 项目工程源码已经提交到GitHub：[https://github.com/binghe001/spring-annotation](https://github.com/binghe001/spring-annotation)

## 星球服务

加入星球，你将获得：

1.项目学习：微服务入门必备的SpringCloud  Alibaba实战项目、手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】、Seckill秒杀系统项目—进大厂必备高并发、高性能和高可用技能。

2.框架源码：手写RPC项目—所有大厂都需要的项目【含上百个经典面试题】、深度解析Spring6核心技术—只要学习Java就必须深度掌握的框架【含数十个经典思考题】。

3.硬核技术：深入理解高并发系列（全册）、深入理解JVM系列（全册）、深入浅出Java设计模式（全册）、MySQL核心知识（全册）。

4.技术小册：深入理解高并发编程（第1版）、深入理解高并发编程（第2版）、从零开始手写RPC框架、SpringCloud  Alibaba实战、冰河的渗透实战笔记、MySQL核心知识手册、Spring IOC核心技术、Nginx核心技术、面经手册等。

5.技术与就业指导：提供相关就业辅导和未来发展指引，冰河从初级程序员不断沉淀，成长，突破，一路成长为互联网资深技术专家，相信我的经历和经验对你有所帮助。

冰河的知识星球是一个简单、干净、纯粹交流技术的星球，不吹水，目前加入享5折优惠，价值远超门票。加入星球的用户，记得添加冰河微信：hacker_binghe，冰河拉你进星球专属VIP交流群。

## 星球重磅福利

跟冰河一起从根本上提升自己的技术能力，架构思维和设计思路，以及突破自身职场瓶颈，冰河特推出重大优惠活动，扫码领券进行星球，**直接立减149元，相当于5折，** 这已经是星球最大优惠力度！

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu_149.png?raw=true" width="80%">
    <br/>
</div>

领券加入星球，跟冰河一起学习《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》，更有已经上新的《大规模分布式Seckill秒杀系统》，从零开始介绍原理、设计架构、手撸代码。后续更有硬核中间件项目和业务项目，而这些都是你升职加薪必备的基础技能。

**100多元就能学这么多硬核技术、中间件项目和大厂秒杀系统，如果是我，我会买他个终身会员！**

## 其他方式加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。

## 星球规划

后续冰河还会在星球更新大规模中间件项目和深度剖析核心技术的专栏，目前已经规划的专栏如下所示。

### 中间件项目

* 《大规模分布式定时调度中间件项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式IM（即时通讯）项目实战（非Demo）》：全程手撸代码。
* 《大规模分布式网关项目实战（非Demo）》：全程手撸代码。
* 《手写Redis》：全程手撸代码。
* 《手写JVM》全程手撸代码。

### 超硬核项目

* 《从零落地秒杀系统项目》：全程手撸代码，在阿里云实现压测（**已上新**）。
* 《大规模电商系统商品详情页项目》：全程手撸代码，在阿里云实现压测。
* 其他待规划的实战项目，小伙伴们也可以提一些自己想学的，想一起手撸的实战项目。。。


既然星球规划了这么多内容，那么肯定就会有小伙伴们提出疑问：这么多内容，能更新完吗？我的回答就是：一个个攻破呗，咱这星球干就干真实中间件项目，剖析硬核技术和项目，不做Demo。初衷就是能够让小伙伴们学到真正的核心技术，不再只是简单的做CRUD开发。所以，每个专栏都会是硬核内容，像《SpringCloud Alibaba实战》、《手撸RPC专栏》和《Spring6核心技术》就是很好的示例。后续的专栏只会比这些更加硬核，杜绝Demo开发。

小伙伴们跟着冰河认真学习，多动手，多思考，多分析，多总结，有问题及时在星球提问，相信在技术层面，都会有所提高。将学到的知识和技术及时运用到实际的工作当中，学以致用。星球中不少小伙伴都成为了公司的核心技术骨干，实现了升职加薪的目标。

## 联系冰河

### 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`星球编号`。



<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">冰河微信</div>
    <br/>
</div>



### 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。内容在 **冰河技术** 微信公众号首发，强烈建议大家关注。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_wechat.jpg?raw=true" width="180px">
    <div style="font-size: 18px;">公众号：冰河技术</div>
    <br/>
</div>


### 视频号

定期分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/ice_video.png?raw=true" width="180px">
    <div style="font-size: 18px;">视频号：冰河技术</div>
    <br/>
</div>



### 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe.gitcode.host/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 18px;">知识星球：冰河技术</div>
    <br/>
</div>