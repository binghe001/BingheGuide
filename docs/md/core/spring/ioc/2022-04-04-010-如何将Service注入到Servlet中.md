---
layout: post
category: binghe-spring-ioc
title: 【Spring注解驱动开发】面试官：如何将Service注入到Servlet中？朋友又栽了！！
tagline: by 冰河
tag: [spring.spring-ioc,binghe-spring-ioc]
excerpt: 最近，一位读者出去面试前准备了很久，信心满满的去面试。没想到面试官的一个问题把他难住了。面试官的问题是这样的：如何使用Spring将Service注入到Servlet中呢？这位读者平时也是很努力的，看什么源码啊、多线程啊、高并发啊、设计模式啊等等。没想到却在一个很简单的问题上栽了跟头，这就说明学习知识要系统化，要有条理，切忌东学一点，西记一点，否则，到头来，啥也学不到。
lock: need
---

# 【Spring注解驱动开发】面试官：如何将Service注入到Servlet中？朋友又栽了！！

## 写在前面

> 最近，一位读者出去面试前准备了很久，信心满满的去面试。没想到面试官的一个问题把他难住了。面试官的问题是这样的：如何使用Spring将Service注入到Servlet中呢？这位读者平时也是很努力的，看什么源码啊、多线程啊、高并发啊、设计模式啊等等。没想到却在一个很简单的问题上栽了跟头，这就说明学习知识要系统化，要有条理，切忌东学一点，西记一点，否则，到头来，啥也学不到。
>
> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

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

> 项目工程源码已经提交到GitHub：[https://github.com/sunshinelyz/spring-annotation](https://github.com/sunshinelyz/spring-annotation)

## 写在最后

> 如果觉得文章对你有点帮助，请微信搜索并关注「 冰河技术 」微信公众号，跟冰河学习Spring注解驱动开发。公众号回复“spring注解”关键字，领取Spring注解驱动开发核心知识图，让Spring注解驱动开发不再迷茫。

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)