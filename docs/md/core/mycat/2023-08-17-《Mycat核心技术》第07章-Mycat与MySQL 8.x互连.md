---
layout: post
category: mycat-core-base
title: 第07章：Mycat与MySQL 8.x互连
tagline: by 冰河
tag: [mycat,mycat-core-base,mycat-core]
excerpt: 第07章：Mycat与MySQL 8.x互连
lock: need
---

# 《Mycat核心技术》第07章：Mycat与MySQL 8.x互连

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>星球项目地址：[https://binghe.gitcode.host/md/zsxq/introduce.html](https://binghe.gitcode.host/md/zsxq/introduce.html)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：介绍Mycat如何与MySQL8.x版本相互连接，并能够在实际项目中灵活使用Mycat进行分库分表。

**大家好，我是冰河~~**

今天给大家介绍《Mycat核心技术》的第07章：给大家简单介绍下Mycat如何与MySQL8.x实现互连，好了，开始今天的内容。

本文教你如何实现Mycat与MySQL 8.x互连，也就是说实现Mycat连接MySQL 8.x数据库，同时，实现使用MySQL 8.x的命令行连接Mycat。

## 一、创建MySQL用户

首先，在MySQL8.x中创建Mycat连接MySQL的用户，如下所示。

```sql
CREATE USER 'mycat'@'192.168.175.%' IDENTIFIED BY 'mycat';
ALTER USER 'mycat'@'192.168.175.%' IDENTIFIED WITH mysql_native_password BY 'mycat'; 
GRANT SELECT, INSERT, UPDATE, DELETE  ON *.* TO 'mycat'@'192.168.175.%';
FLUSH PRIVILEGES;
```

## 二、配置schema.xml文件

```html
<?xml version="1.0"?>
<!DOCTYPE mycat:schema SYSTEM "schema.dtd">
<mycat:schema xmlns:mycat="http://io.mycat/">

	<schema name="shop" checkSQLschema="false" sqlMaxLimit="1000">
		<table name="order_master" primaryKey="order_id" dataNode = "ordb"/>
		<table name="order_detail" primaryKey="order_detail_id" dataNode = "ordb"/>
		<table name="order_cart" primaryKey="cart_id" dataNode = "ordb"/>
		<table name="order_customer_addr" primaryKey="customer_addr_id" dataNode = "ordb"/>
		<table name="region_info" primaryKey="region_id" dataNode = "ordb"/>
		<table name="serial" primaryKey="id" dataNode = "ordb"/>
		<table name="shipping_info" primaryKey="ship_id" dataNode = "ordb"/>
		<table name="warehouse_info" primaryKey="w_id" dataNode = "ordb"/>
		<table name="warehouse_proudct" primaryKey="wp_id" dataNode = "ordb"/>
		
		<table name="product_brand_info" primaryKey="brand_id" dataNode = "prodb"/>
		<table name="product_category" primaryKey="category_id" dataNode = "prodb"/>
		<table name="product_comment" primaryKey="comment_id" dataNode = "prodb"/>
		<table name="product_info" primaryKey="product_id" dataNode = "prodb"/>
		<table name="product_pic_info" primaryKey="product_pic_id" dataNode = "prodb"/>
		<table name="product_supplier_info" primaryKey="supplier_id" dataNode = "prodb"/>
		
		<table name="customer_balance_log" primaryKey="balance_id" dataNode = "custdb"/>
		<table name="customer_inf" primaryKey="customer_inf_id" dataNode = "custdb"/>
		<table name="customer_level_inf" primaryKey="customer_level" dataNode = "custdb"/>
		<table name="customer_login" primaryKey="customer_id" dataNode = "custdb"/>
		<table name="customer_login_log" primaryKey="login_id" dataNode = "custdb"/>
		<table name="customer_point_log" primaryKey="point_id" dataNode = "custdb"/>
		
	</schema>
	 
	<dataNode name="ordb" dataHost="binghe152" database="order_db" />
	<dataNode name="prodb" dataHost="binghe153" database="product_db" />
	<dataNode name="custdb" dataHost="binghe154" database="customer_db" />

	
	<dataHost name="binghe152" maxCon="1000" minCon="10" balance="1"
			  writeType="0" dbType="mysql" dbDriver="native" switchType="1"  slaveThreshold="100">
		<heartbeat>select user()</heartbeat>
		<writeHost host="binghe52" url="192.168.175.152:3306" user="root" password="root"/>
	</dataHost>
	
	<dataHost name="binghe153" maxCon="1000" minCon="10" balance="1"
			  writeType="0" dbType="mysql" dbDriver="native" switchType="1"  slaveThreshold="100">
		<heartbeat>select user()</heartbeat>
		<writeHost host="binghe53" url="192.168.175.153:3306" user="root" password="root"/>
	</dataHost>
	
	<dataHost name="binghe154" maxCon="1000" minCon="10" balance="1"
			  writeType="0" dbType="mysql" dbDriver="native" switchType="1"  slaveThreshold="100">
		<heartbeat>select user()</heartbeat>
		<writeHost host="binghe54" url="192.168.175.154:3306" user="root" password="root"/>
	</dataHost>
	
</mycat:schema>
```

## 三、配置server.xml文件

```html
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mycat:server SYSTEM "server.dtd">
<mycat:server xmlns:mycat="http://io.mycat/">
	<system>
		<property name="useHandshakeV10">1</property>
        <property name="defaultSqlParser">druidparser</property>
		<property name="serverPort">3307</property>
		<property name="managerPort">3308</property>
		<property name="nonePasswordLogin">0</property>
		<property name="bindIp">0.0.0.0</property>
		<property name="charset">utf8mb4</property>
		<property name="frontWriteQueueSize">2048</property>
		<property name="txIsolation">2</property>
		<property name="processors">2</property>
		<property name="idleTimeout">1800000</property>
		<property name="sqlExecuteTimeout">300</property>
		<property name="useSqlStat">0</property>
		<property name="useGlobleTableCheck">0</property>
		<property name="sequenceHandlerType">2</property>
		<property name="defaultMaxLimit">1000</property>
		<property name="maxPacketSize">104857600</property>
	</system>
	
	<user name="mycat" defaultAccount="true">
		<property name="usingDecrypt">1</property>
		<property name="password">cTwf23RrpBCEmalp/nx0BAKenNhvNs2NSr9nYiMzHADeEDEfwVWlI6hBDccJjNBJqJxnunHFp5ae63PPnMfGYA==</property>
		<property name="schemas">shop</property>
	</user>
</mycat:server>
```

注意：在需要使用MySQL 8.x的mysql命令连接Mycat时，在server.xml文件的system标签下必须配置如下选项。

```html
<property name="useHandshakeV10">1</property>
<property name="defaultSqlParser">druidparser</property>
```

否则，MySQL 8.x的mysql命令连接Mycat会失败。

user标签下的password标签的值为登录Mycat的密码，此值使用Mycat提供的加密类对密码明文进行了加密。此类存在于Mycat安装目录下的lib目录下的Mycat-server-xxx-release.jar中的io.mycat.util.DecryptUtil类，可以使用如下命令对密码进行加密。

```bash
java java -cp /usr/local/mycat/lib/Mycat-server-xxx-release.jar io.mycat.util.DecryptUtil 0:mycat:mycat
```

其中0:mycat:mycat为运行Jar包的参数，0表示应用程序连接Mycat时使用密文密码；第一个mycat代表连接Mycat的用户名，也就是说为哪个用户的密码加密；第二个mycat代表需要加密的密码。

加密后的结果数据如下所示

```bash
cTwf23RrpBCEmalp/nx0BAKenNhvNs2NSr9nYiMzHADeEDEfwVWlI6hBDccJjNBJqJxnunHFp5ae63PPnMfGYA==
```

即user标签下的password属性的值。

如果按照上述方式为连接Mycat的密码加密后，需要在user标签下配置如下选项，否则无法正确连接Mycat

```html
<property name="usingDecrypt">1</property>
```

## 四、连接Mycat

使用MySQL 8.x中的mysql命令连接Mycat，如下所示。

```sql
[root@binghe151 ~]# mysql -umycat -pmycat -h192.168.175.151 -P3307 --default-auth=mysql_native_password
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2
Server version: 5.6.29-mycat-xxx-release-20200228205020 MyCat Server (OpenCloudDB)

Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

使用MySQL8.x中的mysql命令连接Mycat时，需要注意的是要在mysql命令后面添加--default-auth=mysql_native_password选项。

接下来，查看下Mycat下的逻辑库和逻辑表，如下所示。

```sql
mysql> SHOW DATABASES;
+----------+
| DATABASE |
+----------+
| shop     |
+----------+
1 row in set (0.00 sec)

mysql> USE shop;
Database changed
mysql> SHOW TABLES;
+-----------------------+
| Tables in shop        |
+-----------------------+
| customer_balance_log  |
| customer_inf          |
| customer_level_inf    |
| customer_login        |
| customer_login_log    |
| customer_point_log    |
| order_cart            |
| order_customer_addr   |
| order_detail          |
| order_master          |
| product_brand_info    |
| product_category      |
| product_comment       |
| product_info          |
| product_pic_info      |
| product_supplier_info |
| region_info           |
| serial                |
| shipping_info         |
| warehouse_info        |
| warehouse_proudct     |
+-----------------------+
21 rows in set (0.00 sec)

mysql> SELECT product_id, product_code, product_name FROM product_info LIMIT 10;
+------------+------------------+---------------------------------------+
| product_id | product_code     | product_name                          |
+------------+------------------+---------------------------------------+
|          1 | 3700000000000001 | [Columbia]打底裤示例商品-1            |
|          2 | 3600000000000001 | [TheNorthFace]小脚裤示例商品-1        |
|          3 | 3500000000000001 | [李宁]九分裤示例商品-1                |
|          4 | 3400000000000001 | [LOWA]哈伦裤示例商品-1                |
|          5 | 3300000000000001 | [JACK&JONES]连体裤示例商品-1          |
|          6 | 3200000000000001 | [诺诗兰]牛仔裤示例商品-1              |
|          7 | 3100000000000001 | [骆驼]休闲裤示例商品-1                |
|          8 | 3000000000000001 | [金狐狸]风衣示例商品-1                |
|          9 | 2900000000000001 | [Columbia]小西装示例商品-1            |
|         10 | 2800000000000001 | [李宁]外套示例商品-1                  |
+------------+------------------+---------------------------------------+
10 rows in set (0.01 sec)
```

**好了，今天就到这儿吧，我是冰河，我们下期见~~**

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