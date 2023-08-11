---
layout: post
category: mycat-core-base
title: 第03章：Mycat核心配置文件schema.xml说明
tagline: by 冰河
tag: [mycat,mycat-core-base,mycat-core]
excerpt: 第03章：Mycat核心配置文件schema.xml说明
lock: need
---

# 《Mycat核心技术》第03章：Mycat核心配置文件schema.xml说明

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>星球项目地址：[https://binghe.gitcode.host/md/zsxq/introduce.html](https://binghe.gitcode.host/md/zsxq/introduce.html)

> 沉淀，成长，突破，帮助他人，成就自我。

* 本章难度：★★☆☆☆
* 本章重点：介绍Mycat核心配置文件schema.xml，理解schema.xml文件在Mycat中的作用，并能够在实际项目中灵活使用Mycat进行分库分表。

**大家好，我是冰河~~**

今天给大家介绍《Mycat核心技术》的第03章：给大家简单介绍下Mycat中的核心配置文件schema.xml，好了，开始今天的内容。

## 一、schema.xml文件概述

schema.xml作为Mycat中重要的配置文件之一，管理着Mycat的逻辑库、表、分片规则、DataNode以及DataSource。弄懂这些配置，是正确使用Mycat的前提。这里就一层层对该文件进行解析。

```html
<?xml version="1.0"?>
<!DOCTYPE mycat:schema SYSTEM "schema.dtd">
<mycat:schema xmlns:mycat="http://org.opencloudb/">

	<schema name="TESTDB" checkSQLschema="false" sqlMaxLimit="100">
		<table name="user" dataNode="dn1,dn2" rule="auto-sharding-long" />
		<table name="stat_tcp_stream" dataNode="dn2,dn3" rule="auto-sharding-long" />
	</schema>
	<dataNode name="dn1" dataHost="localhost1" database="mpos_tshark_miner_2014" />
	<dataNode name="dn2" dataHost="localhost2" database="mpos_tshark_miner2014" />
	<dataNode name="dn3" dataHost="localhost3" database="mpos_tshark_hrtel" />
	
	<dataHost name="localhost1" maxCon="1000" minCon="10" balance="0" dbType="mysql" dbDriver="jdbc" writeType="0" switchType="1"  slaveThreshold="100">
		<heartbeat>select user()</heartbeat>
		<writeHost host="hostM1" url="jdbc:mysql://192.168.1.150:5029" user="root" password="root"></writeHost>
	</dataHost>
	<dataHost name="localhost2" maxCon="1000" minCon="1" balance="0" dbType="mysql" dbDriver="jdbc"> 
		<heartbeat> 		</heartbeat>
		 <writeHost host="hostM2" url="jdbc:mysql://192.168.1.150:5029" user="root" 	password="root"></writeHost> 
	 </dataHost>		
	<dataHost name="localhost3" maxCon="1000" minCon="1" balance="0" dbType="mysql" dbDriver="jdbc"> 
		<heartbeat> 		</heartbeat>
		 <writeHost host="hostM3" url="jdbc:mysql://192.168.1.150:5029" user="root" 	password="root"></writeHost> 
	 </dataHost>		 
		 	<!--		
	  <dataHost name="oracle1" maxCon="1000" minCon="1" balance="0" writeType="0" 	dbType="oracle" dbDriver="jdbc"> <heartbeat>select 1 from dual</heartbeat> 
		<connectionInitSql>alter session set nls_date_format='yyyy-mm-dd hh24:mi:ss'</connectionInitSql> 
		<writeHost host="hostM1" url="jdbc:oracle:thin:@127.0.0.1:1521:nange" user="base" 	password="123456" > </writeHost> </dataHost> 
		
		<dataHost name="jdbchost" maxCon="1000" 	minCon="1" balance="0" writeType="0" dbType="mongodb" dbDriver="jdbc"> 
		<heartbeat>select 	user()</heartbeat> 
		<writeHost host="hostM" url="mongodb://192.168.0.99/test" user="admin" password="123456" ></writeHost> </dataHost> 
		
		<dataHost name="sparksql" maxCon="1000" minCon="1" balance="0" dbType="spark" dbDriver="jdbc"> 
		<heartbeat> </heartbeat>
		 <writeHost host="hostM1" url="jdbc:hive2://feng01:10000" user="jifeng" 	password="jifeng"></writeHost> </dataHost> -->

	<!-- <dataHost name="jdbchost" maxCon="1000" minCon="10" balance="0" dbType="mysql" 
		dbDriver="jdbc"> <heartbeat>select user()</heartbeat> <writeHost host="hostM1" 
		url="jdbc:mysql://localhost:3306" user="root" password="123456"> </writeHost> 
		</dataHost> -->
</mycat:schema>
```

## 二、schema标签的相关属性

### 1.dataNode

该属性用于绑定逻辑库到某个具体的database上，如果定义了这个属性，那么这个逻辑库就不能工作在分库分表模式下了。也就是说对这个逻辑库的所有操作会直接作用到绑定的dataNode上，这个schema就可以用作读写分离和主从切换，具体如下配置:

```html
<schema name="USERDB" checkSQLschema="false" sqlMaxLimit="100" dataNode="dn1">
<!—这里不能配置任何逻辑表信息-->
</schema>
```

那么现在USERDB就绑定到dn1所配置的具体database上，可以直接访问这个database。当然该属性只能配置绑定到一个database上，不能绑定多个dn。

### 2.checkSQLschema

当该值设置为 true 时，如果我们执行语句**select * from TESTDB.travelrecord;**则MyCat会把语句修改为**select * from travelrecord;**。即把表示schema的字符去掉，避免发送到后端数据库执行时报**（ERROR 1146 (42S02): Table ‘testdb.travelrecord’ doesn’t exist）。**不过，即使设置该值为 true ，如果语句所带的是并非是schema指定的名字，例如：**select * from db1.travelrecord;** 那么MyCat并不会删除db1这个字段，如果没有定义该库的话则会报错，所以在提供SQL语句的最好是不带这个字段。

### 3.sqlMaxLimit

当该值设置为某个数值时。每条执行的SQL语句，如果没有加上limit语句，MyCat也会自动的加上所对应的值。例如设置值为100，执行**select * from TESTDB.travelrecord;**的效果为和执行**select * from TESTDB.travelrecord limit 100;**相同。不设置该值的话，MyCat默认会把查询到的信息全部都展示出来，造成过多的输出。所以，在正常使用中，还是建议加上一个值，用于减少过多的数据返回。当然SQL语句中也显式的指定limit的大小，不受该属性的约束。

## 三、table标签

```html
<table name="travelrecord" dataNode="dn1,dn2,dn3" rule="auto-sharding-long" ></table>
```

Table 标签定义了MyCat中的逻辑表，所有需要拆分的表都需要在这个标签中定义。

### 1.name属性

定义逻辑表的表名，这个名字就如同我在数据库中执行create table命令指定的名字一样，同个schema标签中定义的名字必须唯一。

### 2.dataNode属性

定义这个逻辑表所属的dataNode, 该属性的值需要和dataNode标签中name属性的值相互对应。如果需要定义的dn过多可以使用如下的方法减少配置：

```html
<table name="travelrecord" dataNode="multipleDn$0-99,multipleDn2$100-199" rule="auto-sharding-long" ></table>
<dataNode name="multipleDn" dataHost="localhost1" database="db$0-99" ></dataNode>
<dataNode name="multipleDn2" dataHost="localhost1" database=" db$0-99" ></dataNode>
```

这里需要注意的是database属性所指定的真实database name需要在后面添加一个，例如上面的例子中，我需要在真实的mysql上建立名称为dbs0到dbs99的database。

### 3.rule属性

该属性用于指定逻辑表要使用的规则名字，规则名字在rule.xml中定义，必须与tableRule标签中name属性属性值一一对应。

### 4.primaryKey属性

该逻辑表对应真实表的主键，例如：分片的规则是使用非主键进行分片的，那么在使用主键查询的时候，就会发送查询语句到所有配置的DN上，如果使用该属性配置真实表的主键。难么MyCat会缓存主键与具体DN的信息，那么再次使用非主键进行查询的时候就不会进行广播式的查询，就会直接发送语句给具体的DN，但是尽管配置该属性，如果缓存并没有命中的话，还是会发送语句给具体的DN，来获得数据。

### 5.type属性

该属性定义了逻辑表的类型，目前逻辑表只有“全局表”和”普通表”两种类型。对应的配置：全局表：global。普通表：不指定该值为globla的所有表。

### 6.autoIncrement属性

MySQL对非自增长主键，使用last_insert_id()是不会返回结果的，只会返回0。所以，只有定义了自增长主键的表才可以用last_insert_id()返回主键值。mycat目前提供了自增长主键功能，但是如果对应的mysql节点上数据表，没有定义auto_increment，那么在mycat层调用last_insert_id()也是不会返回结果的。

由于insert操作的时候没有带入分片键，mycat会先取下这个表对应的全局序列，然后赋值给分片键。这样才能正常的插入到数据库中，最后使用last_insert_id()才会返回插入的分片键值。如果要使用这个功能最好配合使用数据库模式的全局序列。使用autoIncrement=“true” 指定这个表有使用自增长主键，这样mycat才会不抛出分片键找不到的异常。使用autoIncrement=“false” 来禁用这个功能，当然你也可以直接删除掉这个属性。默认就是禁用的。

### 7.needAddLimit属性

指定表是否需要自动的在每个语句后面加上limit限制。由于使用了分库分表，数据量有时会特别巨大。这时候执行查询语句，如果恰巧又忘记了加上数量限制的话。那么查询所有的数据出来，也够等上一小会儿的。所以，mycat就自动的为我们加上LIMIT 100。当然，如果语句中有limit，就不会在次添加了。这个属性默认为true,你也可以设置成false`禁用掉默认行为。

## 四、childTable标签

childTable标签用于定义E-R分片的子表。通过标签上的属性与父表进行关联。

```html
<table name="customer" primaryKey="ID" dataNode="dn1,dn2"
	rule="sharding-by-intfile">
	<childTable name="orders" primaryKey="ID" joinKey="customer_id"
		parentKey="id">
		<childTable name="order_items" joinKey="order_id"
			parentKey="id" />
	</childTable>
	<childTable name="customer_addr" primaryKey="ID" joinKey="customer_id"
		parentKey="id" />
</table>
```

### 1.name属性

定义子表的表名。

### 2.joinKey属性

插入子表的时候会使用这个列的值查找父表存储的数据节点。

### 3.parentKey属性

属性指定的值一般为与父表建立关联关系的列名。程序首先获取joinkey的值，再通过**parentKey**属性指定的列名产生查询语句，通过执行该语句得到父表存储在哪个分片上。从而确定子表存储的位置。

### 4.primaryKey属性

同table标签所描述的。

### 5.needAddLimit属性

同table标签所描述的。

## 五、dataNode标签

```html
<dataNode name="dn1" dataHost="lch3307" database="db1" ></dataNode>
```

dataNode 标签定义了MyCat中的数据节点，也就是我们通常说所的数据分片。一个**dataNode** 标签就是一个独立的数据分片。例子中所表述的意思为：使用名字为lch3307数据库实例上的db1物理数据库，这就组成一个数据分片，最后，我们使用名字dn1标识这个分片。

### 1.name属性

定义数据节点的名字，这个名字需要是唯一的，我们需要在table标签上应用这个名字，来建立表与分片对应的关系。

### 2.dataHost属性

该属性用于定义该分片属于哪个数据库实例的，属性值是引用dataHost标签上定义的name属性。

### 3.database属性

该属性用于定义该分片属性哪个具体数据库实例上的具体库，因为这里使用两个纬度来定义分片，就是：实例+具体的库。因为每个库上建立的表和表结构是一样的。所以这样做就可以轻松的对表进行水平拆分。

## 六、dataHost标签

作为Schema.xml中最后的一个标签，该标签在mycat逻辑库中也是作为最底层的标签存在，直接定义了具体的数据库实例、读写分离配置和心跳语句。现在我们就解析下这个标签。

```html
<dataHost name="localhost1" maxCon="1000" minCon="10" balance="0"
writeType="0" dbType="mysql" dbDriver="native">
<heartbeat>select user()</heartbeat>
<!-- can have multi write hosts -->
<writeHost host="hostM1" url="localhost:3306" user="root"
password="123456">
<!-- can have multi read hosts -->
<!-- <readHost host="hostS1" url="localhost:3306" user="root" password="123456"
/> -->
</writeHost>
<!-- <writeHost host="hostM2" url="localhost:3316" user="root" password="123456"/> -->
</dataHost>
```

### 1.name属性

唯一标识dataHost标签，供上层的标签使用。

### 2.maxCon属性

指定每个读写实例连接池的最大连接。也就是说，标签内嵌套的writeHost、readHost标签都会使用这个属性的值来实例化出连接池的最大连接数。

### 3.minCon属性

指定每个读写实例连接池的最小连接，初始化连接池的大小。

### 4.balance属性

负载均衡类型，目前的取值有3种：

* balance=“0”, 所有读操作都发送到当前可用的writeHost上。
* balance=“1”，所有读操作都随机的发送到readHost。
* balance=“2”，所有读操作都随机的在writeHost、readhost上分发。

### 5.writeType属性

负载均衡类型，目前的取值有3种：

* writeType=“0”, 所有写操作都发送到可用的writeHost上。
* writeType=“1”，所有写操作都随机的发送到readHost。
* writeType=“2”，所有写操作都随机的在writeHost、readhost分上发。

### 6.dbType属性

指定后端连接的数据库类型，目前支持二进制的mysql协议，还有其他使用JDBC连接的数据库。例如：mongodb、oracle、spark等。

### 7.dbDriver属性

指定连接后端数据库使用的Driver，目前可选的值有native和JDBC。使用native的话，因为这个值执行的是二进制的mysql协议，所以可以使用mysql和maridb。其他类型的数据库则需要使用JDBC驱动来支持。如果使用JDBC的话需要将符合JDBC 4标准的驱动JAR包放到MYCAT\lib目录下，并检查驱动JAR包中包括如下目录结构的文件：META-INF\services\java.sql.Driver。在这个文件内写上具体的Driver类名，例如：com.mysql.jdbc.Driver。

## 七、heartbeat标签

这个标签内指明用于和后端数据库进行心跳检查的语句。例如,MYSQL可以使用select user()，Oracle可以使用select 1 from dual等。这个标签还有一个connectionInitSql属性，主要是当使用Oracla数据库时，需要执行的初始化SQL语句就这个放到这里面来。例如：alter session set nls_date_format='yyyy-mm-dd hh24:mi:ss'

## 八、writeHost标签、readHost标签

这两个标签都指定后端数据库的相关配置给mycat，用于实例化后端连接池。唯一不同的是，writeHost指定写实例、readHost指定读实例，组着这些读写实例来满足系统的要求。在一个dataHost内可以定义多个writeHost和readHost。但是，如果writeHost指定的后端数据库宕机，那么这个writeHost绑定的所有readHost都将不可用。另一方面，由于这个writeHost宕机系统会自动的检测到，并切换到备用的writeHost上去。这两个标签的属性相同，这里就一起介绍。

### 1.host属性

用于标识不同实例，一般writeHost我们使用*M1，readHost我们用*S1。

### 2.url属性

后端实例连接地址，如果是使用native的dbDriver，则一般为address:port这种形式。用JDBC或其他的dbDriver，则需要特殊指定。当使用JDBC时则可以这么写：jdbc:mysql://localhost:3306/。

### 3.user属性

后端存储实例需要的用户名字

### 4.password属性

后端存储实例需要的密码

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