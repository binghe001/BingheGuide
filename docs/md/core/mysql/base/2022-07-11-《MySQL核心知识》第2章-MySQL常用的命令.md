---
layout: post
category: binghe-mysql-base
title: 第2章：MySQL常用的命令
tagline: by 冰河
tag: [mysql,binghe-mysql-base]
excerpt: 第2章：MySQL常用的命令
lock: need
---

# 《MySQL核心知识》第2章：MySQL常用的命令

> 《RPC手撸专栏》已经在 **冰河技术** 知识星球开始更新了，冰河要带你从零开始手撸一个可在实际环境使用的高性能、可扩展的RPC框架，想要一起手撸RPC的小伙伴文末有加入星球的方式。

**大家好，我是冰河~~**

今天是《MySQL核心知识》的第2章，今天给大家讲讲MySQL的常用命令，好了，不多说了，开始今天的正题。

## MySQL常用命令

* 启动：net start mySql;
* 进入：mysql -u root -p/mysql -h localhost -u root -p databaseName;
* 列出数据库：show databases;
* 选择数据库：use databaseName;
* 列出数据表：show tables；
* 显示表格列的属性：show columns from tableName；
* 建立数据库：source fileName.txt;
* 匹配字符：可以用通配符_代表任何一个字符，％代表任何字符串;
* 增加一个字段：alter table tabelName add column fieldName dateType;
* 增加多个字段：alter table tabelName add column fieldName1 dateType,add columns fieldName2 dateType;
* 多行命令输入:注意不能将单词断开;当插入或更改数据时，不能将字段的字符串展开到多行里，否则硬回车将被储存到数据中;
* 增加一个管理员帐户：grant all on *.* to user@localhost identified by "password";
* 每条语句输入完毕后要在末尾填加分号';'，或者填加'\g'也可以；
* 查询时间：select now();
* 查询当前用户：select user();
* 查询数据库版本：select version();
* 查询当前使用的数据库：select database();

1、删除student_course数据库中的students数据表：

```sql
rm -f student_course/students.*
```

2、备份数据库：(将数据库test备份)

```sql
mysqldump -u root -p test>c:\test.txt
```

备份表格：(备份test数据库下的mytable表格)

```sql
mysqldump -u root -p test mytable>c:\test.txt
```

将备份数据导入到数据库：(导回test数据库)

```sql
mysql -u root -p test<c:\test.txt
```

3、创建临时表：(建立临时表zengchao)

```sql
create temporary table zengchao(name varchar(10));
```

4、创建表是先判断表是否存在

```sql
create table if not exists students(……);
```

5、从已经有的表中复制表的结构

```sql
create table table2 select * from table1 where 1<>1;
```

6、复制表

```sql
create table table2 select * from table1;
```

7、对表重新命名

```sql
alter table table1 rename as table2;
```

8、修改列的类型

```sql
alter table table1 modify id int unsigned;//修改列id的类型为int unsigned
alter table table1 change id sid int unsigned;//修改列id的名字为sid，而且把属性修改为int unsigned
```

9、创建索引

```sql
alter table table1 add index ind_id (id);
create index ind_id on table1 (id);
create unique index ind_id on table1 (id);//建立唯一性索引
```

10、删除索引

```sql
drop index idx_id on table1;
alter table table1 drop index ind_id;
```

11、联合字符或者多个列(将列id与":"和列name和"="连接)

```sql
select concat(id,':',name,'=') from students;
```

12、limit(选出10到20条)<第一个记录集的编号是0>

```sql
select * from students order by id limit 9,10;
```

13、MySQL支持的功能

事务，视图，外键和引用完整性，存储过程和触发器

14、MySQL会使用索引的操作符号

```sql
<,<=,>=,>,=,between,in,不带%或者_开头的like
```

15、使用索引的缺点

1)减慢增删改数据的速度；

2）占用磁盘空间；

3）增加查询优化器的负担；

当查询优化器生成执行计划时，会考虑索引，太多的索引会给查询优化器增加工作量，导致无法选择最优的查询方案；

16、分析索引效率

方法：在一般的SQL语句前加上explain；

分析结果的含义：

1）table：表名；

2）type：连接的类型，(ALL/Range/Ref)。其中ref是最理想的；

3）possible_keys：查询可以利用的索引名；

4）key：实际使用的索引；

5）key_len：索引中被使用部分的长度（字节）；

6）ref：显示列名字或者"const"（不明白什么意思）；

7）rows：显示MySQL认为在找到正确结果之前必须扫描的行数；

8）extra：MySQL的建议；

17、使用较短的定长列

1）尽可能使用较短的数据类型；

2）尽可能使用定长数据类型；

a）用char代替varchar，固定长度的数据处理比变长的快些；

b）对于频繁修改的表，磁盘容易形成碎片，从而影响数据库的整体性能；

c）万一出现数据表崩溃，使用固定长度数据行的表更容易重新构造。使用固定长度的数据行，每个记录的开始位置都是固定记录长度的倍数，可以很容易被检测到，但是使用可变长度的数据行就不一定了；

d）对于MyISAM类型的数据表，虽然转换成固定长度的数据列可以提高性能，但是占据的空间也大；

18、使用not null和enum

尽量将列定义为not null，这样可使数据的出来更快，所需的空间更少，而且在查询时，MySQL不需要检查是否存在特例，即null值，从而优化查询；

如果一列只含有有限数目的特定值，如性别，是否有效或者入学年份等，在这种情况下应该考虑将其转换为enum列的值，MySQL处理的更快，因为所有的enum值在系统内都是以标识数值来表示的；

19、使用optimize table

对于经常修改的表，容易产生碎片，使在查询数据库时必须读取更多的磁盘块，降低查询性能。具有可变长的表都存在磁盘碎片问题，这个问题对blob数据类型更为突出，因为其尺寸变化非常大。可以通过使用optimize table来整理碎片，保证数据库性能不下降，优化那些受碎片影响的数据表。 optimize table可以用于MyISAM和BDB类型的数据表。实际上任何碎片整理方法都是用mysqldump来转存数据表，然后使用转存后的文件并重新建数据表；

20、使用procedure analyse()

可以使用procedure analyse()显示最佳类型的建议，使用很简单，在select语句后面加上procedure analyse()就可以了；例如：

```sql
select * from students procedure analyse();
select * from students procedure analyse(16,256);
```

第二条语句要求procedure analyse()不要建议含有多于16个值，或者含有多于256字节的enum类型，如果没有限制，输出可能会很长；

21、使用查询缓存

1）查询缓存的工作方式：

第一次执行某条select语句时，服务器记住该查询的文本内容和查询结果，存储在缓存中，下次碰到这个语句时，直接从缓存中返回结果；当更新数据表后，该数据表的任何缓存查询都变成无效的，并且会被丢弃。

2）配置缓存参数：

变量：query_cache _type，查询缓存的操作模式。

有3中模式：

* 0：不缓存；
* 1：缓存查询，除非与select sql_no_cache开头；
* 2：根据需要只缓存那些以select sql_cache开头的查询；

query_cache_size：设置查询缓存的最大结果集的大小，比这个值大的不会被缓存。

22、调整硬件

1）在机器上装更多的内存；

2）增加更快的硬盘以减少I/O等待时间；

寻道时间是决定性能的主要因素，逐字地移动磁头是最慢的，一旦磁头定位，从磁道读则很快；

3）在不同的物理硬盘设备上重新分配磁盘活动；

如果可能，应将最繁忙的数据库存放在不同的物理设备上，这跟使用同一物理设备的不同分区是不同的，因为它们将争用相同的物理资源（磁头）。

```sql
create database name; 创建数据库
use databasename; 选择数据库
drop database name 直接删除数据库，不提醒
show tables; 显示表
describe tablename; 表的详细描述
select 中加上distinct去除重复字段
mysqladmin drop databasename 删除数据库前，有提示。
select version(),current_date; 显示当前mysql版本和当前日期
```

23、修改mysql中root的密码：

```sql
shell>mysql -u root -p
mysql> update user set password=password(”xueok654123″) where user=’root’;
mysql> flush privileges //刷新数据库
mysql>use dbname； 打开数据库：
mysql>show databases; 显示所有数据库
mysql>show tables; 显示数据库mysql中所有的表：先use mysql；然后
mysql>describe user; 显示表mysql数据库中user表的列信息）；
```

24、grant

创建一个可以从任何地方连接服务器的一个完全的超级用户，但是必须使用一个口令something做这个

```sql
mysql> grant all privileges on . to identified by ’something’ with
```

增加新用户

格式：grant select on 数据库.* to 用户名@登录主机 identified by “密码”

```sql
GRANT ALL PRIVILEGES ON . TO IDENTIFIED BY ’something’ WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON . TO ” IDENTIFIED BY ’something’ WITH GRANT OPTION;
```

删除授权：

```sql
mysql> revoke all privileges on . from ”;
mysql> delete from user where user=”root” and host=”%”;
mysql> flush privileges;
```

创建一个用户custom在特定客户端it363.com登录，可访问特定数据库fangchandb

```sql
mysql >grant select, insert, update, delete, create,drop on fangchandb.* to custom@ it363.com identified by ‘ passwd’
```

重命名表:

```sql
mysql > alter table t1 rename t2;
```

25、mysqldump

备份数据库

```sql
shell> mysqldump -h host -u root -p dbname >dbname_backup.sql
```

恢复数据库

```sql
shell> mysqladmin -h myhost -u root -p create dbname
shell> mysqldump -h host -u root -p dbname < dbname_backup.sql
```

如果只想卸出建表指令，则命令如下：

```sql
shell> mysqladmin -u root -p -d databasename > a.sql
```

如果只想卸出插入数据的sql命令，而不需要建表命令，则命令如下：

```sql
shell> mysqladmin -u root -p -t databasename > a.sql
```

那么如果我只想要数据，而不想要什么sql命令时，应该如何操作呢？

```sql
mysqldump -T./ phptest driver
```

其中，只有指定了-T参数才可以卸出纯文本文件，表示卸出数据的目录，./表示当前目录，即与mysqldump同一目录。如果不指定driver 表，则将卸出整个数据库的数据。每个表会生成两个文件，一个为.sql文件，包含建表执行。另一个为.txt文件，只包含数据，且没有sql指令。

26、可将查询存储在一个文件中并告诉mysql从文件中读取查询而不是等待键盘输入。可利用外壳程序键入重定向实用程序来完成这项工作。例如，如果在文件my_file.sql 中存放有查询，可如下执行这些查询：

例如，如果您想将建表语句提前写在sql.txt中:

```sql
mysql > mysql -h myhost -u root -p database < sql.txt
```

**好了，今天的文章就到这儿吧，如果文章对你有点帮助，记得给冰河一键三连哦，欢迎将文章转发给更多的小伙伴，冰河将不胜感激~~**

## 关于星球

**冰河技术** 知识星球《RPC手撸专栏》已经开始了，我会将《RPC手撸专栏》的源码放到知识星球中，同时在微信上会创建专门的知识星球群，冰河会在知识星球上和星球群里解答球友的提问。

### 星球提供的服务

冰河整理了星球提供的一些服务，如下所示。

加入星球，你将获得： 

1.学习从零开始手撸可用于实际场景的高性能、可扩展的RPC框架项目

2.学习SpringCloud Alibaba实战项目—从零开发微服务项目 

3.学习高并发、大流量业务场景的解决方案，体验大厂真正的高并发、大流量的业务场景 

4.学习进大厂必备技能：性能调优、并发编程、分布式、微服务、框架源码、中间件开发、项目实战 

5.提供站点 https://binghe001.github.io 所有学习内容的指导、帮助 

6.GitHub：https://github.com/binghe001/BingheGuide - 非常有价值的技术资料仓库，包括冰河所有的博客开放案例代码 

7.可以发送你的简历到我的邮箱，提供简历批阅服务 

8.提供技术问题、系统架构、学习成长、晋升答辩等各项内容的回答 

9.定期的整理和分享出各类专属星球的技术小册、电子书、编程视频、PDF文件 

10.定期组织技术直播分享，传道、授业、解惑，指导阶段瓶颈突破技巧

### 如何加入星球

* **链接** ：打开链接 [http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs) 加入星球。
* **回复** ：在公众号 **冰河技术** 回复 **星球** 领取优惠券加入星球。

**特别提醒：** 苹果用户进圈或续费，请加微信 **hacker_binghe** 扫二维码，或者去公众号 **冰河技术** 回复 **星球** 扫二维码加入星球。


![sa-2022-04-21-007](https://binghe001.github.io/assets/images/microservices/springcloudalibaba/sa-2022-04-28-008.png)

**如果图片二维码过期，去公众号 冰河技术 回复 星球 扫二维码加入星球, 好了，今天就到这儿吧，我是冰河，我们下期见~~**

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)

## 加群交流

本群的宗旨是给大家提供一个良好的技术学习交流平台，所以杜绝一切广告！由于微信群人满 100 之后无法加入，请扫描下方二维码先添加作者 “冰河” 微信(hacker_binghe)，备注：`学习加群`。



<div align="center">
    <img src="https://binghe001.github.io/images/personal/hacker_binghe.jpg?raw=true" width="180px">
    <div style="font-size: 9px;">冰河微信</div>
    <br/>
</div>



## 公众号

分享各种编程语言、开发技术、分布式与微服务架构、分布式数据库、分布式事务、云原生、大数据与云计算技术和渗透技术。另外，还会分享各种面试题和面试技巧。

<div align="center">
    <img src="https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true" width="180px">
    <div style="font-size: 9px;">公众号：冰河技术</div>
    <br/>
</div>


## 星球

加入星球 **[冰河技术](http://m6z.cn/6aeFbs)**，可以获得本站点所有学习内容的指导与帮助。如果你遇到不能独立解决的问题，也可以添加冰河的微信：**hacker_binghe**， 我们一起沟通交流。另外，在星球中不只能学到实用的硬核技术，还能学习**实战项目**！

关注 [冰河技术](https://img-blog.csdnimg.cn/20210426115714643.jpg?raw=true)公众号，回复 `星球` 可以获取入场优惠券。

<div align="center">
    <img src="https://binghe001.github.io/images/personal/xingqiu.png?raw=true" width="180px">
    <div style="font-size: 9px;">知识星球：冰河技术</div>
    <br/>
</div>