# Doris使用及优化（1.2.6 - 2.0.2 release）

文章内容是在使用Doris的过程中逐渐积累，但也只是针对使用的经验，请大家参照的时候要综合考虑自己方使用的情况而定。

官方有很多使用及优化的方式方法，建议小伙伴们把官方文档多读几遍，doris官方文档写的相当不错！

官方文档：[https://doris.apache.org/zh-CN/docs/get-starting/what-is-apache-doris](https://doris.apache.org/zh-CN/docs/get-starting/what-is-apache-doris)

该文档会在后续的使用过程中，不断更新。

**1.缓存优化，对于T+1类型的数据，有很好的查询效率提升**

增加set [global] enable_sql_cache=true;在FE节点上，可以开启SQL缓存，提升查询效率
增加set [global] enable_partition_cache=true; 在FE节点上，可以开启分区缓存，提升查询效率

**2.用with定义临时表，通过select查询with临时表的数据，不能得到预期的正确计算结果**

在be节点增加 enable_low_cardinality_optimize=false;配置，并重启be。

**3.当升级doris时fe日志循环出现以下内容:**

```bash
2023-04-25 18:42:48,217 INFO(UNKNOWN192168.16 44 9010 1651040787813( [Env.waitForReady(():896] wait catalo 
g to be ready. FE type: UNKNOWN. is ready: false counter: 1701 
2023-04-25 18:42:50,223 INFO(UNKNOWN 192168.1644 9010 1651040787813(-1)11)「Env.waitForReady():896l wait catalo
g to be ready. FE type: UNKNOWN. is ready: false counter:1721 
2023-04-25 18:42:52,230 INFO(UNKNOWN192168.16 44 9010 1651040787813(-1)11)[Env.waitForReady():896] wait catalo 
g to be ready. FE type: UNKNOWN. is ready: false counter: 1741 
......
```

在 master fe.conf 添加配置：metadata_failure_recovery=true，然后重启，正常之后，关闭这个再重新启动。

**4.关于Doris中使用Catalog进行insert into select进行数据导入动作时，语句中带有with子查询的正确使用姿势**

```sql
INSERT INTO
test.description1 (attention)
WITH temp1 AS (SELECT '李四测试3' as `attention`),
	 temp2 AS (SELECT '张三测试1' as `attention`)
SELECT attention from temp1
UNION ALL SELECT attention FROM temp2;
```

**5.Doris中通过Catalog insert to hana需要注意的是**

速度太慢，经测试5分钟插入20000条左右数据，各位换其他方式吧。不过Doris在2.0以后的版本已经解决。

【Doris在2.0之后的版本有提升，可以使用2.0之后的版本提升Doris insert hana的速率】

> 2.0.2版本之后，Doris to Hana已经有了很好的提升，效率还不错。上面这个不再是问题。

**6.Doris从1.2.2之后支持自动分桶**

[https://doris.apache.org/zh-CN/docs/table-design/data-partition/#%E8%87%AA%E5%8A%A8%E5%88%86%E6%A1%B6](https://doris.apache.org/zh-CN/docs/table-design/data-partition/#%E8%87%AA%E5%8A%A8%E5%88%86%E6%A1%B6)

**7.要删除一个带有分区的表数据时，直接使用delete from不能删除**

可以在执行delete前，先执行set delete_without_partition = true;，或者在删除数据时，指定数据所在分区

**8.Catalog的JDBC总断开连接，怎么办**
 请在`jdbc_url`后面加上`reconnect=true`吧。我建议能加的都加一下，并且源头库的类似超时设置搞的长一点。

**9.varchar 类型数据导入时，当数据长度超出预期，会导致丢数据**

 调整varchar 规定长度至正常的百分之20~30，或者采用string类型（如果是key不能使用string类型）

**10.doris 产生了异常的tablet**

```bash
# 正常来讲，如果doris没有写入数据，下面两条语句查不出东西
SHOW PROC '/cluster_balance/pending_tablets';
 
SHOW PROC '/cluster_balance/running_tablets';
 
# 查看数据库tabelt的状态
SHOW PROC '/cluster_health/tablet_health';
可以看到不健康副本有五个
----
10405   default_cluster:dim 18  13  5
----
 
# 查看指定DbId的不健康的tablet
SHOW PROC '/cluster_health/tablet_health/2116843'
----
2279433,2279437
----
# 可以查看tablet属于哪张表
SHOW TABLET 2279437;
# 查看表（分区）级别状态的tablet信息
ADMIN SHOW REPLICA STATUS FROM stat_users_count dxuc
# 如果上面那个表报错
----
SQL 错误 [S1000]
----
# 如果上面的SQL中的表还能打开，创建新表迁移数据
# 所以我认为，简单粗暴的方式修复不健康tablet，直接重做表比较好
use ods_xmcx;
create table bike1 as select * from bike;
drop table bike;
ALTER TABLE bike1 RENAME bike;
TRUNCATE TABLE orders;
# 对于大表来说转表比较慢，也可以用这个方法，干掉不健康tablet
ADMIN SET REPLICA STATUS PROPERTIES("tablet_id" = "10001", "backend_id" = "20001", "status" = "bad");
```

**11.可以通过在建表时加上"light_schema_change"="true" ，以支持动态修改列，而且速度很快。**

**12.对于有字段为NULL的计算，向量化引擎支持不好，建议在表中插入数据时不要有NULL出现，以最大程度使用向量化引擎优势。**

**13.因查询过大导致了be宕机**

通过设置加大单查询的使用内存，基本可以解决。例如设置成8GB，SET exec_mem_limit = 8589934592;
如果有OOM出现，需要分析BE OOM的原因。

分析BE OOM的原因可以参考：[https://doris.apache.org/zh-CN/docs/admin-manual/memory-management/be-oom-analysis](https://doris.apache.org/zh-CN/docs/admin-manual/memory-management/be-oom-analysis)

**14.关于使用Catalog写入数据至Doris的事务问题**

Doris的数据是由一组batch的方式写入外部表的，如果中途导入中断，之前写入数据可能需要回滚。所以JDBC外表支持数据写入时的事务，事务的支持需要通过设置session variable: enable_odbc_transcation 。

set enable_odbc_transcation = true;

事务保证了JDBC外表数据写入的原子性，但是一定程度上会降低数据写入的性能，可以考虑酌情开启该功能。

**15.如果需要看Doris每次执行的sql，可以打开审计日志功能**

Doris审计日志：[https://doris.apache.org/zh-CN/docs/admin-manual/audit-plugin](https://doris.apache.org/zh-CN/docs/admin-manual/audit-plugin)

对于后面结合doris元数据实现血缘分析很有作用。

注意：审计表的stmt字段是STRING类型，但SQL过长，只能记录4096个长度。
如果需要完整记录SQL，设置 fe/plugins/AuditLoader/plugin.conf 中的 max_stmt_length=100000

**16.关于 routine load**

每次重启doris时，先暂停routine load，doirs启动后，在重启routine load。

**17.如果出现timeout when waiting for send execution start RPC. Wait(sec): 5**

尝试设置以下内容，并重启fe和be：

be.conf:

```properties
fragment_pool_thread_num_max = 2048
fragment_pool_queue_size = 4096
brpc_num_threads = 256
```

fe.conf

```properties
remote_fragment_exec_timeout_ms = 10000
```

**18.doris fe或be 总掉线**

建议给Doris做服务自动拉起。一旦进程挂了，自动把doris拉起来。

Doris服务自动拉起参见：[https://doris.apache.org/zh-CN/docs/dev/admin-manual/maint-monitor/automatic-service-start](https://doris.apache.org/zh-CN/docs/dev/admin-manual/maint-monitor/automatic-service-start)

**19.最大文件句柄数限制**

BE 启动脚本会检查系统的最大文件句柄数需大于等于 65536，否则启动失败。

检查ulimit，服务器执行：

```bash
[root@DORIS-BE-PRD1 ~]# ulimit -n
65535
```

如果小于65536，修改limit：

两种方式：

（1）临时生效，重启服务器失效

```bash
[root@DORIS-BE-PRD1 ~]# ulimit -n 65536
```

（2）永久生效，需要重启服务器

```bash
[root@DORIS-BE-PRD1 ~]# vim /etc/security/limits.conf
# 在文件末尾添加
* soft nofile 65535
* hard nofile 65535

[root@DORIS-BE-PRD1 ~]# vim /etc/sysctl.conf
# 在文件末尾添加
fs.file-max=655350
# 使立即生效
[root@DORIS-BE-PRD1 ~]# /sbin/sysctl -p
# 查看是否设置成功
[root@DORIS-BE-PRD1 ~]# cat /proc/sys/fs/file-max
```

**20.Doris 高频导入大量数据出现 -238 报错**

尝试在BE上设置这两个参数

```bash
enable_segcompaction=true
compaction_task_num_per_fast_disk=16
```

**22.解决doris会话满导致整个集群查询时间非常长的问题**

通过show processlist;查询FE状态是sleep的会话数一直在增加，导致fe的查询变得很慢，普通查询10s+出结果。

通过两种方式解决：

（1）增加fe的数量，原来是1台fe，增加两台fe observer，分散查询压力
（2）调整闲时会话释放的时间，默认是1800s，改成300s。