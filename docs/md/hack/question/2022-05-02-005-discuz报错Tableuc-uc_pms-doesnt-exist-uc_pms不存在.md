---
layout: post
category: binghe-code-hack
title: discuz报错Table 'uc.uc_pms' doesn't exist，uc_pms不存在
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: discuz报错Table 'uc.uc_pms' doesn't exist，uc_pms不存在
lock: need
---

# discuz报错Table 'uc.uc_pms' doesn't exist，uc_pms不存在

第一次安装discuz，安装成功后跳到首页，报如下错误：

```sql
Error:Table 'ucenter.uc_pms' doesn't exist
Errno:1146
SQL::SELECT count(*) FROM `ucenter`.uc_pms WHERE (related='0' AND msgfromid>'0' OR msgfromid='0') AND msgtoid='0' AND folder='inbox' AND new='1'
```

查了下 ，数据库ucenter里没有uc_pms表。
执行如下SQL创建表即可：

```sql
CREATE TABLE uc_pms(
pmid INT( 10 ) UNSIGNED NOT NULL AUTO_INCREMENT ,
msgfrom VARCHAR( 15 ) NOT NULL DEFAULT '',
msgfromid MEDIUMINT( 8 ) UNSIGNED NOT NULL DEFAULT '0',
msgtoid MEDIUMINT( 8 ) UNSIGNED NOT NULL DEFAULT '0',
folder ENUM( 'inbox', 'outbox' ) NOT NULL DEFAULT 'inbox',
new TINYINT( 1 ) NOT NULL DEFAULT '0',
subject VARCHAR( 75 ) NOT NULL DEFAULT '',
dateline INT( 10 ) UNSIGNED NOT NULL DEFAULT '0',
message TEXT NOT NULL ,
delstatus TINYINT( 1 ) UNSIGNED NOT NULL DEFAULT '0',
related INT( 10 ) UNSIGNED NOT NULL DEFAULT '0',
PRIMARY KEY ( pmid ) ,
KEY msgtoid( msgtoid, folder, dateline ) ,
KEY msgfromid( msgfromid, folder, dateline ) ,
KEY RELATED( related ) ,
KEY getnum( msgtoid, folder, delstatus )
) ENGINE=MYISAM ;
```


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)