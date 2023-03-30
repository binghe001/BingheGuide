---
title: 【付费】第38章：深度解析Spring事务失效的八大场景
pay: https://articles.zsxq.com/id_z55u4dijij8c.html
---

# 《Spring核心技术》第38章：深度解析Spring事务失效的八大场景

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe.gitcode.host](https://binghe.gitcode.host)
<br/>文章汇总：[https://binghe.gitcode.host/md/all/all.html](https://binghe.gitcode.host/md/all/all.html)
<br/>源码地址：[https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-37](https://github.com/binghe001/spring-annotation-book/tree/master/spring-annotation-chapter-37)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

------

* **本章难度**：★★★☆☆

* **本章重点**：掌握Spring事务失效的八大场景，并理解导致Spring事务失效的根本问题。

------

本章目录如下所示：

* 学习指引
* 失效场景
  * 数据库不支持事务
  * 事务方法未被Spring管理
  * 方法没有被public修饰
  * 同一类中方法调用
  * 未配置事务管理器
  * 方法的事务传播类型不支持事务
  * 不正确的捕获异常
  * 错误的标注异常类型

* 总结
* 思考
* VIP服务

## 一、学习指引

`明明配置了Spring事务，怎么就失效了呢？`

在日常工作中，如果对Spring的事务管理功能使用不当，则会造成Spring事务不生效的问题。本章就简单总结下在哪些场景下Spring的事务会不生效。

## 二、失效场景

`Spring事务在哪些场景下会失效呢？`

有时候明明在项目中配置了Spring事务，但就是不生效，这是为什么呢？本节，就给大家介绍下Spring事务失效最常见的八大场景。

### 2.1 数据库不支持事务

Spring事务生效的前提是所连接的数据库要支持事务，如果底层的数据库都不支持事务，则Spring的事务肯定会失效。例如，如果使用的数据库为MySQL，并且选用了MyISAM存储引擎，则Spring的事务就会失效。

### 2.2 事务方法未被Spring管理

如果事务方法所在的类没有加载到Spring IOC容器中，也就是说，事务方法所在的类没有被Spring管理，则Spring事务会失效，示例如下。

```java
public class ProductService {
    @Autowired
    private ProductDao productDao;
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void updateProductStockCountById(Integer stockCount, Long id){
        productDao.updateProductStockCountById(stockCount, id);
    }
}
```

ProductService类上没有标注@Service注解，Product的实例没有加载到Spring IOC容器中，就会造成updateProductStockCountById()方法的事务在Spring中失效。

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码
