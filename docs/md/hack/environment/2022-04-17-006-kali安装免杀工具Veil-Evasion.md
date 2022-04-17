---
layout: post
category: binghe-code-hack
title: kali安装免杀工具Veil-Evasion
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: kali安装免杀工具Veil-Evasion
lock: need
---

# kali安装免杀工具Veil-Evasion

## Veil Evasion简介

Veil Evasion是一个可执行文件，它被用来生成Metasploit的payload，能绕过常见杀软。

免责声明：本教程目的只是为了教育，我们不对这些东西会如何使用担任何风险，使用它的后果自负。

Veil-Evasion被原生设计为在kali上，但其实存在python环境的系统上应该都能运行。你可以用命令行轻松调用Veil-Evasion，按菜单选项生成payload。在创建payload的时候，Veil-Evasion会询问你是否想把payload文件用Pyinstaller或者Py2Exe转为可执行文件。

## 如何下载Veil Evasion

下载Veil Evasion需要以下命令：

安装git：

```bash
sudo apt-get -y install git
```

git命令行下载Veil Evasion：

```bash
git clone https://github.com/Veil-Framework/Veil-Evasion.git
```

把它移动到opt目录下（可选）：

```bash
mv Veil-Evasion /opt
```

如何安装Veil Evasion

进入Veil Evasion所在目录：

```bash
cd /opt/Veil-Evasion/
```

启动setup脚本开始安装：

```bash
bash setup/setup.sh -s
```


## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)