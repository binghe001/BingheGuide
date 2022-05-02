---
layout: post
category: binghe-code-hack
title: Metasploit使用reload、edit、reload_all命令加快开发过程
tagline: by 冰河
tag: [hack,binghe-code-hack]
excerpt: Metasploit使用reload、edit、reload_all命令加快开发过程
lock: need
---

# Metasploit使用reload、edit、reload_all命令加快开发过程

可以使用edit命令动态修改Metasploit中的模块，并在不关闭Metasploit的情况下使用reload命令重新加载编辑过的模块。如果对多个模块进行了修改，就可以在Metasploit中使用reload_all命令一次性载入所有模块。

```
msf5 > use exploit/multi/handler 
msf5 exploit(multi/handler) > edit
```

此时我们输入edit，就会以vi方式打开exploit/multi/handler模块 。

![img](https://img-blog.csdnimg.cn/20190127205121624.png)

此时，我们就可以对exploit/multi/handler模块进行编辑，然后保存，之后我们就可以输入reload命令重新载入exploit/multi/handler模块。

```
msf5 exploit(multi/handler) > reload
[*] Reloading module...
msf5 exploit(multi/handler) > 
```

如果我们同时对多个模块进行了修改，那我们就可以输入reload_all命令同时载入所有模块

```
msf5 exploit(multi/handler) > reload_all
[*] Reloading modules from all module paths...
               .;lxO0KXXXK0Oxl:.
           ,o0WMMMMMMMMMMMMMMMMMMKd,
        'xNMMMMMMMMMMMMMMMMMMMMMMMMMWx,
      :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:
    .KMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMX,
   lWMMMMMMMMMMMXd:..     ..;dKMMMMMMMMMMMMo
  xMMMMMMMMMMWd.               .oNMMMMMMMMMMk
 oMMMMMMMMMMx.                    dMMMMMMMMMMx
.WMMMMMMMMM:                       :MMMMMMMMMM,
xMMMMMMMMMo                         lMMMMMMMMMO
NMMMMMMMMW                    ,cccccoMMMMMMMMMWlccccc;
MMMMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:
NMMMMMMMMW.                      ;KMMMMMMMMMMMMMMX:
xMMMMMMMMMd                        ,0MMMMMMMMMMK;
.WMMMMMMMMMc                         'OMMMMMM0,
 lMMMMMMMMMMk.                         .kMMO'
  dMMMMMMMMMMWd'                         ..
   cWMMMMMMMMMMMNxc'.                ##########
    .0MMMMMMMMMMMMMMMMWc            #+#    #+#
      ;0MMMMMMMMMMMMMMMo.          +:+
        .dNMMMMMMMMMMMMo          +#++:++#+
           'oOWMMMMMMMMo                +:+
               .,cdkO0K;        :+:    :+:                                
                                :::::::+:
                      Metasploit

       =[ metasploit v5.0.1-dev                           ]
+ -- --=[ 1851 exploits - 1046 auxiliary - 321 post       ]
+ -- --=[ 541 payloads - 44 encoders - 10 nops            ]
+ -- --=[ 2 evasion                                       ]
+ -- --=[ ** This is Metasploit 5 development branch **   ]

msf5 exploit(multi/handler) > 
```

## 写在最后

> 如果你觉得冰河写的还不错，请微信搜索并关注「 **冰河技术** 」微信公众号，跟冰河学习高并发、分布式、微服务、大数据、互联网和云原生技术，「 **冰河技术** 」微信公众号更新了大量技术专题，每一篇技术文章干货满满！不少读者已经通过阅读「 **冰河技术** 」微信公众号文章，吊打面试官，成功跳槽到大厂；也有不少读者实现了技术上的飞跃，成为公司的技术骨干！如果你也想像他们一样提升自己的能力，实现技术能力的飞跃，进大厂，升职加薪，那就关注「 **冰河技术** 」微信公众号吧，每天更新超硬核技术干货，让你对如何提升技术能力不再迷茫！


![](https://img-blog.csdnimg.cn/20200906013715889.png)