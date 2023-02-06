module.exports = {
    port: "8080",
    dest: ".site",
    base: "/",
    // 是否开启默认预加载js
    shouldPrefetch: (file, type) => {
        return false;
    },
    // webpack 配置 https://vuepress.vuejs.org/zh/config/#chainwebpack
    chainWebpack: config => {
        if (process.env.NODE_ENV === 'production') {
            const dateTime = new Date().getTime();

            // 清除js版本号
            config.output.filename('assets/js/cg-[name].js?v=' + dateTime).end();
            config.output.chunkFilename('assets/js/cg-[name].js?v=' + dateTime).end();

            // 清除css版本号
            config.plugin('mini-css-extract-plugin').use(require('mini-css-extract-plugin'), [{
                filename: 'assets/css/[name].css?v=' + dateTime,
                chunkFilename: 'assets/css/[name].css?v=' + dateTime
            }]).end();

        }
    },
    markdown: {
        lineNumbers: true,
        externalLinks: {
            target: '_blank', rel: 'noopener noreferrer'
        }
    },
    locales: {
        "/": {
            lang: "zh-CN",
            title: "冰河技术",
            description: "包含：编程语言，开发技术，分布式，微服务，高并发，高可用，高可扩展，高可维护，JVM技术，MySQL，分布式数据库，分布式事务，云原生，大数据，云计算，渗透技术，各种面试题，面试技巧..."
        }
    },
    head: [
        // ico
        ["link", {rel: "icon", href: `/favicon.ico`}],
        // meta
        ["meta", {name: "robots", content: "all"}],
        ["meta", {name: "author", content: "冰河"}],
        ["meta", {"http-equiv": "Cache-Control", content: "no-cache, no-store, must-revalidate"}],
        ["meta", {"http-equiv": "Pragma", content: "no-cache"}],
        ["meta", {"http-equiv": "Expires", content: "0"}],
        ["meta", {
            name: "keywords",
            content: "冰河，冰河技术, 编程语言，开发技术，分布式，微服务，高并发，高可用，高可扩展，高可维护，JVM技术，MySQL，分布式数据库，分布式事务，云原生，大数据，云计算，渗透技术，各种面试题，面试技巧"
        }],
        ["meta", {name: "apple-mobile-web-app-capable", content: "yes"}],
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                // src: 'https://code.jquery.com/jquery-3.5.1.min.js',
                src: '/js/jquery.min.js',
            }],
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                // src: 'https://code.jquery.com/jquery-3.5.1.min.js',
                src: '/js/global.js',
            }],
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                src: '/js/fingerprint2.min.js',
            }],
        //github: binghe001.github.io
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                src: 'https://v1.cnzz.com/z_stat.php?id=1281063564&web_id=1281063564',
            }],
        //gitee: binghe001.gitee.io
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                src: 'https://s9.cnzz.com/z_stat.php?id=1281064551&web_id=1281064551',
            }],
        // 添加百度统计
        ["script", {},
            `
            var _hmt = _hmt || [];
            (function() {
              var hm = document.createElement("script");
              hm.src = "https://hm.baidu.com/hm.js?d091d2fd0231588b1d0f9231e24e3f5e";
              var s = document.getElementsByTagName("script")[0];
              s.parentNode.insertBefore(hm, s);
            })();
            `
        ]
    ],
    plugins: [
        [
            {globalUIComponents: ['LockArticle', 'PayArticle']}
        ],
        // ['@vssue/vuepress-plugin-vssue', {
        //     platform: 'github-v3', //v3的platform是github，v4的是github-v4
        //     // 其他的 Vssue 配置
        //     owner: 'fuzhengwei', //github账户名
        //     repo: 'CodeGuide', //github一个项目的名称
        //     clientId: 'df8beab2190bec20352a',//注册的Client ID
        //     clientSecret: '7eeeb4369d699c933f02a026ae8bb1e2a9c80e90',//注册的Client Secret
        //     autoCreateIssue: true // 自动创建评论，默认是false，最好开启，这样首次进入页面的时候就不用去点击创建评论的按钮了。
        // }
        // ],
        // ['@vuepress/back-to-top', true], replaced with inject page-sidebar
        ['@vuepress/medium-zoom', {
            selector: 'img:not(.nozoom)',
            // See: https://github.com/francoischalifour/medium-zoom#options
            options: {
                margin: 16
            }
        }],
        // https://v1.vuepress.vuejs.org/zh/plugin/official/plugin-pwa.html#%E9%80%89%E9%A1%B9
        // ['@vuepress/pwa', {
        //     serviceWorker: true,
        //     updatePopup: {
        //         '/': {
        //             message: "发现新内容可用",
        //             buttonText: "刷新"
        //         },
        //     }
        // }],
        // see: https://vuepress.github.io/zh/plugins/copyright/#%E5%AE%89%E8%A3%85
        // ['copyright', {
        //     noCopy: false, // 允许复制内容
        //     minLength: 100, // 如果长度超过 100 个字符
        //     authorName: "https://bugstack.cn",
        //     clipboardComponent: "请注明文章出处, [bugstack虫洞栈](https://bugstack.cn)"
        // }],
        // see: https://github.com/ekoeryanto/vuepress-plugin-sitemap
        // ['sitemap', {
        //     hostname: 'https://bugstack.cn'
        // }],
        // see: https://github.com/IOriens/vuepress-plugin-baidu-autopush
        ['vuepress-plugin-baidu-autopush', {}],
        // see: https://github.com/znicholasbrown/vuepress-plugin-code-copy
        ['vuepress-plugin-code-copy', {
            align: 'bottom',
            color: '#3eaf7c',
            successText: '@冰河: 代码已经复制到剪贴板'
        }],
        // see: https://github.com/tolking/vuepress-plugin-img-lazy
        ['img-lazy', {}],
        ["vuepress-plugin-tags", {
            type: 'default', // 标签预定义样式
            color: '#42b983',  // 标签字体颜色
            border: '1px solid #e2faef', // 标签边框颜色
            backgroundColor: '#f0faf5', // 标签背景颜色
            selector: '.page .content__default h1' // ^v1.0.1 你要将此标签渲染挂载到哪个元素后面？默认是第一个 H1 标签后面；
        }],
        // https://github.com/lorisleiva/vuepress-plugin-seo
        ["seo", {
            siteTitle: (_, $site) => $site.title,
            title: $page => $page.title,
            description: $page => $page.frontmatter.description,
            author: (_, $site) => $site.themeConfig.author,
            tags: $page => $page.frontmatter.tags,
            // twitterCard: _ => 'summary_large_image',
            type: $page => 'article',
            url: (_, $site, path) => ($site.themeConfig.domain || '') + path,
            image: ($page, $site) => $page.frontmatter.image && (($site.themeConfig.domain && !$page.frontmatter.image.startsWith('http') || '') + $page.frontmatter.image),
            publishedAt: $page => $page.frontmatter.date && new Date($page.frontmatter.date),
            modifiedAt: $page => $page.lastUpdated && new Date($page.lastUpdated),
        }]
    ],
    themeConfig: {
        docsRepo: "binghe001/BingheGuide",
        // 编辑文档的所在目录
        docsDir: 'docs',
        // 文档放在一个特定的分支下：
        docsBranch: 'master',
        //logo: "/logo.png",
        editLinks: true,
        sidebarDepth: 0,
        //smoothScroll: true,
        locales: {
            "/": {
                label: "简体中文",
                selectText: "Languages",
                editLinkText: "在 GitHub 上编辑此页",
                lastUpdated: "上次更新",
                nav: [
                    {
                        text: '导读', link: '/md/all/all.md'
                    },
                    {
                        text: '核心技术',
                        items: [
                            {
                                text: '面试必问系列',  items: [
                                    {
                                        text: '面试必问',
                                        link: '/md/interview/2022-04-18-001-面试必问-聊聊JVM性能调优.md'
                                    }
                                ]
                            },
                            {
                                text: 'Java核心技术',  items: [
                                    {
                                        text: 'Java基础',
                                        link: '/md/core/java/basics/2022-04-28-全网最全正则表达式总结.md'
                                    },
                                    {
                                        text: 'Java进阶',
                                        link: '/md/core/java/advanced/default.md'
                                    },
                                    {
                                        text: 'Java高级',
                                        link: '/md/core/java/senior/default.md'
                                    },
                                    {
                                        text: 'Java8新特性',
                                        link: '/md/core/java/java8/2022-03-31-001-Java8有哪些新特性呢？.md'
                                    }
                                ]
                            },
                            {
                                text: 'Spring核心技术', items: [
                                    {
                                        text: 'IOC核心技术',
                                        link: '/md/core/spring/ioc/2022-04-04-001-聊聊Spring注解驱动开发那些事儿.md'
                                    },
                                    {
                                        text: 'AOP核心技术',
                                        link: '/md/core/spring/aop/default.md'
                                    }
                                ]
                            },
                            {
                                text: 'JVM核心技术', items: [
                                    {
                                        text: 'JVM调优技术',
                                        link: '/md/core/jvm/2022-04-18-001-JVM调优的几种场景.md'
                                    }
                                ]
                            },
                            {
                                text: 'MySQL核心技术', items: [
                                    {
                                        text: 'MySQL基础篇',
                                        link: '/md/core/mysql/base/2022-08-25-MySQL索引底层技术.md'
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        text: '性能调优',
                        items: [
                            {
                                text: 'JVM性能调优',
                                link: '/md/performance/jvm/default.md'
                            },
                            {
                                text: 'Tomcat性能调优',
                                link: '/md/performance/tomcat/default.md'
                            },
                            {
                                text: 'MySQL性能调优',
                                link: '/md/performance/mysql/default.md'
                            },
                            {
                                text: '操作系统性能调优',
                                link: '/md/performance/system/default.md'
                            }
                        ]
                    },
                    {
                        text: '并发编程',
                        items: [
                            {
                                text: '底层技术',
                                link: '/md/concurrent/bottom/default.md'
                            },
                            {
                                text: '源码分析',
                                link: '/md/concurrent/source/2020-03-30-001-一文搞懂线程与多线程.md'
                            },
                            {
                                text: '基础案例',
                                link: '/md/concurrent/basics/2020-03-30-001-明明中断了线程，却为何不起作用呢？.md'
                            },
                            {
                                text: '实战案例',
                                link: '/md/concurrent/ActualCombat/default.md'
                            },
                            {
                                text: '面试',
                                link: '/md/concurrent/interview/default.md'
                            },
                            {
                                text: '系统架构',
                                link: '/md/concurrent/framework/default.md'
                            }
                        ]
                    },
                    {
                        text: '🔥框架源码',
                        items: [
                            {
                                text: '🔥Spring核心技术',
                                link: '/md/frame/spring/ioc/2022-12-02-《Spring核心技术》开篇-我要带你一步步调试Spring6.0源码啦.md'
                            }
                        ]
                    },
                    {
                        text: '分布式',
                        items: [
                            {
                                text: '缓存技术', items: [
                                    {
                                        text: 'Redis',
                                        link: '/md/distributed/cache/default.md'
                                    }
                                ]
                            },
                            {
                                text: '服务注册发现', items: [
                                    {
                                        text: 'Zookeeper',
                                        link: '/md/distributed/zookeeper/default.md'
                                    }
                                ]
                            },
                            {
                                text: '消息中间件', items: [
                                    {
                                        text: 'RabbitMQ',
                                        link: '/md/distributed/mq/rabbitmq/default.md'
                                    },
                                    {
                                        text: 'RocketMQ',
                                        link: '/md/distributed/mq/rocketmq/default.md'
                                    },
                                    {
                                        text: 'Kafka',
                                        link: '/md/distributed/mq/kafka/default.md'
                                    }
                                ]
                            },
                            {
                                text: '网络通信', items: [
                                    {
                                        text: 'Netty',
                                        link: '/md/distributed/netty/default.md'
                                    }
                                ]
                            },
                            {
                                text: '远程调用', items: [
                                    {
                                        text: 'Dubbo',
                                        link: '/md/distributed/dubbo/default.md'
                                    }
                                ]
                            },
                            {
                                text: '数据库', items: [
                                    {
                                        text: 'MongoDB',
                                        link: '/md/distributed/mongodb/default.md'
                                    }
                                ]
                            },
                            {
                                text: '搜索引擎', items: [
                                    {
                                        text: 'ElasticSearch',
                                        link: '/md/distributed/es/default.md'
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        text: '🔥微服务',
                        items: [
                                {
                                    text: 'SpringBoot',
                                    link: '/md/microservices/springboot/default.md'
                                },
                                {
                                    text: '🔥SpringCloudAlibaba',
                                    link: '/md/microservices/springcloudalibaba/2022-04-02-SpringCloudAlibaba专栏开篇.md'
                                }
                            ]
                    },
                    {
                        text: '🔥项目实战',
                        items: [
                            {
                                text: "微服务项目",
                                items:[
                                    {
                                        text: '🔥SpringCloud Alibaba实战',
                                        link: '/md/microservices/springcloudalibaba/2022-04-02-SpringCloudAlibaba专栏开篇.md'
                                    }
                                ]
                            },
                            {
                                text: "中间件项目",
                                items:[
                                    {
                                        text: '🔥《RPC手撸专栏》',
                                        link: '/md/middleware/rpc/2022-08-24-我设计了一款TPS百万级别的RPC框架.md'
                                    },
                                    {
                                        text: '《字节码编程》',
                                        link: '/md/middleware/bytecode/2022-04-11-001-工作多年的你依然重复做着CRUD-是否接触过这种技术.md'
                                    },
                                    {
                                        text: '《手写线程池》',
                                        link: '/md/middleware/threadpool/default.md'
                                    },
                                    {
                                        text: '《分布式限流》',
                                        link: '/md/middleware/limiter/default.md'
                                    },
                                    {
                                        text: '《开源项目》',
                                        link: '/md/middleware/independent/default.md'
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        text: '渗透技术',
                        items: [
                            {
                                text: 'log4j重大漏洞',
                                link: '/md/hack/log4j/2022-05-30-冰河连夜复现了Log4j最新重大漏洞.md'
                            },
                            {
                                text: '基础环境篇',
                                link: '/md/hack/environment/2022-04-17-001-安装Kali系统.md'
                            },
                            {
                                text: '渗透工具篇',
                                link: '/md/hack/tools/2022-04-17-001-使用Easy-Creds工具攻击无线网络.md'
                            },
                            {
                                text: '木马篇',
                                link: '/md/hack/horse/2022-05-02-001-各种一句话木马大全.md'
                            },
                            {
                                text: 'SQL注入篇',
                                link: '/md/hack/sql/2022-05-02-001-sqli-labs-master下载与安装.md'
                            },
                            {
                                text: '漏洞拿Shell篇',
                                link: '/md/hack/shell/2022-05-02-001-各种解析漏洞拿shell.md'
                            },
                            {
                                text: '暴力破解篇',
                                link: '/md/hack/crack/2022-05-02-001-使用rarcrack暴力破解RAR-ZIP-7Z压缩包.md'
                            },
                            {
                                text: '渗透脚本篇',
                                link: '/md/hack/bash/2022-05-02-001-3389脚本开启代码(vbs版).md'
                            },
                            {
                                text: '数据与系统提权篇',
                                link: '/md/hack/raising/2022-05-02-001-数据库提权.md'
                            },
                            {
                                text: '客户端渗透篇',
                                link: '/md/hack/client/2022-05-02-001-浏览器渗透.md'
                            },
                            {
                                text: '社会工程学',
                                link: '/md/hack/sociology/2022-05-02-001-Metasploit之社会工程学工具包.md'
                            },
                            {
                                text: '问题记录篇',
                                link: '/md/hack/question/2022-05-02-001-HTTP错误4031禁止访问-执行访问被拒绝.md'
                            }
                        ]
                    },
                    {
                        text: '🌍知识星球',
                        link: '/md/starball/2022-12-24-硬核星球-即将涨价.md'
                    },
                    /*{
                        text: '🔥🔥🔥冰河指南',
                        link: '/md/all/all.md'
                    },*/
                    {
                        text: '📚书籍',
                        items: [
                            {
                                text: '出版图书', items: [
                                    {
                                        text: '《深入理解高并发编程：核心原理与案例实战》',
                                        link: '/md/knowledge/book/2022-06-17-深入理解高并发编程.md'
                                    },
                                    {
                                        text: '《深入理解分布式事务：原理与实战》',
                                        link: '/md/knowledge/book/2022-03-29-深入理解分布式事务.md'
                                    },
                                    {
                                        text: '《MySQL技术大全：开发、优化与运维实战》',
                                        link: '/md/knowledge/book/2022-03-29-MySQL技术大全.md'
                                    },
                                    {
                                        text: '《海量数据处理与大数据技术实战》',
                                        link: '/md/knowledge/book/2022-03-29-海量数据处理与大数据技术实战.md'
                                    }
                                ]
                            },
                            {
                                text: '电子书籍', items: [
                                    {
                                        text: '《深入理解高并发编程(第2版)》',
                                        link: '/md/knowledge/pdf/2022-10-31《深入理解高并发编程（第2版）》打包发布.md'
                                    },
                                    {
                                        text: '《深入理解高并发编程(第1版)》',
                                        link: '/md/knowledge/pdf/2022-07-25-深入理解高并发编程-第1版.md'
                                    },
                                    {
                                        text: '《从零开始手写RPC框架(基础篇)》',
                                        link: '/md/knowledge/pdf/2022-12-05-《从零开始手写RPC框架》电子书发布.md'
                                    },
                                    {
                                        text: '《SpringCloud Alibaba实战》',
                                        link: '/md/knowledge/pdf/2022-07-25-十大篇章-共26个章节-332页-打包发布.md'
                                    },
                                    {
                                        text: '《冰河的渗透实战笔记》',
                                        link: '/md/knowledge/pdf/2022-03-30-《冰河的渗透实战笔记》电子书，442页，37万字，正式发布.md'
                                    },
                                    {
                                        text: '《MySQL核心知识手册》',
                                        link: '/md/knowledge/pdf/2022-11-14-《MySQL核心知识手册》-打包发布.md'
                                    },
                                    {
                                        text: '《Spring IOC核心技术》',
                                        link: '/md/knowledge/pdf/2023-01-28-《Spring IOC核心技术》共27章-19万字-打包发布.md'
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        text: '关于',
                        items: [
                            {text: '关于自己', link: '/md/about/me/about-me.md'},
                            {text: '关于学习', link: '/md/about/study/default.md'},
                            {text: '关于职场', link: '/md/about/job/default.md'},
                        ]
                    },
                    {
                        text: 'B站',
                        link: 'https://space.bilibili.com/517638832'
                    },
                    {
                        text: 'Github',
                        link: 'https://github.com/binghe001/BingheGuide'
                    }
                ],
                sidebar: {
                    /*"/md/other/": genBarOther(),*/
                    "/md/core/java/": getBarJava(),
                    "/md/performance/": getBarPerformance(),
                    "/md/concurrent/": getBarConcurrent(),
                    "/md/frame/spring/": getBarFrameSpring(),
                    "/md/distributed/cache/": getBarDistributedCache(),
                    "/md/distributed/zookeeper/": getBarZookeeper(),
                    "/md/distributed/mq/": getBarMQ(),
                    "/md/distributed/netty/": getBarInternet(),
                    "/md/distributed/dubbo/": getBarDistributedDubbo(),
                    "/md/distributed/mongodb/": getBarDistributedMongodb(),
                    "/md/distributed/es/": getBarDistributedElasticSearch(),
                    "/md/microservices/springboot/": getBarMicroServices(),
                    "/md/microservices/springcloudalibaba/": getBarMicroServicesAlibaba(),
                    "/md/middleware/independent/": getBarMiddlewareIndependent(),
                    "/md/middleware/limiter/": getBarMiddlewareLimiter(),
                    "/md/middleware/threadpool/": getBarMiddlewareThreadpool(),
                    "/md/middleware/bytecode/": getBarMiddlewareByteCode(),
                    "/md/middleware/rpc/": getBarMiddlewareRPC(),
                    "/md/project/": getBarPeoject(),
                    "/md/hack/environment/": getBarHackEnvironment(),
                    "/md/hack/tools/": getBarHackTools(),
                    "/md/hack/horse/": getBarHackHorse(),
                    "/md/hack/sql/": getBarHackSQL(),
                    "/md/hack/shell/": getBarHackShell(),
                    "/md/hack/crack/": getBarHackCrack(),
                    "/md/hack/bash/": getBarHackBash(),
                    "/md/hack/raising/": getBarHackRaising(),
                    "/md/hack/client/": getBarHackClient(),
                    "/md/hack/sociology/": getBarHackSociology(),
                    "/md/hack/question/": getBarHackQUestion(),
                    "/md/hack/log4j/": getBarHackLog4j(),
                    "/md/interview/": getInterview(),
                    "/md/knowledge/book/": getBarPDFPublish(),
                    "/md/knowledge/pdf/": getBarPDFSink(),
                    "/md/about/": getBarAbout(),
                    "/md/core/spring/ioc/": getBarSpringIoc(),
                    "/md/core/spring/aop/": getBarSpringAop(),
                    "/md/core/mysql/base/": getMySQLBase(),
                    "/md/core/jvm/": getBarCoreJVM(),
                    "/md/starball/": getStarBall(),
                    "/md/all/": getBarAll(),
                }
            }
        }
    }
};


// other
// function genBarOther() {
//     return [
//         {
//             title: "阅读指南",
//             collapsable: false,
//             sidebarDepth: 2,
//             children: [
//                 "guide-to-reading.md"
//             ]
//         }
//     ]
// }

// Java
function getBarJava() {
    return [
        {
            title: "Java基础",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "basics/2022-04-28-全网最全正则表达式总结.md",
            ]
        },
        {
            title: "Java进阶",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "advanced/default.md",
            ]
        },
        {
            title: "Java高级",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "senior/default.md",
            ]
        },
        {
            title: "Java8新特性",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "java8/2022-03-31-001-Java8有哪些新特性呢？.md",
                "java8/2022-03-31-002-你知道Java8为什么引入Lambda表达式吗.md",
                "java8/2022-03-31-003-Lambda表达式基础语法，都在这儿了.md",
                "java8/2022-03-31-004-Lambda表达式典型案例，你想要的的都在这儿了.md",
                "java8/2022-03-31-005-一文搞懂函数式接口.md",
                "java8/2022-03-31-006-知识点总结，你都会了吗.md",
                "java8/2022-03-31-007-方法引用和构造器引用.md",
                "java8/2022-03-31-008-关于Java8的Stream API,都在这儿了.md",
                "java8/2022-03-31-009-强大的Stream API，你了解吗.md",
                "java8/2022-03-31-010-Stream API有哪些中间操作,看完你也可以吊打面试官.md",
                "java8/2022-03-31-011-Java8中的Stream API有哪些终止操作.md",
                "java8/2022-03-31-012-关于并行流与串行流，你必须掌握这些.md",
                "java8/2022-03-31-013-不了解Optional类，简历上别说你懂Java8.md",
                "java8/2022-03-31-014-接口中的默认方法和静态方法，你都掌握了吗.md",
                "java8/2022-03-31-015-关于Java8中的日期时间API，你需要掌握这些.md",
                "java8/2022-03-31-016-重复注解与类型注解，你真的学会了吗.md",
            ]
        }
    ]
}
// Performance
function getBarPerformance() {
    return [
        {
            title: "JVM性能调优",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "jvm/default.md",
            ]
        },
        {
            title: "Tomcat性能调优",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "tomcat/default.md",
            ]
        },
        {
            title: "MySQL性能调优",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "mysql/default.md",
            ]
        },
        {
            title: "操作系统性能调优",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "system/default.md",
            ]
        }
    ]
}

// FrameSpring
function getBarFrameSpring() {
    return [
        {
            title: "专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "ioc/2022-12-02-《Spring核心技术》开篇-我要带你一步步调试Spring6.0源码啦.md",
            ]
        },
        {
            title: "第一篇：IOC容器",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "ioc/2022-12-05-《Spring核心技术》第1章-@Configuration注解-你了解的还不够深入.md",
                "ioc/2022-12-12-《Spring核心技术》第2章-深度解析@ComponentScans注解与@ComponentScan注解.md",
                "ioc/2022-12-21-《Spring核心技术》第3章-深度解析@Bean注解.md",
                "ioc/2022-12-22-《Spring核心技术》第4章-深度解析从IOC容器中获取Bean的过程.md",
            ]
        },
        {
            title: "第二篇：AOP切面(待更新)",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "springmvc/default.md",
            ]
        },
        {
            title: "第三篇：声明式事务(待更新)",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "springmvc/default.md",
            ]
        },
        {
            title: "第四篇：SpringMVC(待更新)",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "springmvc/default.md",
            ]
        }
    ]
}
// cache
function getBarDistributedCache() {
    return [
        {
            title: "Redis",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// Zookeeper
function getBarZookeeper() {
    return [
        {
            title: "Zookeeper",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// MQ
function getBarMQ() {
    return [
        {
            title: "RabbitMQ",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "rabbitmq/default.md",
            ]
        },
        {
            title: "RocketMQ",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "rocketmq/default.md",
            ]
        },
        {
            title: "Kafka",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "kafka/default.md",
            ]
        }
    ]
}
// getBarInternet
function getBarInternet() {
    return [
        {
            title: "Netty",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getBarDistributedDubbo
function getBarDistributedDubbo() {
    return [
        {
            title: "Dubbo",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getBarDistributedMongodb
function getBarDistributedMongodb() {
    return [
        {
            title: "MongoDB",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getBarDistributedElasticSearch
function getBarDistributedElasticSearch() {
    return [
        {
            title: "ElasticSearch",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}

function getBarMicroServicesAlibaba(){
    return [
        {
            title: "第一篇：专栏设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-02-SpringCloudAlibaba专栏开篇.md",
                "2022-04-04-SA实战·第一篇-专栏设计.md",
            ]
        },
        {
            title: "第二篇：微服务介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-09-SA实战-微服务介绍.md",
            ]
        },
        {
            title: "第三篇：微服务环境搭建",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-13-SA实战·项目说明-流程设计-技术选型-模块划分.md",
                "2022-04-18-SA实战-开撸-完成通用模块的开发.md",
                "2022-04-21-SA实战-完成三大微服务的搭建与交互开发.md"
            ]
        },
        {
            title: "第四篇：服务治理",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-25-SA实战-服务治理-实现服务的注册与发现.md",
                "2022-04-27-SA实战-第8章-服务治理-实现服务调用的负载均衡.md"
            ]
        },
        {
            title: "第五篇：服务容错",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-28-SA实战-第9章-服务容错-服务雪崩与容错方案.md",
                "2022-05-03-SA实战-第10章-服务容错-Fegin整合Sentinel.md",
                "2022-05-05-SA实战-第11章-服务容错加餐-Sentinel核心技术与配置规则.md"
            ]
        },
        {
            title: "第六篇：服务网关",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-08-SA实战-第12章-服务网关-网关概述与核心架构.md",
                "2022-05-08-SA实战-第13章-服务网关-项目整合SpringCloudGateway.md",
                "2022-05-10-SA实战-第14章-服务网关-SpringCloudGateway核心技术.md"
            ]
        },
        {
            title: "第七篇：链路追踪",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-11-SA实战-第15章-链路追踪-核心原理与解决方案.md",
                "2022-05-12-SA实战-第16章-链路追踪-项目整合Sleuth实现链路追踪.md",
                "2022-05-13-SA实战-第17章-链路追踪-Sleuth整合ZipKin.md"
            ]
        },
        {
            title: "第八篇：消息服务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-17-SA实战-第18章-消息服务-MQ使用场景与选型对比.md",
                "2022-05-18-SA实战-第19章-消息服务-项目整合RocketMQ.md",
                "2022-05-20-SA实战-第20章-消息服务-RocketMQ核心技术.md"
            ]
        },
        {
            title: "第九篇：服务配置",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-21-SA实战-第21章-服务配置-服务配置介绍与Nacos核心概念.md",
                "2022-05-23-SA实战-第22章-服务配置-项目整合Nacos配置中心.md",
                "2022-05-24-SA实战-第23章-服务配置-实现动态刷新与配置共享.md",
            ]
        },
        {
            title: "第十篇：分布式事务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-25-SA实战-第24章-分布式事务-分布式事务核心原理与Seata介绍.md",
                "2022-05-25-SA实战-第25章-分布式事务-项目整合Seata实现分布式事务.md",
            ]
        },
        {
            title: "结束语",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-06-15-SA实战-第26章-专栏总结与后续规划.md",
            ]
        }
    ]
}
// getBarMicroServices
function getBarMicroServices() {
    return [
        {
            title: "SpringBoot",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getBarMiddlewareByteCode
function getBarMiddlewareByteCode() {
    return [
        {
            title: "字节码编程",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-11-001-工作多年的你依然重复做着CRUD-是否接触过这种技术.md",
                "2022-04-11-002-使用Javassist动态生成HelloWorld.md",
                "2022-04-11-003-使用Javassist生成JavaBean.md",
            ]
        }
    ]
}

// getBarMiddlewareRPC
function getBarMiddlewareRPC() {
    return [
        {
            title: "RPC框架介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-08-24-我设计了一款TPS百万级别的RPC框架.md",
            ]
        },
        {
            title: "第一篇：整体设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-06-25-《RPC手撸专栏》-第1章-开篇-手撸一个能在实际场景使用的RPC框架.md",
                "2022-06-30-《RPC手撸专栏》第2章-高性能分布式RPC框架整体设计.md",
                "2022-08-02-《RPC手撸专栏》第3章-RPC服务核心注解的设计与实现.md",
                "2022-08-22-《RPC手撸专栏》第4章-实现RPC服务核心注解的扫描与解析.md",
            ]
        },
        {
            title: "第二篇：服务提供者",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-09-28-《RPC手撸专栏》第5章-服务提供者收发消息基础功能实现.md",
                "2022-09-30-《RPC手撸专栏》第6章-自定义网络协议的实现.md",
                "2022-10-02-《RPC手撸专栏》第7章-自定义网络编解码的实现.md",
                "2022-10-03-《RPC手撸专栏》第8章-模拟服务消费者与服务提供者之间的数据交互.md",
                "2022-10-04-《RPC手撸专栏》第9章-服务提供者调用真实方法的实现.md",
                "2022-10-05-《RPC手撸专栏》第10章-测试服务提供者调用真实方法.md",
                "2022-10-06-《RPC手撸专栏》第11章-服务提供者扩展支持CGLib调用真实方法.md",
            ]
        },
        {
            title: "第三篇：服务消费者",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-10-08-《RPC手撸专栏》第12章-实现服务消费者与服务提供者直接通信.md",
                "2022-10-09-《RPC手撸专栏》第13章-服务消费者异步转同步直接获取返回结果.md",
                "2022-10-10-《RPC手撸专栏》第14章-服务消费者异步转同步的自定义Future与AQS实现.md",
                "2022-10-11-《RPC手撸专栏》第15章-服务消费者同步-异步-单向调用的实现.md",
                "2022-10-12-《RPC手撸专栏》第16章-服务消费者回调方法的实现.md",
                "2022-10-13-《RPC手撸专栏》第17章-服务消费者实现动态代理功能屏蔽请求协议对象的细节.md",
                "2022-10-17-《RPC手撸专栏》第18章-服务消费者整合动态代理实现直接调用接口返回结果数据.md",
                "2022-10-18-《RPC手撸专栏》第19章-服务消费者动态代理实现异步调用.md",
                "2022-10-19-《RPC手撸专栏》第20章-服务消费者动态代理优化.md",
            ]
        },
        {
            title: "第四篇：注册中心",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-10-20-《RPC手撸专栏》第21章-注册中心基础服务功能的实现.md",
                "2022-10-21-《RPC手撸专栏》第22章-服务提供者整合注册中心实现服务注册.md",
                "2022-10-24-《RPC手撸专栏》第23章-服务消费者整合注册中心实现服务发现.md",
            ]
        },
        {
            title: "第五篇：负载均衡",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-10-25-《RPC手撸专栏》第24章-服务消费者实现基于随机算法的负载均衡策略.md",
            ]
        },
        {
            title: "第六篇：SPI扩展序列化机制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-10-26-《RPC手撸专栏》第25章-对标Dubbo实现SPI扩展机制的基础功能.md",
                "2022-10-27-《RPC手撸专栏》第26章-基于SPI扩展JDK序列化与反序列化机制.md",
                "2022-10-28-《RPC手撸专栏》第27章-基于SPI扩展Json序列化与反序列化机制.md",
                "2022-10-31-《RPC手撸专栏》第28章-基于SPI扩展Hessian2序列化与反序列化机制.md",
                "2022-11-01-《RPC手撸专栏》第29章-基于SPI扩展Fst序列化与反序列化机制.md",
                "2022-11-02-《RPC手撸专栏》第30章-基于SPI扩展Kryo序列化与反序列化机制.md",
                "2022-11-04-《RPC手撸专栏》第31章-基于SPI扩展Protostuff序列化与反序列化机制.md",
            ]
        },
        {
            title: "第七篇：SPI扩展动态代理机制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-11-07-《RPC手撸专栏》第32章-基于SPI扩展JDK动态代理机制.md",
                "2022-11-08-《RPC手撸专栏》第33章-基于SPI扩展CGLib动态代理机制.md",
                "2022-11-09-《RPC手撸专栏》第34章-基于SPI扩展Javassist动态代理机制.md",
                "2022-11-10-《RPC手撸专栏》第35章-基于SPI扩展ByteBuddy动态代理机制.md",
                "2022-11-12-《RPC手撸专栏》第36章-基于SPI扩展ASM动态代理机制.md",
            ]
        },
        {
            title: "第八篇：SPI扩展反射机制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-11-14-《RPC手撸专栏》第37章-基于SPI扩展JDK反射机制调用真实方法.md",
                "2022-11-15-《RPC手撸专栏》第38章-基于SPI扩展CGLib反射机制调用真实方法.md",
                "2022-11-16-《RPC手撸专栏》第39章-基于SPI扩展Javassist反射机制调用真实方法.md",
                "2022-11-17-《RPC手撸专栏》第40章-基于SPI扩展ByteBuddy反射机制调用真实方法.md",
                "2022-11-18-《RPC手撸专栏》第41章-基于SPI扩展ASM反射机制调用真实方法.md",
            ]
        },
        {
            title: "第九篇：SPI扩展负载均衡策略",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-11-19-《RPC手撸专栏》第42章-基于SPI扩展随机算法负载均衡策略.md",
                "2022-11-20-《RPC手撸专栏》第43章-基于SPI扩展加权随机算法负载均衡策略.md",
                "2022-11-21-《RPC手撸专栏》第44章-基于SPI扩展轮询算法负载均衡策略.md",
                "2022-11-22-《RPC手撸专栏》第45章-基于SPI扩展加权轮询算法负载均衡策略.md",
                "2022-11-23-《RPC手撸专栏》第46章-基于SPI扩展Hash算法负载均衡策略.md",
                "2022-11-24-《RPC手撸专栏》第47章-基于SPI扩展加权Hash算法负载均衡策略.md",
                "2022-11-25-《RPC手撸专栏》第48章-基于SPI扩展源IP地址Hash算法负载均衡策略.md",
                "2022-11-27-《RPC手撸专栏》第49章-基于SPI扩展源IP地址加权Hash算法负载均衡策略.md",
                "2022-11-29-《RPC手撸专栏》第50章-基于SPI扩展Zookeeper的一致性Hash算法负载均衡策略.md",
            ]
        },
        {
            title: "第十篇：SPI扩展增强型负载均衡策略",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-11-30-《RPC手撸专栏》第51章-基于SPI扩展增强型加权随机算法负载均衡策略.md",
                "2022-12-01-《RPC手撸专栏》第52章-基于SPI扩展增强型加权轮询算法负载均衡策略.md",
                "2022-12-02-《RPC手撸专栏》第53章-基于SPI扩展增强型加权Hash算法负载均衡策略.md",
                "2022-12-03-《RPC手撸专栏》第54章-基于SPI扩展增强型加权源IP地址Hash算法负载均衡策略.md",
                "2022-12-05-《RPC手撸专栏》第55章-基于SPI扩展增强型Zookeeper一致性Hash算法负载均衡策略.md",
                "2022-12-06-《RPC手撸专栏》第56章-基于SPI扩展最少连接数负载均衡策略.md",
            ]
        },
        {
            title: "第十一篇：SPI扩展实现注册中心",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-12-07-《RPC手撸专栏》第57章-基于SPI扩展实现Zookeeper注册中心.md",
                "2022-12-07-《RPC手撸专栏》第57-X章-阶段性作业.md",
            ]
        },
        {
            title: "第十二篇：心跳机制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-12-09-《RPC手撸专栏》第58章-心跳机制交互数据模型设计.md",
                "2022-12-10-《RPC手撸专栏》第59章-心跳机制增强数据模型与协议解析.md",
                "2022-12-11-《RPC手撸专栏》第60章-服务消费者向服务提供者发送心跳信息并接收心跳响应.md",
                "2022-12-12-《RPC手撸专栏》第61章-服务消费者心跳间隔时间配置化.md",
                "2022-12-15-《RPC手撸专栏》第62章-服务提供者向服务消费者发送心跳消息并接收心跳响应.md",
                "2022-12-16-《RPC手撸专栏》第63章-服务提供者心跳间隔时间配置化.md",
                "2022-12-18-《RPC手撸专栏》第63-X章-阶段性作业.md",
            ]
        },
        {
            title: "第十三篇：增强型心跳机制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-12-20-《RPC手撸专栏》第64章-服务提供者增强型心跳检测机制的实现.md",
                "2022-12-21-《RPC手撸专栏》第65章-服务消费者增强型心跳检测机制的实现.md",
            ]
        },
        {
            title: "第十四篇：重试机制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-12-22-《RPC手撸专栏》第66章-服务消费者实现服务订阅的重试机制.md",
                "2022-12-24-《RPC手撸专栏》第67章-服务消费者连接服务提供者的重试机制.md",
            ]
        },
        {
            title: "第十五篇：整合Spring",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-12-26-《RPC手撸专栏》第68章-服务提供者整合Spring.md",
                "2022-12-27-《RPC手撸专栏》第69章-基于SpringXML接入服务提供者.md",
                "2022-12-28-《RPC手撸专栏》第70章-基于Spring注解接入服务提供者.md",
                "2022-12-29-《RPC手撸专栏》第71章-服务消费者整合Spring.md",
                "2022-12-30-《RPC手撸专栏》第72章-基于SpringXML接入服务消费者.md",
                "2022-12-31-《RPC手撸专栏》第73章-基于Spring注解接入服务消费者.md",
                "2022-12-31-《RPC手撸专栏》第73章-X-整合Spring阶段作业.md",
            ]
        },
        {
            title: "第十六篇：整合SpringBoot",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-01-《RPC手撸专栏》第74章-服务提供者整合SpringBoot.md",
                "2023-01-02-《RPC手撸专栏》第75章-基于SpringBoot接入服务提供者.md",
                "2023-01-03-《RPC手撸专栏》第76章-服务消费者整合SpringBoot.md",
                "2023-01-04-《RPC手撸专栏》第77章-基于SpringBoot接入服务消费者.md",
                "2023-01-04-《RPC手撸专栏》第77章-X-整合SpringBoot阶段作业.md",

            ]
        },
        {
            title: "第十七篇：整合Docker",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-05-《RPC手撸专栏》第78章-基于Docker接入服务提供者.md",
                "2023-01-06-《RPC手撸专栏》第79章-基于Docker接入服务消费者.md",
                "2023-01-06-《RPC手撸专栏》第79章-X-整合Docker阶段作业.md",
            ]
        },
        {
            title: "第十八篇：整合SpringCloud Alibaba",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-07-《RPC手撸专栏》第80章-整合SpringCloudAlibaba.md",
                "2023-01-07-《RPC手撸专栏》第80章-X-整合SpringCloud-Alibaba阶段作业.md",
            ]
        },
        {
            title: "第十九篇：结果缓存",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-09-《RPC手撸专栏》第81章-结果缓存通用模型设计.md",
                "2023-01-10-《RPC手撸专栏》第82章-服务提供者支持结果缓存.md",
                "2023-01-11-《RPC手撸专栏》第83章-服务消费者支持结果缓存.md",
                "2023-01-11-《RPC手撸专栏》第83章-X-结果缓存阶段作业.md",
            ]
        },
        {
            title: "第二十篇：路由控制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-12-《RPC手撸专栏》第84章-服务消费者直连某个服务提供者.md",
                "2023-01-13-《RPC手撸专栏》第85章-服务消费者直连多个服务提供者.md",
                "2023-01-13-《RPC手撸专栏》第85章-X-路由控制阶段作业.md",
            ]
        },
        {
            title: "第二十一篇：延迟连接",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-14-《RPC手撸专栏》第86章-服务消费者支持延迟连接服务提供者.md",
                "2023-01-15-《RPC手撸专栏》第87章-服务消费者支持非延迟连接服务提供者.md",
                "2023-01-15-《RPC手撸专栏》第87章-X-延迟连接阶段作业.md",
            ]
        },
        {
            title: "第二十二篇：并发控制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-16-《RPC手撸专栏》第88章-并发控制基础模型设计.md",
                "2023-01-17-《RPC手撸专栏》第89章-服务提供者支持并发控制.md",
                "2023-01-18-《RPC手撸专栏》第90章-服务消费者支持并发控制.md",
                "2023-01-18-《RPC手撸专栏》第90章-X-并发控制阶段作业.md",
            ]
        },
        {
            title: "第二十三篇：流控分析",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-20-《RPC手撸专栏》第91章-流控分析后置处理器模型设计.md",
                "2023-01-28-《RPC手撸专栏》第92章-服务提供者整合流控分析.md",
                "2023-01-29-《RPC手撸专栏》第93章-服务消费者整合流控分析.md",
                "2023-01-29-《RPC手撸专栏》第93章-X-流控分析阶段作业.md",
            ]
        },
        {
            title: "第二十四篇：连接控制",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-01-30-《RPC手撸专栏》第94章-连接控制基础模型设计.md",
                "2023-01-31-《RPC手撸专栏》第95章-服务提供者整合连接控制.md",
                "2023-01-31-《RPC手撸专栏》第95章-X-连接控制阶段作业.md",
            ]
        },
        {
            title: "第二十五篇：SPI扩展连接淘汰策略",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-01-《RPC手撸专栏》第96章-基于SPI扩展最早连接淘汰策略.md",
                "2023-02-02-《RPC手撸专栏》第97章-基于SPI扩展最晚连接淘汰策略.md",
                "2023-02-03-《RPC手撸专栏》第98章-基于SPI扩展先进先出连接淘汰策略.md",
                "2023-02-04-《RPC手撸专栏》第99章-基于SPI扩展使用次数最少连接淘汰策略.md",
                "2023-02-05-《RPC手撸专栏》第100章-基于SPI扩展最近未被使用连接淘汰策略.md",
                "2023-02-06-《RPC手撸专栏》第101章-基于SPI扩展随机连接淘汰策略.md",
                "2023-02-07-《RPC手撸专栏》第102章-基于SPI扩展拒绝连接淘汰策略.md",
                "2023-02-07-《RPC手撸专栏》第102章-X-SPI扩展连接拒绝策略阶段作业.md",
            ]
        },
        {
            title: "第二十六篇：数据缓冲",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-08-《RPC手撸专栏》第103章-数据缓冲基础模型设计.md",
                "2023-02-09-《RPC手撸专栏》第104章-服务提供者整合数据缓冲.md",
                "2023-02-10-《RPC手撸专栏》第105章-服务消费者整合数据缓冲.md",
                "2023-02-10-《RPC手撸专栏》第105章-X-数据缓冲阶段作业.md",
            ]
        },
        {
            title: "第二十七篇：服务容错",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-11-《RPC手撸专栏》第106章-服务容错设计与研发.md",
                "2023-02-12-《RPC手撸专栏》第107章-服务容错效果测试.md",
                "2023-02-13-《RPC手撸专栏》第108章-服务容错失效问题修复.md",
                "2023-02-13-《RPC手撸专栏》第108章-X-服务容错阶段作业.md"
            ]
        },
        {
            title: "第二十八篇：服务限流",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-14-《RPC手撸专栏》第109章-服务限流基础模型设计.md",
                "2023-02-15-《RPC手撸专栏》第110章-服务提供者整合服务限流.md"
            ]
        }
    ]
}

// getBarMiddlewareIndependent
function getBarMiddlewareIndependent() {
    return [
        {
            title: "开源项目",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getBarMiddlewareLimiter
function getBarMiddlewareLimiter() {
    return [
        {
            title: "分布式限流",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getBarMiddlewareThreadpool
function getBarMiddlewareThreadpool() {
    return [
        {
            title: "手写线程池",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}

// getBarPeoject
function getBarPeoject() {
    return [
        {
            title: "项目实战",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getBarHackEnvironment
function getBarHackEnvironment() {
    return [
        {
            title: "基础环境篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-17-001-安装Kali系统.md",
                "2022-04-17-002-Kali配置.md",
                "2022-04-17-003-Kali中各项菜单的功能.md",
                "2022-04-17-004-安装open-vm-tools实现虚拟机交互.md",
                "2022-04-17-005-Kali设置静态IP.md",
                "2022-04-17-006-kali安装免杀工具Veil-Evasion.md",
                "2022-04-17-007-在Debian8上安装WPScan.md",
                "2022-04-17-008-metasploitable2修改密码.md",
                "2022-04-17-009-操作系统支持的管道符.md",
            ]
        }
    ]
}

function getBarHackShell() {
    return [
        {
            title: "漏洞拿Shell篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-各种解析漏洞拿shell.md",
                "2022-05-02-002-网站入侵思路.md",
                "2022-05-02-003-IIS6.0-7.0-7.5-Nginx-Apache等WebService解析漏洞.md",
                "2022-05-02-004-iis7.5加fck解析漏洞后台拿shell.md",
                "2022-05-02-005-真正的IIS永远的后门解密.md",
            ]
        }
    ]
}

function getBarHackCrack() {
    return [
        {
            title: "暴力破解篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-使用rarcrack暴力破解RAR-ZIP-7Z压缩包.md",
                "2022-05-02-002-使用reaver傻瓜式破解wifi之利用路由器WPS漏洞.md",
                "2022-05-02-003-Python爆破Wifi密码.md",
                "2022-05-02-004-MySQL暴力破解工具多线程版.md",
            ]
        }
    ]
}

function getBarHackBash() {
    return [
        {
            title: "渗透脚本篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-3389脚本开启代码(vbs版).md",
                "2022-05-02-002-触发EasyFileSharingWebServer7.2HEAD缓冲区溢出的Python脚本.md",
            ]
        }
    ]
}

function getBarHackRaising() {
    return [
        {
            title: "数据与系统提权篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-数据库提权.md",
                "2022-05-02-002-NC反弹CMDSHELL提权总结.md",
                "2022-05-02-003-ASP-Web提权.md",
                "2022-05-02-004-MSF提权.md",
                "2022-05-02-005-Metasploit-Win10提权.md",
            ]
        }
    ]
}

function getBarHackClient() {
    return [
        {
            title: "客户端渗透篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-浏览器渗透.md",
                "2022-05-02-002-对网站的客户进行渗透.md",
                "2022-05-02-003-与DNS欺骗的结合使用.md",
                "2022-05-02-004-基于PDF文件格式的渗透攻击.md",
                "2022-05-02-005-基于Word文件格式的渗透攻击.md",
                "2022-05-02-006-使用Metasploit实现对Linux客户端的渗透.md",
                "2022-05-02-007-使用Metasploit渗透Android系统.md",
            ]
        }
    ]
}

function getBarHackSociology() {
    return [
        {
            title: "社会工程学",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-Metasploit之社会工程学工具包.md",
            ]
        }
    ]
}

function getBarHackQUestion() {
    return [
        {
            title: "问题记录篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-HTTP错误4031禁止访问-执行访问被拒绝.md",
                "2022-05-02-002-XP-IIS问题总结.md",
                "2022-05-02-003-IIS-403-404问题.md",
                "2022-05-02-004-DEDE5.7初始化数据体验包获取失败-无法下载安装.md",
                "2022-05-02-005-discuz报错Tableuc-uc_pms-doesnt-exist-uc_pms不存在.md",
                "2022-05-02-006-Windows远程登录提示超出允许最大连接数解决方案.md",
                "2022-05-02-007-Windows2008自动关机最简单的解决方案.md",
                "2022-05-02-008-Hydra安装报错.md",
                "2022-05-02-009-安装OpenVAS后找不到默认密码无法登录Web端.md",
                "2022-05-02-010-AppScan使用问题记录.md",
                "2022-05-02-011-Kali系统报错.md",
                "2022-05-02-012-Kali运行WPScan报错.md",
            ]
        }
    ]
}

function getBarHackLog4j() {
    return [
        {
            title: "log4j重大漏洞",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-30-冰河连夜复现了Log4j最新重大漏洞.md",
            ]
        }
    ]
}

function getBarHackHorse() {
    return [
        {
            title: "木马篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-各种一句话木马大全.md",
                "2022-05-02-002-asp图片木马的制作和使用.md",
            ]
        }
    ]
}

function getBarHackSQL() {
    return [
        {
            title: "SQL注入篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-05-02-001-sqli-labs-master下载与安装.md",
                "2022-05-02-002-SQL注入点检测方法.md",
                "2022-05-02-003-SQL语句生成一句话.md",
                "2022-05-02-004-ASP连接MSSQL数据库语句.md",
                "2022-05-02-005-SQL注入绕过技术总结.md",
                "2022-05-02-006-SQLServer启动-关闭xp_cmdshell.md",
            ]
        }
    ]
}

// getBarHackTools
function getBarHackTools() {
    return [
        {
            title: "渗透工具篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-17-001-使用Easy-Creds工具攻击无线网络.md",
                "2022-04-17-002-Nmap+Zenmap+Amap+Zmap.md",
                "2022-04-17-003-Zenmap.md",
                "2022-04-17-004-Amap.md",
                "2022-04-17-005-Zmap.md",
                "2022-04-17-006-Nessus的整理.md",
                "2022-04-17-007-Burpsuite上传截断及截断原理介绍.md",
                "2022-04-17-008-Kali2.0Meterpreter运用.md",
                "2022-04-17-009-lcx.exe内网转发命令教程-LCX免杀下载.md",
                "2022-04-17-010-字典生成工具Crunch的使用案例.md",
                "2022-04-17-011-WinlogonHack获取系统密码.md",
                "2022-04-17-012-Msfvenom生成各类Payload命令.md",
                "2022-04-17-013-PsExec下载地址及其用法.md",
                "2022-04-17-014-Hydra安装Libssh模块.md",
                "2022-04-17-015-利用procdump+Mimikatz绕过杀软获取Windows明文密码.md",
                "2022-04-17-016-SQLMap的用法+谷歌黑客语法.md",
                "2022-04-17-017-SQLMap用法总结.md",
                "2022-04-17-018-SQLMap参数说明.md",
                "2022-04-17-019-十大渗透测试演练系统.md",
                "2022-04-17-020-目录扫描神器DirBuster用法.md",
                "2022-04-17-021-NMap在实战中的常见用法.md",
                "2022-04-17-022-Metasploit模块的格式说明.md",
                "2022-04-17-023-Meterpreter命令大全.md",
                "2022-04-17-024-Metasploit-Meterpreter-Shell信息收集相关的命令.md",
                "2022-04-17-025-使用Metasploit编写绕过DEP渗透模块.md",
                "2022-04-17-026-Metasploit渗透php-utility-belt程序.md",
                "2022-04-17-027-内网IPC$入侵.md",
                "2022-04-17-028-Metasploit渗透BSPlayerV2.68.md",
                "2022-04-17-029-Metasploit攻击VSFTPD2.3.4后门漏洞并渗透内网.md",
                "2022-04-17-030-Metasploit攻击PHP-CGI查询字符串参数漏洞并渗透内网.md",
                "2022-04-17-031-Metasploit攻击HFS2.3上的漏洞.md",
                "2022-04-17-032-Metasploit访问控制的持久化.md",
                "2022-04-17-033-Metasploit清除渗透痕迹.md",
                "2022-04-17-034-利用Metasploit找出SCADA服务器.md",
                "2022-04-17-035-利用Metasploit渗透DATAC-RealWin-SCADA Server2.0.md",
                "2022-04-17-036-MSF-Meterpreter清理日志.md",
                "2022-04-17-037-Metasploit自定义FTP扫描模块.md",
                "2022-04-17-038-Metasploit渗透MSSQL.md",
                "2022-04-17-039-Metasploit渗透VOIP.md",
                "2022-04-17-040-破解工具hydra安装与使用.md",
                "2022-04-17-041-Metasploit自定义SSH认证暴力破解器.md",
                "2022-04-17-042-Metasploit自定义让磁盘失效的后渗透模块.md",
                "2022-04-17-043-PowerShell基本命令和绕过权限执行.md",
                "2022-05-02-001-Metasploit自定义收集登录凭证的后渗透模块.md",
                "2022-05-02-002-利用Java生成穷举字典(数字+字母(大小写)+字符).md",
                "2022-05-02-003-PowerShell工具之Powerup详解实录.md",
                "2022-05-02-004-Meterpreter以被控制的计算机为跳板渗透其他服务器.md",
                "2022-05-02-005-Win10完美去除桌面快捷图标小箭头.md",
                "2022-05-02-006-OpenVAS8.0-Vulnerability-Scanning.md",
                "2022-05-02-007-kali-Metasploit连接Postgresql默认密码.md",
                "2022-05-02-008-使用OpenVAS进行漏洞扫描.md",
                "2022-05-02-009-对威胁建模附加搭建CVE2014-6287漏洞环境.md",
                "2022-05-02-010-Metasploit设置永久访问权限.md",
                "2022-05-02-011-Empire反弹回Metasploit.md",
                "2022-05-02-012-Metasploit制作并运行自定义Meterpreper脚本.md",
                "2022-05-02-013-使用Metasploit实现对缓冲区栈的溢出攻击.md",
                "2022-05-02-014-使用Metasploit实现基于SEH的缓冲区溢出攻击.md",
                "2022-05-02-015-Metasploit基本后渗透命令.md",
                "2022-05-02-016-Metasploit高级后渗透模块.md",
                "2022-05-02-017-Kali中一键更新Metasploit框架.md",
                "2022-05-02-018-Metasploit其他后渗透模块.md",
                "2022-05-02-019-Metasploit高级扩展功能.md",
                "2022-05-02-020-Metasploit之pushm和popm命令.md",
                "2022-05-02-021-Metasploit使用reload-edit-reload_all命令加快开发过程.md",
                "2022-05-02-022-Metasploit资源脚本的使用方法.md",
                "2022-05-02-023-在Metasploit中使用AutoRunScript.md",
                "2022-05-02-024-使用Metasploit获取目标的控制权限.md",
                "2022-05-02-025-使用Metasploit中的NMap插件扫描并渗透内网主机.md",
                "2022-05-02-026-Kali一句话升级Metasploit的命令.md",
                "2022-05-02-027-Win2012R2打Windows8.1-KB2919355.md",
                "2022-05-02-028-Armitage基本原理.md",
                "2022-05-02-029-Armitage网络扫描以及主机管理.md",
                "2022-05-02-030-使用Armitage进行渗透.md",
                "2022-05-02-031-使用Armitage进行后渗透攻击.md",
                "2022-05-02-032-使用Armitage进行客户端攻击.md",
                "2022-05-02-033-Armitage脚本编写.md",
                "2022-05-02-034-Armitage控制Metasploit.md",
                "2022-05-02-035-Armitage使用Cortana实现后渗透攻击.md",
                "2022-05-02-036-Armitage使用Cortana创建自定义菜单.md",
                "2022-05-02-037-Armitage界面的使用.md",
                "2022-05-02-038-tcpdump用法说明.md",

            ]
        }
    ]
}
// getInterview
function getInterview() {
    return [
        {
            title: "面试必问系列",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-18-001-面试必问-聊聊JVM性能调优.md",
                "2022-04-18-002-面试必问-聊聊MyBatis执行流程.md",
                "2022-05-06-面试必问-哪些场景下Spring的事务会失效.md",
                "2022-05-06-面试必问-如何设计一款高并发的消息中间件.md",
                "2022-05-09-面试必问-聊聊MySQL三大核心日志的实现原理.md",
                "2022-05-16-面试必问-聊聊Kafka的消费模型.md",
                "2022-07-25-面试必问-一个线程从创建到消亡要经历哪些阶段.md",
                "2022-09-26-面试必问悲观锁与乐观锁.md",
            ]
        }
    ]
}
// getBarPDFPublish
function getBarPDFPublish() {
    return [
        {
            title: "出版图书",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-06-17-深入理解高并发编程.md",
                "2022-03-29-深入理解分布式事务.md",
                "2022-03-29-MySQL技术大全.md",
                "2022-03-29-海量数据处理与大数据技术实战.md",
            ]
        }
    ]
}
// getBarPDFSink
function getBarPDFSink() {
    return [
        {
            title: "冰河整理的PDF电子书",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-10-31《深入理解高并发编程（第2版）》打包发布.md",
                "2022-07-25-深入理解高并发编程-第1版.md",
                "2022-07-25-十大篇章-共26个章节-332页-打包发布.md",
                "2022-03-30-《冰河的渗透实战笔记》电子书，442页，37万字，正式发布.md",
                "2022-11-14-《MySQL核心知识手册》-打包发布.md",
                "2022-12-05-《从零开始手写RPC框架》电子书发布.md",
                "2023-01-28-《Spring IOC核心技术》共27章-19万字-打包发布.md",
            ]
        }
    ]
}
// getBarAbout
function getBarAbout() {
    return [
        {
            title: "关于自己",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "me/about-me.md",
            ]
        },
        {
            title: "关于学习",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "study/default.md",
            ]
        },
        {
            title: "关于职场",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "job/default.md",
            ]
        },
        {
            title: "关于面试",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "job/default.md",
            ]
        }
    ]
}
// getMySQLBase
function getMySQLBase() {
    return [
        {
            title: "MySQL基础篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-08-25-MySQL索引底层技术.md",
                "2022-08-25-MySQL之MVCC实现原理.md",
                "2022-07-09-《MySQL核心知识》第1章-开篇-专栏介绍.md",
                "2022-07-11-《MySQL核心知识》第2章-MySQL常用的命令.md",
                "2022-07-13-《MySQL核心知识》第3章-MySQL中的运算符.md",
                "2022-07-18-《MySQL核心知识》第4章-简单语法.md",
                "2022-07-25-《MySQL核心知识》第5章-查看字段长度与类型宽度.md",
                "2022-08-01-《MySQL核心知识》第6章-查询语句.md",
                "2022-08-07-《MySQL核心知识》第7章-插入-更新-删除.md",
                "2022-08-15-《MySQL核心知识》第8章-索引.md",
                "2022-08-22-《MySQL核心知识》第9章-函数.md",
                "2022-08-29-《MySQL核心知识》第10章：自定义存储过程和函数.md",
                "2022-09-16-《MySQL核心知识》第11章：视图.md",
                "2022-09-19-《MySQL核心知识》第12章：触发器.md",
                "2022-09-26-《MySQL核心知识》第13章：权限管理.md",
                "2022-09-28-《MySQL核心知识》第14章：数据备份与恢复.md",
                "2022-10-18-《MySQL核心知识》第15章-自动备份与恢复MySQL数据库并发送Email邮件.md",
                "2022-10-24-《MySQL核心知识》第16章-日志.md",
                "2022-10-31-《MySQL核心知识》第17章-性能优化.md",
                "2022-11-06-《MySQL核心知识》第18章-复制.md",
                "2022-11-09-《MySQL核心知识》第19章-安全地关闭MySQL实例.md",

            ]
        }
    ]
}

// getBarSpringIoc
function getBarSpringIoc() {
    return [
        {
            title: "IOC核心技术",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-04-001-聊聊Spring注解驱动开发那些事儿.md",
                "2022-04-04-002-组件注册-使用@Configuration和@Bean给容器中注册组件.md",
                "2022-04-04-003-组件注册-@ComponentScan-自动扫描组件&指定扫描规则.md",
                "2022-04-04-004-自定义TypeFilter指定过滤规则.md",
                "2022-04-04-005-使用@Lazy注解实现懒加载.md",
                "2022-04-04-006-如何按照条件向Spring中注册bean.md",
                "2022-04-04-007-使用@Import注解给容器中快速导入一个组件.md",
                "2022-04-04-008-深入理解Spring的ImportSelector接口.md",
                "2022-04-04-009-在@Import注解中使用ImportSelector.md",
                "2022-04-04-010-如何将Service注入到Servlet中.md",
                "2022-04-04-011-使用ImportBeanDefinitionRegistrar向容器中注册bean.md",
                "2022-04-04-012-使用FactoryBean注册向Spring容器中注册bean.md",
                "2022-04-04-013-使用@Bean注解指定初始化和销毁的方法.md",
                "2022-04-04-014-使用InitializingBean和DisposableBean来管理bean的生命周期.md",
                "2022-04-04-015-@PostConstruct注解和@PreDestroy注解.md",
                "2022-04-04-016-@PostConstruct与@PreDestroy源码解析.md",
                "2022-04-04-017-使用@Scope注解设置组件的作用域.md",
                "2022-04-04-018-针对bean的生命周期，我们能做哪些工作.md",
                "2022-04-04-019-BeanPostProcessor底层原理解析.md",
                "2022-04-04-020-困扰了我很久的AOP嵌套调用终于解决了.md",
                "2022-04-04-021-BeanPostProcessor在Spring底层是如何使用的.md",
                "2022-04-04-022-BeanPostProcessor后置处理器浅析.md",
                "2022-04-04-023-使用@Value注解为bean的属性赋值，原来这么简单.md",
                "2022-04-04-024-使用@PropertySource加载配置文件，我只看这一篇.md",
                "2022-04-04-025-使用@Autowired@Qualifier@Primary三大注解自动装配组件.md",
                "2022-04-04-026-详解@Resource和@Inject注解.md",
                "2022-04-04-027-如何实现方法、构造器位置的自动装配.md",
                "2022-04-04-028-如何解决Spring的循环依赖问题.md",
                "2022-04-04-029-看了这篇Spring事务原理，我才知道我对Spring事务的误解有多深.md",
                "2022-04-04-030-自定义组件如何注入Spring底层的组件.md",
                "2022-04-04-031-使用@Profile注解实现开发、测试和生产环境的配置和切换，看完这篇我彻底会了.md",
                "2022-04-04-032-面试官竟然让我现场搭建一个AOP测试环境.md",
                "2022-04-04-033-二狗子让我给他讲讲@EnableAspectJAutoProxy注解.md",
                "2022-04-04-034-Spring中的注解中的注解使用汇总，你想要的都在这儿了.md",
                "2022-04-04-035-为什么你用@JsonFormat注解时，LocalDateTime会反序列化失败.md",
                "2022-04-04-036-如何实现多数据源读写分离.md",
                "2022-04-04-037-一张图彻底理解Spring如何解决循环依赖.md",
                "2022-04-04-038-AnnotationAwareAspectJAutoProxyCreator源码解析.md",
                "2022-04-04-039-小伙伴们在催更Spring系列，于是我写下了这篇注解汇总.md",
                "2022-04-04-040-一张图带你窥探「Spring注解系列」专题到底要更新些啥.md",
                "2022-04-04-041-AnnotationAwareAspectJAutoProxyCreator类的调用流程是啥.md",
                "2022-04-04-042-Spring中Scheduled和Async两种调度方式有啥区别.md",
                "2022-04-04-043-AnnotationAwareAspectJAutoProxyCreator深度解析.md",
            ]
        }
    ]
}
// getBarSpringAop
function getBarSpringAop() {
    return [
        {
            title: "AOP核心技术",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}

// getBarCoreJVM
function getBarCoreJVM() {
    return [
        {
            title: "JVM核心技术",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-04-18-001-JVM调优的几种场景.md",
                "2022-04-18-002-类的编译.md",
                "2022-04-18-003-类的加载过程.md",
                "2022-04-18-004-JVM内存空间.md",
                "2022-04-18-005-JVM堆内存分配.md",
                "2022-04-18-006-JVM垃圾回收机制.md",
                "2022-04-18-007-JVM垃圾回收算法.md",
                "2022-04-18-008-JVM-CMS垃圾收集器.md",
                "2022-04-18-009-JVM -G1收集器-Region-停顿时间模型-垃圾回收.md",
                "2022-04-18-010-JVM内存布局.md",
            ]
        }
    ]
}
// getStarBall
function getStarBall() {
    return [
        {
            title: "星球介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-12-24-硬核星球-即将涨价.md"
            ]
        }
    ]
}
// getBarAll()
function getBarAll() {
    return [
        {
            title: "阅读指南",
            collapsable: false,
            sidebarDepth: 2,
            children: [
                "all.md",
            ]
        }
    ]
}

// ConcurrentPage
function getBarConcurrent() {
    return [
        {
            title: "底层技术",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "bottom/default.md",
            ]
        },
        {
            title: "源码分析",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "source/2020-03-30-001-一文搞懂线程与多线程.md",
                "source/2020-03-30-002-如何确保线程按照我们想要的顺序执行.md",
                "source/2020-03-30-003-深入解析Callable接口.md",
                "source/2020-03-30-004-两种异步模型与深度解析Future接口.md",
                "source/2020-03-30-005-SimpleDateFormat类到底为啥不是线程安全的？（附六种解决方案，建议收藏）.md",
                "source/2020-03-30-006-不得不说的线程池与ThreadPoolExecutor类浅析.md",
                "source/2020-03-30-007-深度解析线程池中那些重要的顶层接口和抽象类.md",
                "source/2020-03-30-008-从源码角度分析创建线程池究竟有哪些方式.md",
                "source/2020-03-30-009-通过源码深度解析ThreadPoolExecutor类是如何保证线程池正确运行的.md",
                "source/2020-03-30-010-通过ThreadPoolExecutor类的源码深度解析线程池执行任务的核心流程.md",
                "source/2020-03-30-011-通过源码深度分析线程池中Worker线程的执行流程.md",
                "source/2020-03-30-012-从源码角度深度解析线程池是如何实现优雅退出的.md",
                "source/2020-03-30-013-ScheduledThreadPoolExecutor与Timer的区别和简单示例.md",
                "source/2020-03-30-014-深度解析ScheduledThreadPoolExecutor类的源代码.md",
                "source/2020-03-30-015-浅谈AQS中的CountDownLatch、Semaphore与CyclicBarrier.md",
                "source/2020-03-30-016-浅谈AQS中的ReentrantLock、ReentrantReadWriteLock、StampedLock与Condition.md",
                "source/2020-03-30-017-朋友去面试竟然栽在了Thread类的源码上.md",
                "source/2020-03-30-018-如何使用Java7提供的ForkJoin框架实现高并发程序？.md"
            ]
        },
        {
            title: "基础案例",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "basics/2020-03-30-001-明明中断了线程，却为何不起作用呢？.md",
                "basics/2020-03-30-002-由InterruptedException异常引发的思考.md",
                "basics/2020-03-30-003-要想学好并发编程，关键是要理解这三个核心问题.md",
                "basics/2020-03-30-004-导致并发编程频繁出问题的“幕后黑手”.md",
                "basics/2020-03-30-005-解密诡异并发问题的第一个幕后黑手——可见性问题.md",
                "basics/2020-03-30-006-解密导致并发问题的第二个幕后黑手——原子性问题.md",
                "basics/2020-03-30-007-解密导致并发问题的第三个幕后黑手——有序性问题.md",
                "basics/2020-03-30-008-一文秒懂Happens-Before原则.md",
            ]
        },
        {
            title: "实战案例",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "ActualCombat/default.md",
            ]
        },
        {
            title: "面试",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "interview/default.md",
            ]
        },
        {
            title: "系统架构",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "framework/default.md",
            ]
        }
    ];

}

