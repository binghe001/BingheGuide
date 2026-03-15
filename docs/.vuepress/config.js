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
            {globalUIComponents: ['LockArticle', 'PayArticle', 'RedirectArticle']}
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
        //     authorName: "https://binghe.site",
        //     clipboardComponent: "请注明文章出处, [冰河技术](https://binghe.site)"
        // }],
        // see: https://github.com/ekoeryanto/vuepress-plugin-sitemap
        // ['sitemap', {
        //     hostname: 'https://binghe.site'
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
                        text: '♻学习路线',
                        link: '/md/study/concurrent/concurrent_road.md',
                    },
                    {
                        text: '踩坑经历',
                        items: [
                            {
                                text: '面试必问系列',  items: [
                                    {
                                        text: '面试必问',
                                        link: '/md/interview/2022-04-18-001-面试必问-聊聊JVM性能调优.md'
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        text: '核心技术',
                        items: [
                            {
                                text: '架构与模式',  items: [
                                    {
                                        text: 'Java极简设计模式',
                                        link: '/md/core/design/java/2023-07-09-《Java极简设计模式》第01章-单例模式.md'
                                    },
                                    {
                                        text: '实战高并发设计模式',
                                        link: '/md/core/design/concurrent/2023-09-17-start.md'
                                    }
                                ]
                            },
                            {
                                text: 'Java核心技术',  items: [
                                    {
                                        text: 'Java8新特性',
                                        link: '/md/core/java/java8/2022-03-31-001-Java8有哪些新特性呢？.md'
                                    },
                                    {
                                        text: 'IOC核心技术',
                                        link: '/md/core/spring/ioc/2022-04-04-001-聊聊Spring注解驱动开发那些事儿.md'
                                    },
                                    {
                                        text: 'JVM调优技术',
                                        link: '/md/core/jvm/2025-05-18-chapter00.md'
                                    }
                                ]
                            },
                            {
                                text: '容器化核心技术',  items: [
                                    {
                                        text: 'Dockek核心技术',
                                        link: '/md/core/docker/2023-09-10-《容器化核心设计》第01章-制作Java基础docker镜像.md'
                                    }
                                ]
                            },
                            {
                                text: '分布式存储',  items: [
                                    {
                                        text: 'Mycat核心技术',
                                        link: '/md/core/mycat/2023-08-11-《Mycat核心技术》第01章-互联网大厂有哪些分库分表的思路和技.md'
                                    }
                                ]
                            },
                            {
                                text: '数据库核心技术',  items: [
                                    {
                                        text: 'MySQL基础篇',
                                        link: '/md/core/mysql/base/2022-08-25-MySQL索引底层技术.md'
                                    }
                                ]
                            },
                            {
                                text: '服务器核心技术',  items: [
                                    {
                                        text: 'Nginx核心技术',
                                        link: '/md/core/nginx/2023-07-23-《Nginx核心技术》第01章-安装Nginx.md'
                                    }
                                ]
                            },
                            {
                                text: '渗透核心技术',  items: [
                                    {
                                        text: '渗透实战技术',
                                        link: '/md/hack/environment/2022-04-17-001-安装Kali系统.md'
                                    }
                                ]
                            }
                        ]
                    },
                    /*{
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
                    },*/
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
                        text: '框架源码',
                        items: [
                            {
                                text: 'Spring6核心技术',
                                link: '/md/frame/spring/ioc/2022-12-02-《Spring核心技术》开篇-我要带你一步步调试Spring6.0源码啦.md'
                            }
                        ]
                    },
                    {
                        text: '分布式',
                        items: [
                            {
                                text: '分布式事务',items: [
                                    {
                                        text: '分布式事务系列视频',
                                        link: '/md/distributed/transaction/transaction-video-001.md'
                                    }
                                ]
                            }

                            /*{
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
                            }*/
                        ]
                    },
                    {
                        text: '微服务',
                        items: [
                            {
                                text: 'SpringBoot',
                                link: '/md/microservices/springboot/default.md'
                            },
                            {
                                text: 'SpringCloudAlibaba',
                                link: '/md/microservices/springcloudalibaba/2022-04-02-SpringCloudAlibaba专栏开篇.md'
                            }
                        ]
                    },
                    {
                        text: '🔥项目实战',
                        items: [
                            {
                                text: "🔥AI大模型项目",
                                items:[
                                    {
                                        text: '🔥AI智能问答系统(新)',
                                        link: '/md/project/ai/qa/start/2025-01-14-start.md'
                                    },
                                    {
                                        text: '🔥实战AI大模型(新)',
                                        link: '/md/project/ai/dk/v1/start/2025-10-25-start.md'
                                    }
                                ]
                            },
                            {
                                text: "中间件项目",
                                items:[
                                    {
                                        text: '手写高性能Redis组件',
                                        link: '/md/project/redis-plugin/start/2025-10-20-start.md'
                                    },
                                    {
                                        text: '手写高性能脱敏组件',
                                        link: '/md/project/sensitive/start/2025-09-08-start.md'
                                    },
                                    {
                                        text: '手写线程池项目',
                                        link: '/md/project/threadpool/start/2025-08-26-start.md'
                                    },
                                    {
                                        text: '手写高性能SQL引擎',
                                        link: '/md/project/sql/start/2025-08-12-start.md'
                                    },
                                    {
                                        text: '手写高性能Polaris网关',
                                        link: '/md/project/gateway/start/2024-05-19-start.md'
                                    },
                                    {
                                        text: '手写高性能RPC项目',
                                        link: '/md/middleware/rpc/2022-08-24-我设计了一款TPS百万级别的RPC框架.md'
                                    }/*,
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
                                    }*/
                                ]
                            },
                            {
                                text: "高并发项目",
                                items:[
                                    {
                                        text: '分布式IM即时通讯系统（新）',
                                        link: '/md/project/im/start/2023-11-20-start.md'
                                    },
                                    {
                                        text: '分布式Seckill秒杀系统',
                                        link: '/md/project/seckill/2023-04-16-《Seckill秒杀系统》开篇-我要手把手教你搭建一个抗瞬时百万流量的秒杀系统.md'
                                    },
                                    {
                                        text: '实战高并发设计模式',
                                        link: '/md/core/design/concurrent/2023-09-17-start.md'
                                    }
                                ]
                            },
                            {
                                text: "微服务项目",
                                items:[
                                    {
                                        text: '简易电商脚手架项目',
                                        link: '/md/microservices/springcloudalibaba/2022-04-02-SpringCloudAlibaba专栏开篇.md'
                                    }
                                ]
                            },
                            {
                                text: "手撕源码",
                                items:[
                                    {
                                        text: '手撕Spring6源码',
                                        link: '/md/frame/spring/ioc/2022-12-02-《Spring核心技术》开篇-我要带你一步步调试Spring6.0源码啦.md'
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        text: '🌍知识星球',
                        link: '/md/zsxq/introduce.md'
                    },
                    /*{
                        text: '🔥🔥🔥冰河指南',
                        link: '/md/all/all.md'
                    },*/
                    {
                        text: '📚书籍',
                        items: [
                            {
                                text: '总览', items: [
                                    {
                                        text: '《书籍汇总》',
                                        link: '/md/knowledge/all/2023-03-26-书籍汇总.md'
                                    }

                                ]
                            },
                            {
                                text: '出版图书', items: [
                                    {
                                        text: '《深入理解高并发编程：核心原理与案例实战》',
                                        link: '/md/knowledge/book/2022-06-17-深入理解高并发编程.md'
                                    },
                                    {
                                        text: '《深入理解高并发编程：JDK核心技术》',
                                        link: '/md/knowledge/book/2023-02-27-深入理解高并发编程-JDK核心技术.md'
                                    },
                                    {
                                        text: '《深入高平行開發：深度原理&專案實戰》',
                                        link: '/md/knowledge/book/2023-02-03-深入高平行開發.md'
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
                                        text: '《实战高并发设计模式》',
                                        link: '/md/knowledge/pdf/2023-11-27-concurrent-design-mode.md'
                                    },
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
                    }/*,
                    {
                        text: 'ChatGPT',
                        link: 'https://chat.openai.run'
                    }*/
                ],
                sidebar: {
                    /*"/md/other/": genBarOther(),*/
                    "/md/core/java/": getBarJava(),
                    "/md/study/": getStudyRoadJava(),
                    "/md/core/design/java/": getBarJavaDegign(),
                    "/md/core/design/concurrent/": getBarConcurrentDegign(),
                    "/md/core/mycat/": getBarMycat(),
                    "/md/core/docker/": getBarDocker(),
                    "/md/core/nginx/": getBarNginx(),
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
                    "/md/project/gateway/": getBarGateway(),
                    "/md/project/sql/": getBarSql(),
                    "/md/project/threadpool/": getBarThreadPool(),
                    "/md/project/sensitive/": getBarSensitive(),
                    "/md/project/redis-plugin/": getBarRedisPlugin(),
                    "/md/project/ai/dk/v1/": getBarAiDeepSeekV1(),
                    "/md/project/ai/qa/": getBarAiQaSystem(),
                    "/md/distributed/transaction/": getBarDistributedTransaction(),
                    "/md/project/seckill/": getBarPeojectSeckill(),
                    "/md/project/im/": getBarPeojectIM(),
                    "/md/hack/": getBarHack(),
                    "/md/interview/": getInterview(),
                    "/md/knowledge/book/": getBarPDFPublish(),
                    "/md/knowledge/all/": getBarBookAll(),
                    "/md/knowledge/pdf/": getBarPDFSink(),
                    "/md/about/": getBarAbout(),
                    "/md/core/spring/ioc/": getBarSpringIoc(),
                    "/md/core/spring/aop/": getBarSpringAop(),
                    "/md/core/mysql/base/": getMySQLBase(),
                    "/md/core/jvm/": getBarCoreJVM(),
                    "/md/zsxq/": getStarBall(),
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

// getStudyRoadJava
function getStudyRoadJava() {
    return [
        {
            title: "学习指南",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "concurrent/concurrent_road.md",
                "java/java_road.md"
            ]
        }
    ]
}

// Java
function getBarJava() {
    return [
        /*{
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
        },*/
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

// Mycat
function getBarMycat() {
    return [
        {
            title: "第一篇：基础与疑难杂症",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-11-《Mycat核心技术》第01章-互联网大厂有哪些分库分表的思路和技.md",
                "2023-08-12-《Mycat核心技术》第02章-Mycat核心配置文件server.xml说明.md",
                "2023-08-13-《Mycat核心技术》第03章-Mycat核心配置文件schema.xml说明.md",
                "2023-08-14-《Mycat核心技术》第04章-Mycat核心配置文件rule.xml说明.md",
                "2023-08-15-《Mycat核心技术》第05章-Mycat中文乱码解决方案.md",
                "2023-08-16-《Mycat核心技术》第06章-Mycat问题处理总结.md",
                "2023-08-17-《Mycat核心技术》第07章-Mycat与MySQL 8.x互连.md",
                "2023-08-18-《Mycat核心技术》第08章-Mycat的限制.md"
            ]
        },
        {
            title: "第二篇：数据分片",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-19-《Mycat核心技术》第09章-自定义数字范围分片.md",
                "2023-08-20-《Mycat核心技术》第10章-按日期分片.md",
                "2023-08-21-《Mycat核心技术》第11章-枚举分片.md",
                "2023-08-22-《Mycat核心技术》第12章-程序指定分区分片.md",
                "2023-08-23-《Mycat核心技术》第13章-取模分片.md",
                "2023-08-24-《Mycat核心技术》第14章-实现ER分片.md",
                "2023-08-25-《Mycat核心技术》第15章-数据分片入门实战.md",
                "2023-08-26-《Mycat核心技术》第16章-Mycat综合测试.md"
            ]
        },
        {
            title: "第三篇：运维实战",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-27-《Mycat核心技术》第17章-实现MySQL的读写分离.md",
                "2023-08-28-《Mycat核心技术》第18章-路由转发实例解析.md",
                "2023-08-29-《Mycat核心技术》第19章-基于MySQL实现读写分离.md",
                "2023-08-30-《Mycat核心技术》第20章-Mycat集群部署.md"
            ]
        }
    ]
}

// docker
function getBarDocker() {
    return [
        {
            title: "第一篇：基础与疑难杂症",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-10-《容器化核心设计》第01章-制作Java基础docker镜像.md"
            ]
        }
    ]
}

// Java
function getBarJavaDegign() {
    return [
        {
            title: "第一篇：创建型模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-09-《Java极简设计模式》第01章-单例模式.md",
                "2023-07-10-《Java极简设计模式》第02章-抽象工厂模式.md",
                "2023-07-11-《Java极简设计模式》第03章-工厂方法模式.md",
                "2023-07-12-《Java极简设计模式》第04章-建造者模式.md",
                "2023-07-13-《Java极简设计模式》第05章-原型模式.md"
            ]
        },
        {
            title: "第二篇：结构型模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-14-《Java极简设计模式》第06章-适配器模式.md",
                "2023-07-15-《Java极简设计模式》第07章-装饰模式.md",
                "2023-07-16-《Java极简设计模式》第08章-外观模式.md",
                "2023-07-17-《Java极简设计模式》第09章-代理模式.md",
                "2023-07-18-《Java极简设计模式》第10章-桥接模式.md",
                "2023-07-19-《Java极简设计模式》第11章-组合模式.md",
                "2023-07-20-《Java极简设计模式》第12章-享元模式.md",
            ]
        },
        {
            title: "第三篇：行为型模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-21-《Java极简设计模式》第13章-责任链模式.md",
                "2023-07-22-《Java极简设计模式》第14章-命令模式.md",
                "2023-07-23-《Java极简设计模式》第15章-解析器模式.md",
                "2023-07-24-《Java极简设计模式》第16章-迭代器模式.md",
                "2023-07-25-《Java极简设计模式》第17章-中介者模式.md",
                "2023-07-26-《Java极简设计模式》第18章-备忘录模式.md",
                "2023-07-27-《Java极简设计模式》第19章-观察者模式.md",
                "2023-07-28-《Java极简设计模式》第20章-状态模式.md",
                "2023-07-29-《Java极简设计模式》第21章-策略模式.md",
                "2023-07-30-《Java极简设计模式》第22章-模板方法.md",
                "2023-07-31-《Java极简设计模式》第23章-访问者模式.md"
            ]
        }
    ]
}

// Concurrent Design
function getBarConcurrentDegign() {
    return [
        {
            title: "专栏开篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-17-start.md"
            ]
        },
        {
            title: "第一篇：不可变模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-18-第01章-到底问题出在哪里.md",
                "2023-09-19-第02章-原来问题出在这里.md",
                "2023-09-20-第03章-有哪些方法能够解决并发问题.md",
                "2023-09-21-第04章-可变类的线程安全问题.md",
                "2023-09-22-第05章-实现不可变类解决线程安全问题.md",
                "2023-09-23-第06章-实现消息聚合发送系统.md",
                "2023-09-24-第07章-JDK中的等效不可变类.md"
            ]
        },
        {
            title: "第二篇：保护性暂挂模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-25-第08章-线程的流转状态.md",
                "2023-09-26-第09章-解决交易过程加锁的安全性问题.md",
                "2023-09-27-第10章-解决交易过程性能与死锁问题.md",
                "2023-09-28-第11章-使用保护性暂挂模式优化交易性能.md",
                "2023-09-29-第12章-基于护性暂挂模式实现监控报警系统.md",
                "2023-09-30-第13章-保护性暂挂模式在JDK中的应用.md"
            ]
        },
        {
            title: "第三篇：两阶段终止模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-10-01-第14章-线程还没执行完怎么就退出了.md",
                "2023-10-02-第15章-到底什么是两阶段终止模式.md",
                "2023-10-03-第16章-实现监控报警系统线程优雅退出.md",
                "2023-10-04-第17章-两阶段终止模式在线程池中的应用.md"
            ]
        },
        {
            title: "第四篇：承诺模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-10-05-第18章-这代码性能怎么这么差.md",
                "2023-10-06-第19章-到底什么是承诺模式.md",
                "2023-10-07-第20章-基于承诺模式优化社区电商项目.md",
                "2023-10-08-第21章-文件助手项目性能太差原因分析.md",
                "2023-10-09-第22章-基于承诺模式优化文件同步助手项目.md",
                "2023-10-10-第23章-承诺模式在FutureTask类中的应用.md"
            ]
        },
        {
            title: "第五篇：生产者消费者模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-10-11-第24章-面向C端的个人文库系统崩了.md",
                "2023-10-12-第25章-初步优化面向C端的个人文库系统.md",
                "2023-10-13-第26章-优化面向C端的个人文库系统.md",
                "2023-10-14-第27章-消息堆积问题场景分析.md",
                "2023-10-15-第28章-消息堆积问题解决方案.md",
                "2023-10-16-第29章-生产者消费者模式在线程池中的应用.md"
            ]
        },
        {
            title: "第六篇：主动对象模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-10-17-第30章-重大事故访问商品链接404.md",
                "2023-10-18-第31章-访问商品链接404原因分析.md",
                "2023-10-19-第32章-到底什么是主动对象模式.md",
                "2023-10-20-第33章-基于主动对象模式优化社区电商系统.md",
                "2023-10-21-第34章-主动对象模式在线程池中的应用.md"
            ]
        },
        {
            title: "第七篇：线程池模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-10-22-第35章-服务器内存爆了.md",
                "2023-10-23-第36章-无法创建新的本地线程.md",
                "2023-10-24-第37章-优化社区电商系统优惠券服务.md",
                "2023-10-25-第38章-线程池核心参数解析.md",
                "2023-10-26-第39章-线程池执行任务源码深度解析.md",
                "2023-10-27-第40章-实现手写线程池.md"
            ]
        },
        {
            title: "第八篇：线程特有存储模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-10-28-第41章-用户信息怎么错乱了.md",
                "2023-10-29-第42章-到底什么是线程特有存储.md",
                "2023-10-30-第43章-解决格式化时间的线程安全问题.md",
                "2023-10-31-第44章-线程特有存储模式在JDK中的应用.md",
                "2023-11-01-第45章-ThreadLocal内存泄露分析.md"

            ]
        },
        {
            title: "第九篇：串行线程封闭模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-11-02-第46章-导出报表数据错乱了.md",
                "2023-11-03-第47章-到底什么是串行线程封闭模式.md",
                "2023-11-04-第48章-优化报表系统导出数据功能.md"
            ]
        },
        {
            title: "第十篇：主仆模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-11-05-第49章-统计个数据性能太差了.md",
                "2023-11-06-第50章-到底什么是主仆模式.md",
                "2023-11-07-第51章-基于主仆模式优化统计热点商品功能.md",
                "2023-11-08-第52章-主仆模式在JDK中的应用.md"
            ]
        },
        {
            title: "第十一篇：流水线模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-11-09-第53章-统计个交易额也能这么慢.md",
                "2023-11-10-第54章-到底什么是流水线模式.md",
                "2023-11-11-第55章-基于流水线模式优化实时统计交易额功能.md",
                "2023-11-12-第56章-流水线模式在Netty中的应用.md"
            ]
        },
        {
            title: "第十二篇：半同步半异步模式",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-11-13-第57章-支付系统性能太差了.md",
                "2023-11-14-第58章-到底什么是半同步半异步模式.md",
                "2023-11-15-第59章-使用半同步半异步模式优化支付系统.md",
                "2023-11-16-第60章-如何处理消息堆积问题.md"
            ]
        },
        {
            title: "专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-11-17-并发设计模式整体专栏总结.md"
            ]
        }
    ]
}

// Nginx
function getBarNginx() {
    return [
        {
            title: "Nginx核心技术",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-23-《Nginx核心技术》第01章-安装Nginx.md",
                "2023-07-24-《Nginx核心技术》第02章-获取客户端真实信息.md",
                "2023-07-25-《Nginx核心技术》第03章-实现负载均衡等.md",
                "2023-07-26-《Nginx核心技术》第04章-生成缩略图.md",
                "2023-07-27-《Nginx核心技术》第05章-封禁IP和IP段.md",
                "2023-07-28-《Nginx核心技术》第06章-按日期分割Nginx日志.md",
                "2023-07-29-《Nginx核心技术》第07章-配置Nginx日志.md",
                "2023-07-30-《Nginx核心技术》第08章-为Nginx动态添加模块.md",
                "2023-07-31-《Nginx核心技术》第09章-格式化日志并推送到远程服务器.md",
                "2023-08-01-《Nginx核心技术》第10章-Nginx配置WebSocket.md",
                "2023-08-02-《Nginx核心技术》第11章-实现MySQL数据库的负载均衡.md",
                "2023-08-03-《Nginx核心技术》第12章-使用Nginx解决跨域问题.md",
                "2023-08-04-《Nginx核心技术》第13章-解决文件与图片显示过慢问题.md",
                "2023-08-05-《Nginx核心技术》第14章-使用Nginx搭建流媒体服务器实现直播.md",
                "2023-08-06-《Nginx核心技术》第15章-使用Nginx抗高并发流量.md",
                "2023-08-07-《Nginx核心技术》第16章-实现Nginx的高可用负载均衡.md",
                "2023-08-08-《Nginx核心技术》第17章-使用自签CA配置HTTPS加密反向代理访问.md",
                "2023-08-09-《Nginx核心技术》第18章-基于主从模式搭建Nginx-Keepalived双机热备环境.md",
                "2023-08-10-《Nginx核心技术》第19章-Nginx实现四层负载均衡.md",
                "2024-07-28-nginx.md",

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
                "ioc/2023-02-24-《Spring核心技术》第5章-深度解析@Import注解.md",
                "ioc/2023-02-25-《Spring核心技术》第6章-深度解析@PropertySource注解.md",
                "ioc/2023-02-27-《Spring核心技术》第7章-深度解析@DependsOn注解.md",
                "ioc/2023-02-28-《Spring核心技术》第8章-深度解析@Conditional注解.md",
                "ioc/2023-03-01-《Spring核心技术》第9章-深度解析@Lazy注解.md",
                "ioc/2023-03-02-《Spring核心技术》第10章-深度解析@Component注解.md",
                "ioc/2023-03-03-《Spring核心技术》第11章-深度解析@Value注解.md",
                "ioc/2023-03-06-《Spring核心技术》第12章-深度解析@Autowired注解.md",
                "ioc/2023-03-07-《Spring核心技术》第13章-深度解析@Qualifier注解.md",
                "ioc/2023-03-08-《Spring核心技术》第14章-深度解析@Resource注解.md",
                "ioc/2023-03-10-《Spring核心技术》第15章-深度解析@Inject注解.md",
                "ioc/2023-03-11-《Spring核心技术》第16章-深度解析@Primary注解.md",
                "ioc/2023-03-12-《Spring核心技术》第17章-深度解析@Scope注解.md",
                "ioc/2023-03-13-《Spring核心技术》第18章-深度解析@PostConstruct注解与@PreDestroy注解.md",
                "ioc/2023-03-14-《Spring核心技术》第19章-深度解析@Profile注解.md",
                "ioc/2023-03-15-《Spring核心技术》第20章-深度解析循环依赖.md",
                "ioc/2023-03-16-《Spring核心技术》第21章-深度解析事件监听机制.md",

            ]
        },
        {
            title: "第二篇：AOP切面",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "aop/2023-03-19-《Spring核心技术》第22章-AOP切面型注解实战.md",
                "aop/2023-03-20-《Spring核心技术》第23章-深度解析@EnableAspectJAutoProxy注解.md",
                "aop/2023-03-21-《Spring核心技术》第24章-深度解析切入点表达式.md",
                "aop/2023-03-22-《Spring核心技术》第25章-深度解析构建AOP拦截器链的流程.md",
                "aop/2023-03-23-《Spring核心技术》第26章-深度解析调用通知方法的流程.md",
                "aop/2023-03-24-《Spring核心技术》第27章-深度解析@DeclareParents注解.md",
                "aop/2023-03-25-《Spring核心技术》第28章-@EnableLoadTimeWeaving注解.md",
            ]
        },
        {
            title: "第三篇：声明式事务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "transaction/2023-03-26-《Spring核心技术》第29章-Spring事务概述与编程实战.md",
                "transaction/2023-03-27-《Spring核心技术》第30章-深度解析Spring事务三大接口.md",
                "transaction/2023-03-28-《Spring核心技术》第31章-深度解析Spring事务隔离级别与传播机制.md",
                "transaction/2023-03-29-《Spring核心技术》第32章-深度解析@EnableTransactionManagement注解.md",
                "transaction/2023-03-30-《Spring核心技术》第33章-深度解析@Transactional注解.md",
                "transaction/2023-03-31-《Spring核心技术》第34章-深度解析Spring事务的执行流程.md",
                "transaction/2023-04-01-《Spring核心技术》第35章-深度解析Spring底层事务传播机制源码.md",
                "transaction/2023-04-02-《Spring核心技术》第36章-深度解析@TransactionEventListener注解.md",
                "transaction/2023-04-03-《Spring核心技术》第37章-Spring事务嵌套最佳实践.md",
                "transaction/2023-04-04-《Spring核心技术》第38章-深度解析Spring事务失效的场景.md",
            ]
        },
        {
            title: "第四篇：AOT预编译",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "aot/2023-04-05-《Spring核心技术》第39章-AOT预编译技术概述.md",
                "aot/2023-04-06-《Spring核心技术》第40章-构建Native-Image.md",
                "aot/2023-04-07-《Spring核心技术》第41章-Maven构建Native-Image.md",
            ]
        },
        {
            title: "第五篇：SpringMVC",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "springmvc/2023-04-09-《Spring核心技术》第42章-注解型SpringMVC通用启动模型设计.md",
                "springmvc/2023-04-10-《Spring核心技术》第43章-深度解析@Controller注解.md",
                "springmvc/2023-04-11-《Spring核心技术》第44章-深度解析@RestController注解.md",
                "springmvc/2023-04-12-《Spring核心技术》第45章-深度解析@RequestMapping注解.md",
                "springmvc/2023-04-13-《Spring核心技术》第46章-深度解析@RequestParam注解.md",
                "springmvc/2023-04-14-《Spring核心技术》第47章-深度解析@PathVariable注解.md",
                "springmvc/2023-04-15-《Spring核心技术》第48章-深度解析@RequestBody注解.md",
                "springmvc/2023-04-16-《Spring核心技术》第49章-深度解析@RequestHeader注解.md",
                "springmvc/2023-04-17-《Spring核心技术》第50章-深度解析@CookieValue注解.md",
                "springmvc/2023-04-18-《Spring核心技术》第51章-深度解析@ModelAttribute注解.md",
                "springmvc/2023-04-19-《Spring核心技术》第52章-深度解析@ExceptionHandler注解.md",
                "springmvc/2023-04-20-《Spring核心技术》第53章-深度解析@InitBinder注解.md",
                "springmvc/2023-04-21-《Spring核心技术》第54章-深度解析@ControllerAdvice注解.md",
                "springmvc/2023-04-22-《Spring核心技术》第55章-深度解析@RequestAttribute注解.md",
                "springmvc/2023-04-23-《Spring核心技术》第56章-深度解析@SessionAttribute注解.md",
                "springmvc/2023-04-24-《Spring核心技术》第57章-深度解析@SessionAttributes注解.md",
                "springmvc/2023-04-25-《Spring核心技术》第58章-深度解析@ResponseBody注解.md",
                "springmvc/2023-04-26-《Spring核心技术》第59章-深度解析@CrossOrigin注解.md",
            ]
        },
        {
            title: "作业篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "work/2023-04-08-《Spring核心技术》作业-专栏整体作业.md",
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

// getBarDistributedTransaction
function getBarDistributedTransaction() {
    return [
        {
            title: "分布式事务系列视频",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "transaction-video-001.md",
                "transaction-video-002.md",
                "transaction-video-003.md",
                "transaction-video-004.md",
                "transaction-video-005.md",
                "transaction-video-006.md",
                "transaction-video-007.md",
                "transaction-video-008.md",
                "transaction-video-009.md",
                "transaction-video-010.md",
                "transaction-video-011.md",
                "transaction-video-012.md",
                "transaction-video-013.md",
                "transaction-video-014.md",
                "transaction-video-015.md",
                "transaction-video-016.md",
                "transaction-video-017.md",
                "transaction-video-018.md",
                "transaction-video-019.md",
                "transaction-video-020.md",
                "transaction-video-021.md",
                "transaction-video-022.md",
                "transaction-video-023.md",
                "transaction-video-024.md",
                "transaction-video-025.md",
                "transaction-video-026.md",
                "transaction-video-027.md",
                "transaction-video-028.md",
                "transaction-video-029.md",
                "transaction-video-030.md",
                "transaction-video-031.md",
                "transaction-video-032.md",
                "transaction-video-033.md",
                "transaction-video-034.md",
                "transaction-video-035.md",
                "transaction-video-036.md",
                "transaction-video-037.md",
                "transaction-video-038.md",
                "transaction-video-039.md",
            ]
        }
    ]
}

function getBarAiQaSystem() {
    return [
        {
            title: "开篇：专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "start/2025-01-14-start.md"
            ]
        },
        {
            title: "第01部分：需求设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "demand/2026-01-15-chapter01.md"
            ]
        },
        {
            title: "第02部分：落地实现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "coding/2026-01-16-chapter01.md",
                "coding/2026-01-18-chapter02.md",
                "coding/2026-01-19-chapter03.md",
                "coding/2026-01-20-chapter04.md",
            ]
        },
        {
            title: "第03部分：功能测试",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "testing/2026-01-21-chapter01.md",
            ]
        },
        {
            title: "第04部分：专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "summary/2026-01-22-summary.md",
            ]
        },
    ]
}

// Java
function getBarAiDeepSeekV1() {
    return [
        {
            title: "开篇：专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "start/2025-10-25-start.md",
            ]
        },
        {
            title: "第01部分：DeepSeek API实战",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "api/2025-10-26-chapter01.md",
                "api/2025-11-01-chapter02.md",
                "api/2025-11-14-chapter03.md",
            ]
        },
        {
            title: "第02部分：部署AI大模型",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "deploy/2025-11-18-chapter01.md",
                "deploy/2025-11-22-chapter02.md",
                "deploy/2025-11-23-chapter03.md",
                "deploy/2025-11-24-chapter04.md",
                "deploy/2025-11-25-chapter05.md",
                "deploy/2025-11-26-chapter06.md",
                "deploy/2025-11-30-chapter07.md",
                "deploy/2025-12-01-chapter08.md",
            ]
        },
        {
            title: "第03部分：生成AI应用",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "app/2025-12-02-chapter01.md",
                "app/2025-12-03-chapter02.md",
                "app/2025-12-04-chapter03.md",
                "app/2025-12-05-chapter04.md",
                "app/2025-12-06-chapter05.md",
                "app/2025-12-07-chapter06.md",
                "app/2025-12-08-chapter07.md",
                "app/2025-12-09-chapter08.md",
                "app/2025-12-10-chapter09.md",
                "app/2025-12-11-chapter10.md",
                "app/2025-12-12-chapter11.md",
            ]
        },
        {
            title: "第04部分：AI数字人应用",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "number/2025-12-13-chapter01.md",
                "number/2025-12-14-chapter02.md",
                "number/2025-12-15-chapter03.md",
                "number/2025-12-16-chapter04.md",
                "number/2025-12-17-chapter05.md",
            ]
        },
        {
            title: "第05部分：增强与优化",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "optimize/2025-12-18-chapter01.md",
                "optimize/2025-12-19-chapter02.md",
                "optimize/2025-12-20-chapter03.md",
            ]
        },
        {
            title: "专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "summary/2025-12-23-summary.md",
            ]
        }
    ]
}

function getBarRedisPlugin() {
    return [
        {
            title: "开篇：专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "start/2025-10-20-start.md",
            ]
        },
        {
            title: "第01部分：需求设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "demand/2025-10-23-chapter01.md",
                "demand/2025-12-28-chapter02.md",
                "demand/2025-12-29-chapter03.md",
            ]
        },
        {
            title: "第02部分：总体架构设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "archit/2025-12-30-chapter01.md",
            ]
        },
        {
            title: "第03部分：落地实现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "coding/2026-01-04-chapter01.md",
                "coding/2026-01-06-chapter02.md",
                "coding/2026-01-07-chapter03.md",
            ]
        },
        {
            title: "第04部分：测试验证",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "test/2026-01-08-chapter01.md",
                "test/2026-01-09-chapter02.md",
            ]
        },
        {
            title: "专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "summary/2026-01-10-summary.md",
            ]
        }
    ]
}


function getBarSensitive() {
    return [
        {
            title: "开篇：专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "start/2025-09-08-start.md",
            ]
        },
        {
            title: "第01部分：需求设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "demand/2025-09-09-chapter01.md",
                "demand/2025-09-10-chapter02.md",
                "demand/2025-09-11-chapter03.md",
            ]
        },
        {
            title: "第02部分：总体架构设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "archit/2025-09-12-chapter01.md",
                "archit/2025-09-13-chapter02.md",
            ]
        },
        {
            title: "第03部分：脱敏设计实现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "shield/2025-09-14-chapter01.md",
                "shield/2025-09-15-chapter02.md",
                "shield/2025-09-16-chapter03.md",
                "shield/2025-09-17-chapter04.md",
            ]
        },
        {
            title: "第04部分：扩展设计实现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "extend/2025-09-18-chapter01.md",
            ]
        },
        {
            title: "第05部分：测试场景验证",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "test/2025-09-19-chapter01.md",
                "test/2025-09-20-chapter02.md",
            ]
        },
        {
            title: "第06部分：专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "zj/2025-09-21-summary.md",
            ]
        }
    ]
}

function getBarThreadPool() {
    return [
        {
            title: "第01部分：专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "start/2025-08-26-start.md",
            ]
        },
        {
            title: "第02部分：线程池核心技术",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "jdk/2025-08-27-chapter01.md",
                "jdk/2025-08-28-chapter02.md",
                "jdk/2025-08-29-chapter03.md",
                "jdk/2025-08-30-chapter04.md",
                "jdk/2025-08-31-chapter05.md",
                "jdk/2025-09-01-chapter06.md",
            ]
        },
        {
            title: "第03部分：实战手写线程池",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "example/2025-09-02-threadpool.md",
            ]
        },
        {
            title: "第04部分：专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "summary/2025-09-03-summary.md",
            ]
        }
    ]
}

function getBarSql() {
    return [
        {
            title: "专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "start/2025-08-12-start.md",
            ]
        },
        {
            title: "第01部分：需求设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "demand/2025-08-13-chapter01.md",
                "demand/2025-08-15-chapter02.md",
                "demand/2025-08-16-chapter03.md",
            ]
        },
        {
            title: "第02部分：总体架构设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "archit/2025-08-17-chapter01.md",
                "archit/2025-08-18-chapter02.md",
            ]
        },
        {
            title: "第03部分：通用模型设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "model/2025-08-19-chapter01.md",
                "model/2025-08-20-chapter02.md"
            ]
        },
        {
            title: "第04部分：SQL引擎设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "engine/2025-08-21-chapter01.md",
                "engine/2025-08-22-chapter02.md",
            ]
        },
        {
            title: "第05部分：SQL引擎实战",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "example/2025-08-23-chapter01.md",
                "example/2025-08-24-chapter02.md",
            ]
        },
        {
            title: "第06部分：性能测试",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "pressure/2025-08-25-chapter01.md",
                "pressure/2025-08-26-chapter02.md",
            ]
        },
        {
            title: "第07部分：专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "zj/summary.md",
            ]
        }
    ]
}

function getBarGateway(){
    return [
        {
            title: "专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "start/2024-05-19-start.md",
                "start/2024-05-20-gateway.md",
            ]
        },
        {
            title: "第01部分：需求设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "demand/2024-06-02-chapter01.md",
                "demand/2024-06-23-chapter02.md",
                "demand/2024-06-30-chapter03.md",
                "demand/2024-07-14-chapter04.md",
            ]
        },
        {
            title: "第02部分：总体架构设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "archit/2024-07-20-chapter01.md",
                "archit/2024-08-03-chapter02.md",
            ]
        },
        {
            title: "第03部分：环境搭建",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "env/2024-08-06-chapter01.md",
                "env/2024-08-07-chapter02.md",
                "env/2024-08-26-chapter03.md",
            ]
        },
        {
            title: "第04部分：通用模型设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "model/2024-09-08-chapter01.md",
                "model/2024-09-17-chapter02.md",
                "model/2024-09-18-chapter03.md",
                "model/2024-09-22-chapter04.md",
                "model/2024-09-23-chapter05.md",
                "model/2024-09-24-chapter06.md",
                "model/2024-09-25-chapter07.md",
                "model/2024-09-28-chapter08.md",
                "model/2024-09-29-chapter09.md",
                "model/2024-09-30-chapter10.md",
                "model/2024-10-02-chapter11.md",
                "model/2024-10-03-chapter12.md",
                "model/2024-10-06-chapter13.md",
            ]
        },
        {
            title: "第05部分：通用过滤器设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "filter/2024-11-05-chapter01.md",
                "filter/2025-02-13-chapter02.md",
                "filter/2025-02-22-chapter03.md",
                "filter/2025-03-17-chapter04.md",
                "filter/2025-03-25-chapter05.md",
                "filter/2025-03-26-chapter06.md",
                "filter/2025-04-04-chapter07.md",
                "filter/2025-04-08-chapter08.md",
                "filter/2025-04-10-chapter09.md",
                "filter/2025-04-12-chapter10.md",
                "filter/2025-04-14-chapter11.md",
                "filter/2025-04-18-chapter12.md",
                "filter/2025-04-19-chapter13.md",
                "filter/2025-04-20-chapter14.md",
            ]
        },
        {
            title: "第06部分：通用处理器设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "processor/2025-06-22-chapter01.md",
                "processor/2025-06-23-chapter02.md",
                "processor/2025-06-24-chapter03.md",
                "processor/2025-06-25-chapter04.md",
                "processor/2025-06-26-chapter05.md",
                "processor/2025-06-28-chapter06.md",
                "processor/2025-06-29-chapter07.md",
                "processor/2025-06-30-chapter08.md",
                "processor/2025-06-30-chapter09.md",
                "processor/2025-07-01-chapter10.md",
                "processor/2025-07-03-chapter11.md",
                "processor/2025-07-06-chapter12.md",
                "processor/2025-07-07-chapter13.md",
                "processor/2025-07-08-chapter14.md",
            ]
        },
        {
            title: "第07部分：核心容器设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "http/2025-07-10-chapter01.md",
                "http/2025-07-11-chapter02.md",
                "http/2025-07-12-chapter03.md",
                "http/2025-07-13-chapter04.md",
                "http/2025-07-14-chapter05.md",
            ]
        },
        {
            title: "第08部分：核心启动流程",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "core/2025-07-15-chapter01.md",
                "core/2025-07-16-chapter02.md",
            ]
        },
        {
            title: "第09部分：牛刀小试",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "test/2025-07-17-chapter01.md",
            ]
        },
        {
            title: "第10部分：注册中心",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "registry/2025-07-18-chapter01.md",
                "registry/2025-07-19-chapter02.md",
                "registry/2025-07-20-chapter03.md",
                "registry/2025-07-21-chapter04.md",
                "registry/2025-07-22-chapter05.md",
                "registry/2025-07-23-chapter06.md",
            ]
        },
        {
            title: "第11部分：负载均衡",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "balancer/2025-07-24-chapter01.md",
                "balancer/2025-07-25-chapter02.md",
                "balancer/2025-07-26-chapter03.md",
                "balancer/2025-07-27-chapter04.md",
                "balancer/2025-07-28-chapter05.md",
                "balancer/2025-07-29-chapter06.md",
                "balancer/2025-07-30-chapter07.md",
                "balancer/2025-07-31-chapter08.md",
                "balancer/2025-08-01-chapter09.md",
                "balancer/2025-08-02-chapter10.md",
            ]
        },
        {
            title: "第12部分：增强型负载均衡",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "balancer/enhanced/2025-08-03-chapter01.md",
                "balancer/enhanced/2025-08-04-chapter02.md",
                "balancer/enhanced/2025-08-05-chapter03.md",
                "balancer/enhanced/2025-08-06-chapter04.md",
                "balancer/enhanced/2025-08-07-chapter05.md",
            ]
        },
        {
            title: "第13部分：实战负载均衡",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "balancer/actual/2025-08-08-chapter01.md",
            ]
        },
        {
            title: "第14部分：配置中心",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "config/2025-08-09-chapter01.md",
                "config/2025-08-10-chapter02.md",
                "config/2025-08-11-chapter03.md",
                "config/2025-08-12-chapter04.md",
                "config/2025-08-13-chapter05.md",
                "config/2025-08-14-chapter06.md",
            ]
        },
        {
            title: "第15部分：热插拔插件",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "plugin/2025-08-15-chapter01.md",
                "plugin/2025-08-16-chapter02.md",
            ]
        },
        {
            title: "第16部分：客户端SDK",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "client/2025-08-17-chapter01.md",
                "client/2025-08-18-chapter02.md",
                "client/2025-08-19-chapter03.md",
                "client/2025-08-20-chapter04.md",
                "client/2025-08-21-chapter05.md",
            ]
        },
        {
            title: "第17部分：完整实战实例",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "actual/2025-08-22-chapter01.md",
                "actual/2025-08-23-chapter02.md",
            ]
        },
        {
            title: "第18部分：专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "zj/summary.md",
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
            title: "第二十七篇：服务容错(降级)",
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
                "2023-02-15-《RPC手撸专栏》第110章-服务提供者整合服务限流.md",
                "2023-02-16-《RPC手撸专栏》第111章-服务消费者整合服务限流.md",
                "2023-02-16-《RPC手撸专栏》第111章-X-服务限流阶段作业.md"
            ]
        },
        {
            title: "第二十九篇：基于SPI扩展限流策略",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-17-《RPC手撸专栏》第112章-基于SPI扩展Semaphore限流策略.md",
                "2023-02-18-《RPC手撸专栏》第113章-基于SPI扩展Guava限流策略.md",
                "2023-02-18-《RPC手撸专栏》第113章-X-基于SPI扩展限流策略阶段作业.md"
            ]
        },
        {
            title: "第三十篇：超出限流规则",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-19-《RPC手撸专栏》第114章-服务提供者超出限流上限触发的规则.md",
                "2023-02-20-《RPC手撸专栏》第115章-服务消费者超出限流上限触发的规则.md",
                "2023-02-20-《RPC手撸专栏》第115章-X-超出限流规则阶段作业.md",
            ]
        },
        {
            title: "第三十一篇：服务熔断",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-21-《RPC手撸专栏》第116章-服务熔断基础模型设计.md",
                "2023-02-22-《RPC手撸专栏》第117章-服务提供者整合服务熔断.md",
                "2023-02-23-《RPC手撸专栏》第118章-服务消费者整合服务熔断.md",
                "2023-02-23-《RPC手撸专栏》第118章-X-服务熔断阶段作业.md",
            ]
        },
        {
            title: "第三十二篇：基于SPI扩展熔断策略",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-24-《RPC手撸专栏》第119章-基于SPI扩展错误率熔断策略.md",
                "2023-02-24-《RPC手撸专栏》第119章-X：基于SPI扩展熔断策略阶段作业.md"
            ]
        },
        {
            title: "第三十三篇：异常监控",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-03-05-《RPC手撸专栏》第120章-异常监控基础模型设计.md",
                "2023-03-06-《RPC手撸专栏》第121章-服务提供者整合异常监控.md",
                "2023-03-07-《RPC手撸专栏》第122章-服务消费者整合异常监控.md",
                "2023-03-07-《RPC手撸专栏》第122章-X-异常监控阶段作业.md"
            ]
        },
        {
            title: "维护篇：持续维护篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-02-25-《RPC手撸专栏》第fix-01章-修复服务消费者读取配置优先级的问题.md",
                "2023-02-26-《RPC手撸专栏》第fix-02章-修复Zookeeper一致性Hash负载均衡泛型类型不匹配的问题.md",
                "2023-02-27-《RPC手撸专栏》第fix-03章-修复自定义扫描器递归扫描文件标识不起作用的问题.md",
                "2023-02-28-《RPC手撸专栏》第fix-04章-修复基于SpringBoot启动服务消费者Netty Group多次连接的问题.md",
                "2023-03-01-《RPC手撸专栏》第fix-05章-修复基于计数器的限流策略不起作用的问题.md",
                "2023-03-02-《RPC手撸专栏》第fix-06章-修复基于SpringBoot启动服务消费者无法同时连接多个服务提供者的问题.md",
                "2023-03-03-《RPC手撸专栏》第fix-07章-更新基于Semaphore的限流策略.md",
                "2023-03-04-《RPC手撸专栏》第fix-08章-优化服务熔断半开启状态的执行逻辑.md"
            ]
        },
        {
            title: "番外篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-12-05-《从零开始手写RPC框架》电子书发布.md",
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

// getBarPeojectSeckill
function getBarPeojectSeckill() {
    return [
        {
            title: "专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-04-16-《Seckill秒杀系统》开篇-我要手把手教你搭建一个抗瞬时百万流量的秒杀系统.md",
            ]
        },
        {
            title: "研发背景",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-04-23-《Seckill秒杀系统》第1章-从多个角度聊聊为何要研发秒杀系统.md",
            ]
        },
        {
            title: "目标与挑战",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-04-《Seckill秒杀系统》第2章-秒杀系统的目标与挑战.md",
                "2023-05-05-《Seckill秒杀系统》第3章-秒杀系统高并发大流量的应对之道.md",
            ]
        },
        {
            title: "用户故事",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-08-《Seckill秒杀系统》第4章-秒杀系统需求与流程梳理.md",
                "2023-05-09-《Seckill秒杀系统》第5章-秒杀系统技术流程梳理.md",
            ]
        },
        {
            title: "架构设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-10-《Seckill秒杀系统》第6章-秒杀系统总体方案目标与架构设计.md",
                "2023-05-13-《Seckill秒杀系统》第9章-秒杀系统数据模型设计.md",

            ]
        },
        {
            title: "环境搭建",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-11-《Seckill秒杀系统》第7章-秒杀系统基础环境搭建.md",
                "2023-05-12-《Seckill秒杀系统》第8章-秒杀系统研发环境搭建.md",
                "2023-05-14-《Seckill秒杀系统》第10章-基于DDD快速搭建秒杀系统项目并测试.md"
            ]
        },
        {
            title: "用户服务设计与实现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-15-《Seckill秒杀系统》第11章-用户登录流程的设计与实现.md",
                "2023-05-16-《Seckill秒杀系统》第12章-访问登录授权限制接口的流程设计与实现.md",
            ]
        },
        {
            title: "秒杀活动设计与实现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-17-《Seckill秒杀系统》第13章-秒杀活动业务流程与接口设计.md",
                "2023-05-18-《Seckill秒杀系统》第14章-秒杀活动后端接口开发.md",
                "2023-05-19-《Seckill秒杀系统》第15章-秒杀活动运营端业务开发.md",
                "2023-05-20-《Seckill秒杀系统》第16章-秒杀活动用户端业务开发.md",
            ]
        },
        {
            title: "秒杀商品设计与实现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-21-《Seckill秒杀系统》第17章-秒杀商品业务流程与接口设计.md",
                "2023-05-22-《Seckill秒杀系统》第18章-秒杀商品后端业务与接口开发.md",
                "2023-05-23-《Seckill秒杀系统》第19章-秒杀商品运营端业务开发.md",
                "2023-05-24-《Seckill秒杀系统》第20章-秒杀商品用户端业务开发.md",
            ]
        },
        {
            title: "秒杀订单设计与实现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-25-《Seckill秒杀系统》第21章-秒杀订单业务流程与接口设计.md",
                "2023-05-26-《Seckill秒杀系统》第22章-秒杀订单后端业务与接口开发.md",
                "2023-05-27-《Seckill秒杀系统》第23章-秒杀订单用户端业务开发.md",
                "2023-05-28-《Seckill秒杀系统》第24章-秒杀订单运营端业务开发.md",
            ]
        },
        {
            title: "经典问题重现",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-05-29-《Seckill秒杀系统》第25章-重现刷单流量问题.md",
                "2023-05-30-《Seckill秒杀系统》第26章-重现库存超卖问题.md"
            ]
        },
        {
            title: "极致缓存设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-06-02-《Seckill秒杀系统》第27章-秒杀系统混合型缓存设计场景与原则.md",
                "2023-06-03-《Seckill秒杀系统》第28章-秒杀系统混合型缓存架构设计.md",
                "2023-06-04-《Seckill秒杀系统》第29章-秒杀系统混合型缓存通用代码设计与实现.md",
                "2023-06-07-《Seckill秒杀系统》第30章-分布式锁通用代码设计与实现.md",
                "2023-06-08-《Seckill秒杀系统》第31章-混合型缓存通用模型设计与实现.md"
            ]
        },
        {
            title: "整合极致缓存",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-06-09-《Seckill秒杀系统》第32章-活动列表混合型缓存设计与实现.md",
                "2023-06-10-《Seckill秒杀系统》第33章-活动详情混合型缓存设计与实现.md",
                "2023-06-12-《Seckill秒杀系统》第34章-商品列表混合型缓存设计与实现.md",
                "2023-06-13-《Seckill秒杀系统》第35章-商品详情混合型缓存设计与实现.md"
            ]
        },
        {
            title: "缓存领域事件",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-06-14-《Seckill秒杀系统》第36章-领域事件通用缓存模型设计.md",
                "2023-06-15-《Seckill秒杀系统》第37章-秒杀活动监听缓存领域事件的设计与实现.md",
                "2023-06-16-《Seckill秒杀系统》第38章-秒杀活动发送缓存领域事件的设计与实现.md",
                "2023-06-17-《Seckill秒杀系统》第39章-秒杀商品监听缓存领域事件的设计与实现.md",
                "2023-06-19-《Seckill秒杀系统》第40章-秒杀商品发送缓存领域事件的设计与实现.md"
            ]
        },
        {
            title: "订单领域事件",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-06-20-《Seckill秒杀系统》第41章-秒杀订单监听领域事件的设计与实现.md",
                "2023-06-21-《Seckill秒杀系统》第42章-秒杀订单发送领域事件的设计与实现.md"
            ]
        },
        {
            title: "库存扣减防超卖设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-06-24-《Seckill秒杀系统》第43章-秒杀扣减库存设计.md",
                "2023-06-25-《Seckill秒杀系统》第44章-基于数据库设计并实现库存防超卖.md",
                "2023-06-26-《Seckill秒杀系统》第45章-基于分布式锁设计并实现库存防超卖.md",
                "2023-06-27-《Seckill秒杀系统》第46章-基于Lua脚本设计并实现库存防超卖.md"
            ]
        },
        {
            title: "单体到微服务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-04-《Seckill秒杀系统》第47章-从单体到微服务重构项目.md",
                "2023-07-06-《Seckill秒杀系统》第48章-重现分布式事务问题.md",
                "2023-07-08-《Seckill秒杀系统》第49章-基于TCC模型解决分布式事务问题.md",
                "2023-07-10-《Seckill秒杀系统》第50章-基于AT模型解决分布式事务问题.md",
                "2023-07-14-《Seckill秒杀系统》第51章-基于可靠消息最终一致性模型解决分布式事务问题.md"
            ]
        },
        {
            title: "缓存数据一致性",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-17-《Seckill秒杀系统》第52章-零侵入重构秒杀活动异步事件后置处理器.md",
                "2023-07-18-《Seckill秒杀系统》第53章-零侵入重构秒杀商品异步事件后置处理器.md",
                "2023-07-19-《Seckill秒杀系统》第54章-零侵入重构秒杀订单异步事件后置处理器.md"
            ]
        },
        {
            title: "异步化设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-20-《Seckill秒杀系统》第55章-异步化下单流程设计.md",
                "2023-07-22-《Seckill秒杀系统》第56章-异步化下单编码实现.md",
                "2023-07-23-《Seckill秒杀系统》第57章-异步化扣减商品库存流程设计.md",
                "2023-07-24-《Seckill秒杀系统》第58章-异步化扣减商品库存编码实现.md"
            ]
        },
        {
            title: "库存分库分表与分桶设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-25-《Seckill秒杀系统》第59章-商品库存分库分表与分桶设计.md",
                "2023-07-27-《Seckill秒杀系统》第60章-商品库存分库分表与分桶编码实现.md",
                "2023-07-29-《Seckill秒杀系统》第61章-下单流程整合商品库存分桶.md",
            ]
        },
        {
            title: "订单分库分表设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-07-31-《Seckill秒杀系统》第62章-订单分库分表设计.md",
                "2023-08-01-《Seckill秒杀系统》第63章-订单分库分表编码实现.md",
                "2023-08-02-《Seckill秒杀系统》第64章-下单流程整合订单分库分表.md"
            ]
        },
        {
            title: "隔离与限制策略",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-03-《Seckill秒杀系统》第65章-秒杀系统流量隔离策略.md",
                "2023-08-07-《Seckill秒杀系统》第66章-秒杀系统规模限制策略.md"
            ]
        },
        {
            title: "预约系统设计与实现(含缓存)",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-08-《Seckill秒杀系统》第67章-预约系统需求梳理与架构设计.md",
                "2023-08-09-《Seckill秒杀系统》第68章-预约系统数据模型设计.md",
                "2023-08-10-《Seckill秒杀系统》第69章-预约系统业务流程与接口设计.md",
                "2023-08-11-《Seckill秒杀系统》第70章-预约系统运营端业务与接口开发.md",
                "2023-08-12-《Seckill秒杀系统》第71章-预约系统用户端业务与接口开发.md",
                "2023-08-13-《Seckill秒杀系统》第72章-下单流程整合预约系统.md"
            ]
        },
        {
            title: "预约系统优化",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-14-《Seckill秒杀系统》第73章-预约系统分库分表设计.md",
                "2023-08-15-《Seckill秒杀系统》第74章-预约系统分库分表实现.md",
                "2023-08-16-《Seckill秒杀系统》第75章-预约系统整合分库分表.md"
            ]
        },
        {
            title: "秒杀系统削峰策略",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-17-《Seckill秒杀系统》第76章-限流总体概述.md",
                "2023-08-18-《Seckill秒杀系统》第77章-打散客户端流量.md",
                "2023-08-19-《Seckill秒杀系统》第78章-消息队列削峰.md",
                "2023-08-20-《Seckill秒杀系统》第79章-限流削峰.md"
            ]
        },
        {
            title: "分布式流控",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-21-《Seckill秒杀系统》第80章-搭建Sentinel环境.md",
                "2023-08-22-《Seckill秒杀系统》第81章-秒杀系统整合Sentinel实现流控.md",
                "2023-08-23-《Seckill秒杀系统》第82章-Sentinel核心技术与配置规则.md"
            ]
        },
        {
            title: "单机限流",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-24-《Seckill秒杀系统》第83章-本地API限流.md",
                "2023-08-25-《Seckill秒杀系统》第84章-基于线程池实现单机并发数限流.md"
            ]
        },
        {
            title: "业务网关",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-08-26-《Seckill秒杀系统》第85章-业务网关概述与核心架构.md",
                "2023-08-27-《Seckill秒杀系统》第86章-秒杀系统整合业务网关.md",
                "2023-08-28-《Seckill秒杀系统》第87章-业务网关整合Nacos配置.md",
                "2023-08-29-《Seckill秒杀系统》第88章-业务网关整合Sentinel流控.md",
                "2023-08-30-《Seckill秒杀系统》第89章-业务网关整合Guava流控.md",
                "2023-08-31-《Seckill秒杀系统》第90章-业务网关使用自带流控.md"
            ]
        },
        {
            title: "流量网关",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-01-《Seckill秒杀系统》第91章-流量网关初步搭建.md",
                "2023-09-02-《Seckill秒杀系统》第92章-流量网关项目搭建.md",
                "2023-09-03-《Seckill秒杀系统》第93章-流量网关实现限流.md"
            ]
        },
        {
            title: "服务容错",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-04-《Seckill秒杀系统》第94章-服务雪崩与容错方案.md",
                "2023-09-05-《Seckill秒杀系统》第95章-服务降级核心原理与落地方案.md",
                "2023-09-06-《Seckill秒杀系统》第96章-热点数据问题与解决方案.md",
                "2023-09-07-《Seckill秒杀系统》第97章-秒杀系统实现容错.md"
            ]
        },
        {
            title: "服务配置",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-08-《Seckill秒杀系统》第98章-凌乱的服务配置与解决方案.md",
                "2023-09-09-《Seckill秒杀系统》第99章-秒杀系统整合Nacos配置中心.md",
                "2023-09-10-《Seckill秒杀系统》第100章-实现配置动态刷新.md",
                "2023-09-11-《Seckill秒杀系统》第101章-实现配置动态共享.md"
            ]
        },
        {
            title: "链路追踪",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-12-《Seckill秒杀系统》第102章-链路追踪核心原理与解决方案.md",
                "2023-09-13-《Seckill秒杀系统》第103章-整合Sleuth实现链路追踪.md",
                "2023-09-14-《Seckill秒杀系统》第104章-扩展Dubbo源码实现链路追踪.md",
                "2023-09-15-《Seckill秒杀系统》第105章-Sleuth整合ZipKin实现可视化.md"
            ]
        },
        {
            title: "日志治理",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-16-《Seckill秒杀系统》第106章-日志治理概述与原则.md",
                "2023-09-17-《Seckill秒杀系统》第107章-快速搭建ELK环境并导入配置.md",
                "2023-09-18-《Seckill秒杀系统》第108章-秒杀系统整合日志治理.md"
            ]
        },
        {
            title: "防刷方案",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-19-《Seckill秒杀系统》第109章-实现基于条件限流防刷.md",
                "2023-09-20-《Seckill秒杀系统》第110章-实现基于Token机制防刷.md",
                "2023-09-21-《Seckill秒杀系统》第111章-实现基于黑名单机制防刷.md"
            ]
        },
        {
            title: "风控模型",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-22-《Seckill秒杀系统》第112章-黑灰产与风控基础知识介绍.md",
                "2023-09-23-《Seckill秒杀系统》第113章-风控模型架构与落地方案.md",
                "2023-09-24-《Seckill秒杀系统》第114章-秒杀系统风控模型设计.md",
                "2023-09-25-《Seckill秒杀系统》第115章-秒杀系统风控模型实现.md"
            ]
        },
        {
            title: "容器化集群部署",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-26-《Seckill秒杀系统》第116章-容器化集群部署架构设计.md",
                "2023-09-27-《Seckill秒杀系统》第117章-容器化集群部署落地实现.md",
                "2023-09-28-《Seckill秒杀系统》第118章-容灾架构设计与落地方案.md"
            ]
        },
        {
            title: "全链路压测",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-09-29-《Seckill秒杀系统》第119章-全链路压测场景与核心流程.md",
                "2023-09-30-《Seckill秒杀系统》第120章-全链路压测核心原则与策略.md",
                "2023-10-01-《Seckill秒杀系统》第121章-全链路压测落地方案实施.md"
            ]
        },
        {
            title: "极致优化",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-10-02-《Seckill秒杀系统》第122章-服务器物理机极致优化.md",
                "2023-10-03-《Seckill秒杀系统》第123章-单机服务极致优化.md",
                "2023-10-04-《Seckill秒杀系统》第124章-秒杀系统流程极致优化.md"
            ]
        },
        {
            title: "专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-10-05-《Seckill秒杀系统》结尾-秒杀系统整体专栏总结.md"
            ]
        },
        {
            title: "番外篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-12-10-cache-design.md"
            ]
        }
    ]
}
// getBarPeojectIM
function getBarPeojectIM() {
    return [
        {
            title: "开篇：专栏介绍",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "start/2023-11-20-start.md",
                "start/2023-12-08-interview.md"
            ]
        },
        {
            title: "第01部分：需求设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "requirement/2023-11-23-chapter01.md",
                "requirement/2023-11-25-chapter02.md",
                "requirement/2023-11-26-chapter03.md",
                "requirement/2023-11-28-chapter04.md",
            ]
        },
        {
            title: "第02部分：总体架构设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "architecture/2023-11-29-chapter01.md",
                "architecture/2023-11-30-chapter02.md",
            ]
        },
        {
            title: "第03部分：环境搭建",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "environment/2023-12-01-chapter01.md",
                "environment/2023-12-04-chapter02.md",
                "environment/2023-12-05-chapter03.md",
                "environment/2023-12-06-chapter04.md",
            ]
        },
        {
            title: "第04部分：通用模型设计",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "model/2023-12-09-chapter01.md",
                "model/2023-12-10-chapter02.md",
                "model/2023-12-11-chapter03.md",
                "model/2023-12-12-chapter04.md",
                "model/2023-12-13-chapter05.md",
                "model/2023-12-14-chapter06.md",
                "model/2023-12-15-chapter07.md",
            ]
        },
        {
            title: "第05部分：即时通讯后端服务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "im-backend/2023-12-15-chapter01.md",
                "im-backend/2023-12-16-chapter02.md",
                "im-backend/2023-12-17-chapter03.md",
                "im-backend/2023-12-18-chapter04.md",
                "im-backend/2023-12-19-chapter05.md",
                "im-backend/2023-12-20-chapter06.md",
                "im-backend/2023-12-21-chapter07.md"
            ]
        },
        {
            title: "第06部分：即时通讯SDK",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "sdk/2023-12-22-chapter01.md",
                "sdk/2023-12-23-chapter02.md",
                "sdk/2023-12-24-chapter03.md",
                "sdk/2023-12-25-chapter04.md",
                "sdk/2023-12-26-chapter05.md",
            ]
        },
        {
            title: "第07部分：大后端平台-通用模型",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "platform/model/2023-12-27-chapter01.md",
                "platform/model/2023-12-28-chapter02.md",
                "platform/model/2023-12-29-chapter03.md",
                "platform/model/2023-12-30-chapter04.md",
                "platform/model/2023-12-31-chapter05.md",
                "platform/model/2024-01-01-chapter06.md",
                "platform/model/2024-01-02-chapter07.md",
                "platform/model/2024-01-03-chapter08.md",
            ]
        },
        {
            title: "第08部分：大后端平台-用户微服务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "platform/user/2024-01-05-chapter01.md",
                "platform/user/2024-01-06-chapter02.md",
                "platform/user/2024-01-07-chapter03.md",
                "platform/user/2024-01-08-chapter04.md",
                "platform/user/2024-01-09-chapter05.md",
                "platform/user/2024-01-10-chapter06.md",
            ]
        },
        {
            title: "第09部分：大后端平台-好友微服务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "platform/friend/2024-01-11-chapter01.md",
                "platform/friend/2024-01-14-chapter02.md",
                "platform/friend/2024-01-15-chapter03.md",
                "platform/friend/2024-01-16-chapter04.md",
            ]
        },
        {
            title: "第10部分：大后端平台-群组微服务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "platform/group/2024-01-17-chapter01.md",
                "platform/group/2024-01-18-chapter02.md",
                "platform/group/2024-01-19-chapter03.md",
                "platform/group/2024-01-20-chapter04.md",
            ]
        },
        {
            title: "第11部分：大后端平台-消息微服务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "platform/message/2024-01-21-chapter01.md",
                "platform/message/2024-01-22-chapter02.md",
                "platform/message/2024-01-23-chapter03.md",
                "platform/message/2024-01-24-chapter04.md",
                "platform/message/2024-01-25-chapter05.md",
                "platform/message/2024-01-26-chapter06.md",
                "platform/message/2024-01-27-chapter07.md",
                "platform/message/2024-01-28-chapter08.md",
                "platform/message/2024-01-29-chapter09.md",
                "platform/message/2024-01-30-chapter10.md",
            ]
        },
        {
            title: "第12部分：大后端平台-视频通话",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "platform/video/2024-01-31-chapter01.md",
                "platform/video/2024-02-01-chapter02.md",
                "platform/video/2024-02-02-chapter03.md",
                "platform/video/2024-02-03-chapter04.md",
                "platform/video/2024-02-04-chapter05.md",
                "platform/video/2024-02-05-chapter06.md",
                "platform/video/2024-02-06-chapter07.md",
            ]
        },
        {
            title: "第13部分：大前端UI-基础架构",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "front/base/2024-02-07-chapter01.md",
                "front/base/2024-02-08-chapter02.md"
            ]
        },
        {
            title: "第14部分：大前端UI-用户模块",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "front/user/2024-02-09-chapter01.md",
                "front/user/2024-02-10-chapter02.md"
            ]
        },
        {
            title: "第15部分：大前端UI-好友模块",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "front/friend/2024-02-11-chapter01.md",
                "front/friend/2024-02-12-chapter02.md",
            ]
        },
        {
            title: "第16部分：大前端UI-群组模块",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "front/group/2024-02-13-chapter01.md",
                "front/group/2024-02-14-chapter02.md",
                "front/group/2024-02-15-chapter03.md",
                "front/group/2024-02-16-chapter04.md",
                "front/group/2024-02-17-chapter05.md",
                "front/group/2024-02-18-chapter06.md",
                "front/group/2024-02-19-chapter07.md",
                "front/group/2024-02-20-chapter08.md",
            ]
        },
        {
            title: "第17部分：大前端UI-消息模块",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "front/message/2024-02-21-chapter01.md",
                "front/message/2024-02-22-chapter02.md",
                "front/message/2024-02-23-chapter03.md",
                "front/message/2024-02-24-chapter04.md",
                "front/message/2024-02-25-chapter05.md",
                "front/message/2024-02-26-chapter06.md",
                "front/message/2024-02-27-chapter07.md",
                "front/message/2024-02-28-chapter08.md",
                "front/message/2024-02-29-chapter09.md",
                "front/message/2024-03-01-chapter10.md",
                "front/message/2024-03-02-chapter11.md",
            ]
        },
        {
            title: "第18部分：OpenAI大模型接入服务",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "openai/2024-03-03-chapter01.md",
                "openai/2024-03-04-chapter02.md",
                "openai/2024-03-05-chapter03.md",
                "openai/2024-03-06-chapter04.md",
                "openai/2024-03-07-chapter05.md",
                "openai/2024-03-08-chapter06.md",
                "openai/2024-03-09-chapter07.md",
            ]
        },
        {
            title: "第19部分：专栏总结",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "summary/2024-03-10-summary.md",
            ]
        }
        /*{
            title: "第14部分：OpenAI接入服务",
            collapsable: true,
            sidebarDepth: 0,
            children: [
                "develop/develop.md",
            ]
        },
        {
            title: "第15部分：部署与监控",
            collapsable: true,
            sidebarDepth: 0,
            children: [
                "develop/develop.md",
            ]
        },
        {
            title: "结尾：专栏总结",
            collapsable: true,
            sidebarDepth: 0,
            children: [
                "develop/develop.md",
            ]
        }*/
    ]
}

function getBarHack() {
    return [
        {
            title: "第01部分：基础环境篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "environment/2022-04-17-001-安装Kali系统.md",
                "environment/2022-04-17-002-Kali配置.md",
                "environment/2022-04-17-003-Kali中各项菜单的功能.md",
                "environment/2022-04-17-004-安装open-vm-tools实现虚拟机交互.md",
                "environment/2022-04-17-005-Kali设置静态IP.md",
                "environment/2022-04-17-006-kali安装免杀工具Veil-Evasion.md",
                "environment/2022-04-17-007-在Debian8上安装WPScan.md",
                "environment/2022-04-17-008-metasploitable2修改密码.md",
                "environment/2022-04-17-009-操作系统支持的管道符.md",
            ]
        },
        {
            title: "第02部分：渗透工具篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "tools/2022-04-17-001-使用Easy-Creds工具攻击无线网络.md",
                "tools/2022-04-17-002-Nmap+Zenmap+Amap+Zmap.md",
                "tools/2022-04-17-003-Zenmap.md",
                "tools/2022-04-17-004-Amap.md",
                "tools/2022-04-17-005-Zmap.md",
                "tools/2022-04-17-006-Nessus的整理.md",
                "tools/2022-04-17-007-Burpsuite上传截断及截断原理介绍.md",
                "tools/2022-04-17-008-Kali2.0Meterpreter运用.md",
                "tools/2022-04-17-009-lcx.exe内网转发命令教程-LCX免杀下载.md",
                "tools/2022-04-17-010-字典生成工具Crunch的使用案例.md",
                "tools/2022-04-17-011-WinlogonHack获取系统密码.md",
                "tools/2022-04-17-012-Msfvenom生成各类Payload命令.md",
                "tools/2022-04-17-013-PsExec下载地址及其用法.md",
                "tools/2022-04-17-014-Hydra安装Libssh模块.md",
                "tools/2022-04-17-015-利用procdump+Mimikatz绕过杀软获取Windows明文密码.md",
                "tools/2022-04-17-016-SQLMap的用法+谷歌黑客语法.md",
                "tools/2022-04-17-017-SQLMap用法总结.md",
                "tools/2022-04-17-018-SQLMap参数说明.md",
                "tools/2022-04-17-019-十大渗透测试演练系统.md",
                "tools/2022-04-17-020-目录扫描神器DirBuster用法.md",
                "tools/2022-04-17-021-NMap在实战中的常见用法.md",
                "tools/2022-04-17-022-Metasploit模块的格式说明.md",
                "tools/2022-04-17-023-Meterpreter命令大全.md",
                "tools/2022-04-17-024-Metasploit-Meterpreter-Shell信息收集相关的命令.md",
                "tools/2022-04-17-025-使用Metasploit编写绕过DEP渗透模块.md",
                "tools/2022-04-17-026-Metasploit渗透php-utility-belt程序.md",
                "tools/2022-04-17-027-内网IPC$入侵.md",
                "tools/2022-04-17-028-Metasploit渗透BSPlayerV2.68.md",
                "tools/2022-04-17-029-Metasploit攻击VSFTPD2.3.4后门漏洞并渗透内网.md",
                "tools/2022-04-17-030-Metasploit攻击PHP-CGI查询字符串参数漏洞并渗透内网.md",
                "tools/2022-04-17-031-Metasploit攻击HFS2.3上的漏洞.md",
                "tools/2022-04-17-032-Metasploit访问控制的持久化.md",
                "tools/2022-04-17-033-Metasploit清除渗透痕迹.md",
                "tools/2022-04-17-034-利用Metasploit找出SCADA服务器.md",
                "tools/2022-04-17-035-利用Metasploit渗透DATAC-RealWin-SCADA Server2.0.md",
                "tools/2022-04-17-036-MSF-Meterpreter清理日志.md",
                "tools/2022-04-17-037-Metasploit自定义FTP扫描模块.md",
                "tools/2022-04-17-038-Metasploit渗透MSSQL.md",
                "tools/2022-04-17-039-Metasploit渗透VOIP.md",
                "tools/2022-04-17-040-破解工具hydra安装与使用.md",
                "tools/2022-04-17-041-Metasploit自定义SSH认证暴力破解器.md",
                "tools/2022-04-17-042-Metasploit自定义让磁盘失效的后渗透模块.md",
                "tools/2022-04-17-043-PowerShell基本命令和绕过权限执行.md",
                "tools/2022-05-02-001-Metasploit自定义收集登录凭证的后渗透模块.md",
                "tools/2022-05-02-002-利用Java生成穷举字典(数字+字母(大小写)+字符).md",
                "tools/2022-05-02-003-PowerShell工具之Powerup详解实录.md",
                "tools/2022-05-02-004-Meterpreter以被控制的计算机为跳板渗透其他服务器.md",
                "tools/2022-05-02-005-Win10完美去除桌面快捷图标小箭头.md",
                "tools/2022-05-02-006-OpenVAS8.0-Vulnerability-Scanning.md",
                "tools/2022-05-02-007-kali-Metasploit连接Postgresql默认密码.md",
                "tools/2022-05-02-008-使用OpenVAS进行漏洞扫描.md",
                "tools/2022-05-02-009-对威胁建模附加搭建CVE2014-6287漏洞环境.md",
                "tools/2022-05-02-010-Metasploit设置永久访问权限.md",
                "tools/2022-05-02-011-Empire反弹回Metasploit.md",
                "tools/2022-05-02-012-Metasploit制作并运行自定义Meterpreper脚本.md",
                "tools/2022-05-02-013-使用Metasploit实现对缓冲区栈的溢出攻击.md",
                "tools/2022-05-02-014-使用Metasploit实现基于SEH的缓冲区溢出攻击.md",
                "tools/2022-05-02-015-Metasploit基本后渗透命令.md",
                "tools/2022-05-02-016-Metasploit高级后渗透模块.md",
                "tools/2022-05-02-017-Kali中一键更新Metasploit框架.md",
                "tools/2022-05-02-018-Metasploit其他后渗透模块.md",
                "tools/2022-05-02-019-Metasploit高级扩展功能.md",
                "tools/2022-05-02-020-Metasploit之pushm和popm命令.md",
                "tools/2022-05-02-021-Metasploit使用reload-edit-reload_all命令加快开发过程.md",
                "tools/2022-05-02-022-Metasploit资源脚本的使用方法.md",
                "tools/2022-05-02-023-在Metasploit中使用AutoRunScript.md",
                "tools/2022-05-02-024-使用Metasploit获取目标的控制权限.md",
                "tools/2022-05-02-025-使用Metasploit中的NMap插件扫描并渗透内网主机.md",
                "tools/2022-05-02-026-Kali一句话升级Metasploit的命令.md",
                "tools/2022-05-02-027-Win2012R2打Windows8.1-KB2919355.md",
                "tools/2022-05-02-028-Armitage基本原理.md",
                "tools/2022-05-02-029-Armitage网络扫描以及主机管理.md",
                "tools/2022-05-02-030-使用Armitage进行渗透.md",
                "tools/2022-05-02-031-使用Armitage进行后渗透攻击.md",
                "tools/2022-05-02-032-使用Armitage进行客户端攻击.md",
                "tools/2022-05-02-033-Armitage脚本编写.md",
                "tools/2022-05-02-034-Armitage控制Metasploit.md",
                "tools/2022-05-02-035-Armitage使用Cortana实现后渗透攻击.md",
                "tools/2022-05-02-036-Armitage使用Cortana创建自定义菜单.md",
                "tools/2022-05-02-037-Armitage界面的使用.md",
                "tools/2022-05-02-038-tcpdump用法说明.md",
            ]
        },
        {
            title: "第03部分：木马篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "horse/2022-05-02-001-各种一句话木马大全.md",
                "horse/2022-05-02-002-asp图片木马的制作和使用.md",
            ]
        },
        {
            title: "第04部分：SQL注入篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "sql/2022-05-02-001-sqli-labs-master下载与安装.md",
                "sql/2022-05-02-002-SQL注入点检测方法.md",
                "sql/2022-05-02-003-SQL语句生成一句话.md",
                "sql/2022-05-02-004-ASP连接MSSQL数据库语句.md",
                "sql/2022-05-02-005-SQL注入绕过技术总结.md",
                "sql/2022-05-02-006-SQLServer启动-关闭xp_cmdshell.md",
            ]
        },
        {
            title: "第05部分：漏洞拿Shell篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "shell/2022-05-02-001-各种解析漏洞拿shell.md",
                "shell/2022-05-02-002-网站入侵思路.md",
                "shell/2022-05-02-003-IIS6.0-7.0-7.5-Nginx-Apache等WebService解析漏洞.md",
                "shell/2022-05-02-004-iis7.5加fck解析漏洞后台拿shell.md",
                "shell/2022-05-02-005-真正的IIS永远的后门解密.md",
            ]
        },
        {
            title: "第06部分：暴力破解篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "crack/2022-05-02-001-使用rarcrack暴力破解RAR-ZIP-7Z压缩包.md",
                "crack/2022-05-02-002-使用reaver傻瓜式破解wifi之利用路由器WPS漏洞.md",
                "crack/2022-05-02-003-Python爆破Wifi密码.md",
                "crack/2022-05-02-004-MySQL暴力破解工具多线程版.md",
            ]
        },
        {
            title: "第07部分：渗透脚本篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "bash/2022-05-02-001-3389脚本开启代码(vbs版).md",
                "bash/2022-05-02-002-触发EasyFileSharingWebServer7.2HEAD缓冲区溢出的Python脚本.md",
            ]
        },
        {
            title: "第08部分：数据与系统提权篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "raising/2022-05-02-001-数据库提权.md",
                "raising/2022-05-02-002-NC反弹CMDSHELL提权总结.md",
                "raising/2022-05-02-003-ASP-Web提权.md",
                "raising/2022-05-02-004-MSF提权.md",
                "raising/2022-05-02-005-Metasploit-Win10提权.md",
            ]
        },
        {
            title: "第09部分：客户端渗透篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "client/2022-05-02-001-浏览器渗透.md",
                "client/2022-05-02-002-对网站的客户进行渗透.md",
                "client/2022-05-02-003-与DNS欺骗的结合使用.md",
                "client/2022-05-02-004-基于PDF文件格式的渗透攻击.md",
                "client/2022-05-02-005-基于Word文件格式的渗透攻击.md",
                "client/2022-05-02-006-使用Metasploit实现对Linux客户端的渗透.md",
                "client/2022-05-02-007-使用Metasploit渗透Android系统.md",
            ]
        },
        {
            title: "第10部分：社会工程学",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "sociology/2022-05-02-001-Metasploit之社会工程学工具包.md",
            ]
        },
        {
            title: "第11部分：log4j重大漏洞",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "log4j/2022-05-30-冰河连夜复现了Log4j最新重大漏洞.md",
            ]
        },
        {
            title: "第12部分：问题记录篇",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "question/2022-05-02-001-HTTP错误4031禁止访问-执行访问被拒绝.md",
                "question/2022-05-02-002-XP-IIS问题总结.md",
                "question/2022-05-02-003-IIS-403-404问题.md",
                "question/2022-05-02-004-DEDE5.7初始化数据体验包获取失败-无法下载安装.md",
                "question/2022-05-02-005-discuz报错Tableuc-uc_pms-doesnt-exist-uc_pms不存在.md",
                "question/2022-05-02-006-Windows远程登录提示超出允许最大连接数解决方案.md",
                "question/2022-05-02-007-Windows2008自动关机最简单的解决方案.md",
                "question/2022-05-02-008-Hydra安装报错.md",
                "question/2022-05-02-009-安装OpenVAS后找不到默认密码无法登录Web端.md",
                "question/2022-05-02-010-AppScan使用问题记录.md",
                "question/2022-05-02-011-Kali系统报错.md",
                "question/2022-05-02-012-Kali运行WPScan报错.md",
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
// getBarBookAll
function getBarBookAll() {
    return [
        {
            title: "出版图书",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2023-03-26-书籍汇总.md",
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
                "2023-02-27-深入理解高并发编程-JDK核心技术.md",
                "2023-02-03-深入高平行開發.md",
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
                "2023-11-27-concurrent-design-mode.md",
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
                "2025-05-18-chapter00.md",
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
                "2023-09-07-JVM各种参数配置.md"
            ]
        },
        {
            title: "JVM生产实践",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2025-05-25-chapter001.md",
                "2025-05-25-chapter002.md",
                "2025-05-25-chapter003.md",
                "2025-05-25-chapter004.md",
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
            sidebarDepth: 1,
            children: [
                "introduce.md",
                "guide/guide.md",
                "other/join.md",
                "other/project.md"
                /*"2023-10-06-introduce.md",*/
                /*"2023-07-09-秒杀系统.md",
                "2023-06-06-想跳槽没项目经验该如何破局.md",*/
            ]
        },
        {
            title: "星球归档",
            collapsable: false,
            sidebarDepth: 1,
            children: [
                "essence/essence.md"
            ]
        },
        {
            title: "AI大模型",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "project/ai/qa/2025-01-14-start.md",
                "project/ai/dk/v1/2025-10-25-start.md",
            ]
        },
        {
            title: "高并发项目",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "project/im/2023-11-20-im.md",
                "project/seckill/2023-04-16-seckill.md",
                "project/concurrent/2023-09-17-concurrent-design.md",
            ]
        },
        {
            title: "中间件项目",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "project/redis-plugin/2025-10-20-start.md",
                "project/sentitive/2025-09-08-start.md",
                "project/threadpool/2025-08-26-start.md",
                "project/sql/2025-08-12-start.md",
                "project/gateway/2024-05-19-start.md",
                "project/rpc/2022-08-24-rpc.md"
            ]
        },
        {
            title: "微服务项目",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "project/sa/2022-04-02-sa.md"
            ]
        },
        {
            title: "手撕源码",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "project/spring/2022-12-02-spring.md"
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


