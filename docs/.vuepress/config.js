module.exports = {
    port: "8080",
    dest: "docs/.vuepress/dist/",
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
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                src: 'https://s9.cnzz.com/z_stat.php?id=1278232949&web_id=1278232949',
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
                        text: '导读', link: '/md/other/guide-to-reading.md'
                    },
                    {
                        text: 'Java',
                        items: [
                            {
                                text: 'Java基础',
                                link: '/md/java/basics/default.md'
                            },
                            {
                                text: 'Java进阶',
                                link: '/md/java/advanced/default.md'
                            },
                            {
                                text: 'Java高级',
                                link: '/md/java/senior/default.md'
                            },
                            {
                                text: 'Java8新特性',
                                link: '/md/java/java8/2022-03-31-001-Java8有哪些新特性呢？.md'
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
                        text: '框架源码',
                        items: [
                            {
                                text: 'Spring源码',
                                link: '/md/frame/spring/default.md'
                            },
                            {
                                text: 'SpringMVC源码',
                                link: '/md/frame/springmvc/default.md'
                            },
                            {
                                text: 'MyBatis源码',
                                link: '/md/frame/mybatis/default.md'
                            },
                            {
                                text: 'Dubbo源码',
                                link: '/md/frame/dubbo/default.md'
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
                        text: '微服务',
                        items: [
                                {
                                    text: 'SpringBoot',
                                    link: '/md/microservices/springboot/default.md'
                                },
                                {
                                    text: 'SpringCloud',
                                    link: '/md/microservices/springcloud/default.md'
                                }
                            ]
                    },
                    {
                        text: '中间件',
                        items: [
                            {
                                text: '手写线程池',
                                link: '/md/middleware/threadpool/default.md'
                            },
                            {
                                text: '分布式限流',
                                link: '/md/middleware/limiter/default.md'
                            },
                            {
                                text: '开源项目',
                                link: '/md/middleware/independent/default.md'
                            }
                        ]
                    },
                    {
                        text: '项目实战',
                        link: '/md/project/default.md'
                    },
                    {
                        text: '渗透技术',
                        link: '/md/hack/default.md'
                    },
                    {
                        text: '面试',
                        link: '/md/interview/default.md'
                    },
                    {
                        text: '📚PDF',
                        items: [
                            {
                                text: '出版图书', items: [
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
                                        text: '冰河的渗透实战笔记',
                                        link: '/md/knowledge/pdf/2022-03-30-《冰河的渗透实战笔记》电子书，442页，37万字，正式发布.md'
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
                            {text: '关于职场', link: '/md/about/job/default.md'}
                        ]
                    },
                    {
                        text: 'Github',
                        link: 'https://github.com/binghe001/BingheGuide'
                    }
                ],
                sidebar: {
                    "/md/other/": genBarOther(),
                    "/md/java/": getBarJava(),
                    "/md/performance/": getBarPerformance(),
                    "/md/concurrent/": getBarConcurrent(),
                    "/md/frame/": getBarFrame(),
                    "/md/distributed/cache/": getBarDistributedCache(),
                    "/md/distributed/zookeeper/": getBarZookeeper(),
                    "/md/distributed/mq/": getBarMQ(),
                    "/md/distributed/netty/": getBarInternet(),
                    "/md/distributed/dubbo/": getBarDistributedDubbo(),
                    "/md/distributed/mongodb/": getBarDistributedMongodb(),
                    "/md/distributed/es/": getBarDistributedElasticSearch(),
                    "/md/microservices/": getBarMicroServices(),
                    "/md/middleware/": getBarMiddleware(),
                    "/md/project/": getBarPeoject(),
                    "/md/hack/": getBarHack(),
                    "/md/interview/": getInterview(),
                    "/md/knowledge/book/": getBarPDFPublish(),
                    "/md/knowledge/pdf/": getBarPDFSink(),
                    "/md/about/": getBarAbout(),
                }
            }
        }
    }
};


// other
function genBarOther() {
    return [
        {
            title: "阅读指南",
            collapsable: false,
            sidebarDepth: 2,
            children: [
                "guide-to-reading.md"
            ]
        }
    ]
}

// Java
function getBarJava() {
    return [
        {
            title: "Java基础",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "basics/default.md",
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
                "java8/2022-04-01-001-Java8新特性总结.md",
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

// Frame
function getBarFrame() {
    return [
        {
            title: "Spring源码",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "spring/default.md",
            ]
        },
        {
            title: "SpringMVC源码",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "springmvc/default.md",
            ]
        },
        {
            title: "MyBatis源码",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "mybatis/default.md",
            ]
        },
        {
            title: "Dubbo源码",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "dubbo/default.md",
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
// getBarMicroServices
function getBarMicroServices() {
    return [
        {
            title: "SpringBoot",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "springboot/default.md",
            ]
        },
        {
            title: "SpringCloud",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "springcloud/default.md",
            ]
        }
    ]
}
// getBarMiddleware
function getBarMiddleware() {
    return [
        {
            title: "手写线程池",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "threadpool/default.md",
            ]
        },
        {
            title: "分布式限流",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "limiter/default.md",
            ]
        },
        {
            title: "开源项目",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "independent/default.md",
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
// getBarHack
function getBarHack() {
    return [
        {
            title: "渗透技术",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getInterview
function getInterview() {
    return [
        {
            title: "面试",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "default.md",
            ]
        }
    ]
}
// getBarPDFPublish
function getBarPDFPublish() {
    return [
        {
            title: "《深入理解分布式事务：原理与实战》",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-03-29-深入理解分布式事务.md",
            ]
        },
        {
            title: "《MySQL技术大全：开发、优化与运维实战》",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-03-29-MySQL技术大全.md",
            ]
        },
        {
            title: "《海量数据处理与大数据技术实战》",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-03-29-海量数据处理与大数据技术实战.md",
            ]
        }
    ]
}
// getBarPDFSink
function getBarPDFSink() {
    return [
        {
            title: "冰河的渗透实战笔记",
            collapsable: false,
            sidebarDepth: 0,
            children: [
                "2022-03-30-《冰河的渗透实战笔记》电子书，442页，37万字，正式发布.md",
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

