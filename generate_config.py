#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate docs/.vuepress/config.ts from the original VuePress 1 config.js"""

import subprocess
import re

# Get the original config.js content from git
result = subprocess.run(
    'git show HEAD:docs/.vuepress/config.js',
    shell=True,
    cwd='D:/workspaces/binghe001/BingheGuide',
    capture_output=True,
    text=True,
    encoding='utf-8',
    errors='replace'
)

original_lines = result.stdout.split('\n')

# Find where the sidebar functions start (after the closing of module.exports = {...})
func_start = -1
for i, line in enumerate(original_lines):
    # Look for the comment or function definitions after the main config
    if i > 700 and (line.strip().startswith('// other') or line.strip().startswith('// getStudyRoadJava') or (line.strip().startswith('function ') and 'get' in line)):
        func_start = i
        break

if func_start == -1:
    # Fallback: find the closing of module.exports
    for i, line in enumerate(original_lines):
        if i > 700 and line.strip() == '};':
            func_start = i + 1
            break

print(f"Sidebar functions start at line: {func_start + 1}")

# Extract sidebar functions
sidebar_funcs = '\n'.join(original_lines[func_start:])

# The config.ts header with all the main config
config_header = '''import { defineUserConfig } from 'vuepress'
import { viteBundler } from '@vuepress/bundler-vite'
import { defaultTheme } from '@vuepress/theme-default'
import { mediumZoomPlugin } from '@vuepress/plugin-medium-zoom'

// Convert VuePress 1 sidebar format to VuePress 2 format
function s(prefix: string, groups: any[]): any[] {
  return groups.map((group: any) => {
    if (typeof group === 'string') return prefix + group
    return {
      text: group.title || '',
      collapsible: group.collapsable !== false,
      children: (group.children || []).map((child: any) => {
        if (typeof child === 'string') return prefix + child
        if (Array.isArray(child)) return { text: child[1], link: prefix + child[0] }
        return child
      })
    }
  })
}

export default defineUserConfig({
  dest: '.site',
  base: '/',
  shouldPrefetch: false,
  markdown: {
    code: {
      lineNumbers: true
    }
  },
  locales: {
    '/': {
      lang: 'zh-CN',
      title: '冰河技术',
      description: '包含：编程语言，开发技术，分布式，微服务，高并发，高可用，高可扩展，高可维护，JVM技术，MySQL，分布式数据库，分布式事务，云原生，大数据，云计算，渗透技术，各种面试题，面试技巧...'
    }
  },
  head: [
    ['link', { rel: 'icon', href: '/favicon.ico' }],
    ['meta', { name: 'robots', content: 'all' }],
    ['meta', { name: 'author', content: '冰河' }],
    ['meta', { 'http-equiv': 'Cache-Control', content: 'no-cache, no-store, must-revalidate' }],
    ['meta', { 'http-equiv': 'Pragma', content: 'no-cache' }],
    ['meta', { 'http-equiv': 'Expires', content: '0' }],
    ['meta', { name: 'keywords', content: '冰河，冰河技术, 编程语言，开发技术，分布式，微服务，高并发，高可用，高可扩展，高可维护，JVM技术，MySQL，分布式数据库，分布式事务，云原生，大数据，云计算，渗透技术，各种面试题，面试技巧' }],
    ['meta', { name: 'apple-mobile-web-app-capable', content: 'yes' }],
    ['script', { charset: 'utf-8', async: 'async', src: '/js/jquery.min.js' }],
    ['script', { charset: 'utf-8', async: 'async', src: '/js/global.js' }],
    ['script', { charset: 'utf-8', async: 'async', src: '/js/fingerprint2.min.js' }],
    ['script', { charset: 'utf-8', async: 'async', src: 'https://v1.cnzz.com/z_stat.php?id=1281063564&web_id=1281063564' }],
    ['script', { charset: 'utf-8', async: 'async', src: 'https://s9.cnzz.com/z_stat.php?id=1281064551&web_id=1281064551' }],
    ['script', {}, `var _hmt = _hmt || [];(function() {var hm = document.createElement("script");hm.src = "https://hm.baidu.com/hm.js?d091d2fd0231588b1d0f9231e24e3f5e";var s = document.getElementsByTagName("script")[0];s.parentNode.insertBefore(hm, s);})();`]
  ],
  bundler: viteBundler(),
  theme: defaultTheme({
    docsRepo: 'binghe001/BingheGuide',
    docsDir: 'docs',
    docsBranch: 'master',
    editLink: true,
    sidebarDepth: 0,
    locales: {
      '/': {
        selectLanguageName: '简体中文',
        editLinkText: '在 GitHub 上编辑此页',
        lastUpdatedText: '上次更新',
        navbar: [
          { text: '导读', link: '/md/all/all.md' },
          {
            text: '♻学习路线',
            link: '/md/study/concurrent/concurrent_road.md'
          },
          {
            text: '踩坑经历',
            children: [
              {
                text: '面试必问系列',
                children: [
                  { text: '面试必问', link: '/md/interview/2022-04-18-001-面试必问-聊聊JVM性能调优.md' }
                ]
              }
            ]
          },
          {
            text: '核心技术',
            children: [
              {
                text: '架构与模式',
                children: [
                  { text: 'Java极简设计模式', link: '/md/core/design/java/2023-07-09-《Java极简设计模式》第01章-单例模式.md' },
                  { text: '实战高并发设计模式', link: '/md/core/design/concurrent/2023-09-17-start.md' }
                ]
              },
              {
                text: 'Java核心技术',
                children: [
                  { text: 'Java8新特性', link: '/md/core/java/java8/2022-03-31-001-Java8有哪些新特性呢？.md' },
                  { text: 'IOC核心技术', link: '/md/core/spring/ioc/2022-04-04-001-聊聊Spring注解驱动开发那些事儿.md' },
                  { text: 'JVM调优技术', link: '/md/core/jvm/2025-05-18-chapter00.md' }
                ]
              },
              {
                text: '容器化核心技术',
                children: [
                  { text: 'Dockek核心技术', link: '/md/core/docker/2023-09-10-《容器化核心设计》第01章-制作Java基础docker镜像.md' }
                ]
              },
              {
                text: '分布式存储',
                children: [
                  { text: 'Mycat核心技术', link: '/md/core/mycat/2023-08-11-《Mycat核心技术》第01章-互联网大厂有哪些分库分表的思路和技.md' }
                ]
              },
              {
                text: '数据库核心技术',
                children: [
                  { text: 'MySQL基础篇', link: '/md/core/mysql/base/2022-08-25-MySQL索引底层技术.md' }
                ]
              },
              {
                text: '服务器核心技术',
                children: [
                  { text: 'Nginx核心技术', link: '/md/core/nginx/2023-07-23-《Nginx核心技术》第01章-安装Nginx.md' }
                ]
              },
              {
                text: '渗透核心技术',
                children: [
                  { text: '渗透实战技术', link: '/md/hack/environment/2022-04-17-001-安装Kali系统.md' }
                ]
              }
            ]
          },
          {
            text: '并发编程',
            children: [
              { text: '底层技术', link: '/md/concurrent/bottom/default.md' },
              { text: '源码分析', link: '/md/concurrent/source/2020-03-30-001-一文搞懂线程与多线程.md' },
              { text: '基础案例', link: '/md/concurrent/basics/2020-03-30-001-明明中断了线程，却为何不起作用呢？.md' },
              { text: '实战案例', link: '/md/concurrent/ActualCombat/default.md' },
              { text: '面试', link: '/md/concurrent/interview/default.md' },
              { text: '系统架构', link: '/md/concurrent/framework/default.md' }
            ]
          },
          {
            text: '框架源码',
            children: [
              { text: 'Spring6核心技术', link: '/md/frame/spring/ioc/2022-12-02-《Spring核心技术》开篇-我要带你一步步调试Spring6.0源码啦.md' }
            ]
          },
          {
            text: '分布式',
            children: [
              {
                text: '分布式事务',
                children: [
                  { text: '分布式事务系列视频', link: '/md/distributed/transaction/transaction-video-001.md' }
                ]
              }
            ]
          },
          {
            text: '微服务',
            children: [
              { text: 'SpringBoot', link: '/md/microservices/springboot/default.md' },
              { text: 'SpringCloudAlibaba', link: '/md/microservices/springcloudalibaba/2022-04-02-SpringCloudAlibaba专栏开篇.md' }
            ]
          },
          {
            text: '🔥项目实战',
            children: [
              {
                text: '🔥AI大模型项目',
                children: [
                  { text: '一站式AI智能平台', link: '/md/project/ai/one/start/2026-01-28-start.md' },
                  { text: 'AI智能客服系统', link: '/md/project/ai/kefu/start/2026-01-23-start.md' },
                  { text: 'AI智能问答系统', link: '/md/project/ai/qa/start/2025-01-14-start.md' },
                  { text: '实战AI大模型', link: '/md/project/ai/dk/v1/start/2025-10-25-start.md' }
                ]
              },
              {
                text: '中间件项目',
                children: [
                  { text: '手写高性能Redis组件', link: '/md/project/redis-plugin/start/2025-10-20-start.md' },
                  { text: '手写高性能脱敏组件', link: '/md/project/sensitive/start/2025-09-08-start.md' },
                  { text: '手写线程池项目', link: '/md/project/threadpool/start/2025-08-26-start.md' },
                  { text: '手写高性能SQL引擎', link: '/md/project/sql/start/2025-08-12-start.md' },
                  { text: '手写高性能Polaris网关', link: '/md/project/gateway/start/2024-05-19-start.md' },
                  { text: '手写高性能RPC项目', link: '/md/middleware/rpc/2022-08-24-我设计了一款TPS百万级别的RPC框架.md' }
                ]
              },
              {
                text: '高并发项目',
                children: [
                  { text: '分布式IM即时通讯系统（新）', link: '/md/project/im/start/2023-11-20-start.md' },
                  { text: '分布式Seckill秒杀系统', link: '/md/project/seckill/2023-04-16-《Seckill秒杀系统》开篇-我要手把手教你搭建一个抗瞬时百万流量的秒杀系统.md' },
                  { text: '实战高并发设计模式', link: '/md/core/design/concurrent/2023-09-17-start.md' }
                ]
              },
              {
                text: '微服务项目',
                children: [
                  { text: '简易电商脚手架项目', link: '/md/microservices/springcloudalibaba/2022-04-02-SpringCloudAlibaba专栏开篇.md' }
                ]
              },
              {
                text: '手撕源码',
                children: [
                  { text: '手撕Spring6源码', link: '/md/frame/spring/ioc/2022-12-02-《Spring核心技术》开篇-我要带你一步步调试Spring6.0源码啦.md' }
                ]
              }
            ]
          },
          { text: '🌍知识星球', link: '/md/zsxq/introduce.md' },
          {
            text: '📚书籍',
            children: [
              {
                text: '总览',
                children: [
                  { text: '《书籍汇总》', link: '/md/knowledge/all/2023-03-26-书籍汇总.md' }
                ]
              },
              {
                text: '出版图书',
                children: [
                  { text: '《深入理解高并发编程：核心原理与案例实战》', link: '/md/knowledge/book/2022-06-17-深入理解高并发编程.md' },
                  { text: '《深入理解高并发编程：JDK核心技术》', link: '/md/knowledge/book/2023-02-27-深入理解高并发编程-JDK核心技术.md' },
                  { text: '《深入高平行開發：深度原理&專案實戰》', link: '/md/knowledge/book/2023-02-03-深入高平行開發.md' },
                  { text: '《深入理解分布式事务：原理与实战》', link: '/md/knowledge/book/2022-03-29-深入理解分布式事务.md' },
                  { text: '《MySQL技术大全：开发、优化与运维实战》', link: '/md/knowledge/book/2022-03-29-MySQL技术大全.md' },
                  { text: '《海量数据处理与大数据技术实战》', link: '/md/knowledge/book/2022-03-29-海量数据处理与大数据技术实战.md' }
                ]
              },
              {
                text: '电子书籍',
                children: [
                  { text: '《实战高并发设计模式》', link: '/md/knowledge/pdf/2023-11-27-concurrent-design-mode.md' },
                  { text: '《深入理解高并发编程(第2版)》', link: '/md/knowledge/pdf/2022-10-31《深入理解高并发编程（第2版）》打包发布.md' },
                  { text: '《深入理解高并发编程(第1版)》', link: '/md/knowledge/pdf/2022-07-25-深入理解高并发编程-第1版.md' },
                  { text: '《从零开始手写RPC框架(基础篇)》', link: '/md/knowledge/pdf/2022-12-05-《从零开始手写RPC框架》电子书发布.md' },
                  { text: '《SpringCloud Alibaba实战》', link: '/md/knowledge/pdf/2022-07-25-十大篇章-共26个章节-332页-打包发布.md' },
                  { text: '《冰河的渗透实战笔记》', link: '/md/knowledge/pdf/2022-03-30-《冰河的渗透实战笔记》电子书，442页，37万字，正式发布.md' },
                  { text: '《MySQL核心知识手册》', link: '/md/knowledge/pdf/2022-11-14-《MySQL核心知识手册》-打包发布.md' },
                  { text: '《Spring IOC核心技术》', link: '/md/knowledge/pdf/2023-01-28-《Spring IOC核心技术》共27章-19万字-打包发布.md' }
                ]
              }
            ]
          },
          {
            text: '关于',
            children: [
              { text: '关于自己', link: '/md/about/me/about-me.md' },
              { text: '关于学习', link: '/md/about/study/default.md' },
              { text: '关于职场', link: '/md/about/job/default.md' }
            ]
          },
          { text: 'B站', link: 'https://space.bilibili.com/517638832' },
          { text: 'Github', link: 'https://github.com/binghe001/BingheGuide' }
        ],
        sidebar: {
          '/md/core/java/': s('/md/core/java/', getBarJava()),
          '/md/study/': s('/md/study/', getStudyRoadJava()),
          '/md/core/design/java/': s('/md/core/design/java/', getBarJavaDegign()),
          '/md/core/design/concurrent/': s('/md/core/design/concurrent/', getBarConcurrentDegign()),
          '/md/core/mycat/': s('/md/core/mycat/', getBarMycat()),
          '/md/core/docker/': s('/md/core/docker/', getBarDocker()),
          '/md/core/nginx/': s('/md/core/nginx/', getBarNginx()),
          '/md/performance/': s('/md/performance/', getBarPerformance()),
          '/md/concurrent/': s('/md/concurrent/', getBarConcurrent()),
          '/md/frame/spring/': s('/md/frame/spring/', getBarFrameSpring()),
          '/md/distributed/cache/': s('/md/distributed/cache/', getBarDistributedCache()),
          '/md/distributed/zookeeper/': s('/md/distributed/zookeeper/', getBarZookeeper()),
          '/md/distributed/mq/': s('/md/distributed/mq/', getBarMQ()),
          '/md/distributed/netty/': s('/md/distributed/netty/', getBarInternet()),
          '/md/distributed/dubbo/': s('/md/distributed/dubbo/', getBarDistributedDubbo()),
          '/md/distributed/mongodb/': s('/md/distributed/mongodb/', getBarDistributedMongodb()),
          '/md/distributed/es/': s('/md/distributed/es/', getBarDistributedElasticSearch()),
          '/md/microservices/springboot/': s('/md/microservices/springboot/', getBarMicroServices()),
          '/md/microservices/springcloudalibaba/': s('/md/microservices/springcloudalibaba/', getBarMicroServicesAlibaba()),
          '/md/middleware/independent/': s('/md/middleware/independent/', getBarMiddlewareIndependent()),
          '/md/middleware/limiter/': s('/md/middleware/limiter/', getBarMiddlewareLimiter()),
          '/md/middleware/threadpool/': s('/md/middleware/threadpool/', getBarMiddlewareThreadpool()),
          '/md/middleware/bytecode/': s('/md/middleware/bytecode/', getBarMiddlewareByteCode()),
          '/md/middleware/rpc/': s('/md/middleware/rpc/', getBarMiddlewareRPC()),
          '/md/project/gateway/': s('/md/project/gateway/', getBarGateway()),
          '/md/project/sql/': s('/md/project/sql/', getBarSql()),
          '/md/project/threadpool/': s('/md/project/threadpool/', getBarThreadPool()),
          '/md/project/sensitive/': s('/md/project/sensitive/', getBarSensitive()),
          '/md/project/redis-plugin/': s('/md/project/redis-plugin/', getBarRedisPlugin()),
          '/md/project/ai/dk/v1/': s('/md/project/ai/dk/v1/', getBarAiDeepSeekV1()),
          '/md/project/ai/qa/': s('/md/project/ai/qa/', getBarAiQaSystem()),
          '/md/project/ai/kefu/': s('/md/project/ai/kefu/', getBarAiKeSystem()),
          '/md/project/ai/one/': s('/md/project/ai/one/', getBarAiOneSystem()),
          '/md/distributed/transaction/': s('/md/distributed/transaction/', getBarDistributedTransaction()),
          '/md/project/seckill/': s('/md/project/seckill/', getBarPeojectSeckill()),
          '/md/project/im/': s('/md/project/im/', getBarPeojectIM()),
          '/md/hack/': s('/md/hack/', getBarHack()),
          '/md/interview/': s('/md/interview/', getInterview()),
          '/md/knowledge/book/': s('/md/knowledge/book/', getBarPDFPublish()),
          '/md/knowledge/all/': s('/md/knowledge/all/', getBarBookAll()),
          '/md/knowledge/pdf/': s('/md/knowledge/pdf/', getBarPDFSink()),
          '/md/about/': s('/md/about/', getBarAbout()),
          '/md/core/spring/ioc/': s('/md/core/spring/ioc/', getBarSpringIoc()),
          '/md/core/spring/aop/': s('/md/core/spring/aop/', getBarSpringAop()),
          '/md/core/mysql/base/': s('/md/core/mysql/base/', getMySQLBase()),
          '/md/core/jvm/': s('/md/core/jvm/', getBarCoreJVM()),
          '/md/zsxq/': s('/md/zsxq/', getStarBall()),
          '/md/all/': s('/md/all/', getBarAll()),
        }
      }
    }
  }),
  plugins: [
    mediumZoomPlugin({
      selector: 'img:not(.nozoom)',
      options: {
        margin: 16
      }
    })
  ]
})

'''

# Write the config.ts
output_path = 'D:/workspaces/binghe001/BingheGuide/docs/.vuepress/config.ts'
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(config_header)
    f.write('\n')
    f.write(sidebar_funcs)

print(f"config.ts written to {output_path}")
print(f"Total lines: {len(config_header.split(chr(10))) + len(sidebar_funcs.split(chr(10)))}")
