# VuePress 1 -> VuePress 2 升级计划

## 项目概况

**当前版本**: VuePress 1.8.2
**目标版本**: VuePress 2.0+
**项目名称**: BingheGuide (冰河技术)
**项目类型**: 技术文档站

## 一、项目结构分析

### 1.1 目录结构
```
BingheGuide/
├── package.json                    # 依赖配置
├── docs/
│   └── .vuepress/
│       ├── config.js              # VuePress 配置文件
│       ├── enhanceApp.js          # 应用增强脚本
│       ├── components/            # 自定义组件
│       │   ├── LockArticle.vue
│       │   ├── PayArticle.vue
│       │   └── RedirectArticle.vue
│       ├── styles/                # 样式文件
│       │   ├── index.styl
│       │   └── palette.styl
│       └── public/                # 静态资源
└── .github/                       # GitHub 配置
```

### 1.2 技术栈
- **核心**: VuePress 1.8.2, Vue 2.x
- **样式**: Stylus
- **Markdown**: 支持行号、外部链接
- **插件**: 多个 VuePress 插件
- **构建工具**: Webpack 4.x (VuePress 1 内置)

---

## 二、依赖与插件分析

### 2.1 当前依赖列表

#### 核心依赖
```json
{
  "vuepress": "^1.8.2",
  "@vuepress/core": "^1.8.2"
}
```

#### 官方插件
```json
{
  "@vuepress/plugin-back-to-top": "^1.8.2",
  "@vuepress/plugin-google-analytics": "^1.8.2",
  "@vuepress/plugin-medium-zoom": "^1.8.2"
}
```

#### 第三方插件
```json
{
  "vuepress-plugin-seo": "^0.1.4",
  "vuepress-plugin-sitemap": "^2.3.1",
  "vuepress-plugin-tags": "^1.0.2",
  "vuepress-plugin-baidu-autopush": "^1.0.1",
  "vuepress-plugin-code-copy": "^1.0.6",
  "vuepress-plugin-copyright": "^1.0.2",
  "vuepress-plugin-img-lazy": "^1.0.4",
  "vuepress-plugin-table-of-contents": "^1.1.7"
}
```

#### 评论插件 (已注释)
```json
{
  "@vssue/api-github-v3": "^1.4.7",
  "@vssue/vuepress-plugin-vssue": "^1.4.8"
}
```

### 2.2 插件兼容性分析

| 插件名称 | VuePress 1 | VuePress 2 | 迁移方案 |
|---------|-----------|-----------|---------|
| vuepress-plugin-seo | ✅ 支持 | ❌ 不支持 | 迁移到 vuepress-plugin-seo2 |
| vuepress-plugin-sitemap | ✅ 支持 | ❌ 不支持 | 使用 vuepress-sitemap2 |
| vuepress-plugin-tags | ✅ 支持 | ❌ 不支持 | 迁移到 @vuepress/plugin-tag |
| vuepress-plugin-baidu-autopush | ✅ 支持 | ❌ 不支持 | 改用 @vuepress/plugin-baidu-autopush2 |
| vuepress-plugin-code-copy | ✅ 支持 | ✅ 内置 | 使用内置 `@vuepress/plugin-copy-code` |
| vuepress-plugin-copyright | ✅ 支持 | ❌ 不支持 | 手动实现或迁移到 @vuepress/plugin-copyright2 |
| vuepress-plugin-img-lazy | ✅ 支持 | ❌ 不支持 | 使用 `v-lazy` 或 vue-lazyload |
| vuepress-plugin-table-of-contents | ✅ 支持 | ❌ 不支持 | 改用 `@vuepress/plugin-reading-time` + 手动实现 |
| @vuepress/plugin-medium-zoom | ✅ 支持 | ✅ 内置 | 使用内置 `@vuepress/plugin-medium-zoom` |
| @vuepress/plugin-back-to-top | ✅ 支持 | ✅ 内置 | 使用内置 `@vuepress/plugin-back-to-top` |
| @vuepress/plugin-google-analytics | ✅ 支持 | ✅ 内置 | 使用内置 `@vuepress/plugin-google-analytics` |

---

## 三、配置文件变更

### 3.1 package.json 变更

#### 3.1.1 依赖更新
```json
{
  "devDependencies": {
    "vuepress": "^2.0.0-beta",
    "@vuepress/core": "^2.0.0-beta",
    "@vuepress/plugin-back-to-top": "^2.0.0-beta",
    "@vuepress/plugin-google-analytics": "^2.0.0-beta",
    "@vuepress/plugin-medium-zoom": "^2.0.0-beta",

    // 以下插件需要迁移到 VuePress 2 版本
    "vuepress-plugin-seo2": "^0.1.5",
    "vuepress-sitemap2": "^3.6.7",
    "@vuepress/plugin-tag": "^1.0.1",
    "@vuepress/plugin-baidu-autopush2": "^1.0.3",
    "@vuepress/plugin-copy-code": "^2.0.0-beta",

    // 图片懒加载 (Vue 2 推荐 vue-lazyload)
    "vue-lazyload": "^1.4.0",

    // 移除不需要的插件
    "vuepress-plugin-seo": "^0.1.4",
    "vuepress-plugin-sitemap": "^2.3.1",
    "vuepress-plugin-tags": "^1.0.2",
    "vuepress-plugin-baidu-autopush": "^1.0.1",
    "vuepress-plugin-code-copy": "^1.0.6",
    "vuepress-plugin-copyright": "^1.0.2",
    "vuepress-plugin-img-lazy": "^1.0.4",
    "vuepress-plugin-table-of-contents": "^1.1.7"
  }
}
```

#### 3.1.2 脚本变更
```json
{
  "scripts": {
    "dev": "vuepress dev docs",
    "build": "vuepress build docs"
  }
}
```

**移除的内容**:
- `export NODE_OPTIONS="--max_old_space_size=6144 --openssl-legacy-provider"`
- VuePress 1 使用 Webpack 4，VuePress 2 使用 Vite，不需要这些 Node 选项

### 3.2 配置文件格式变更 (config.js)

#### 3.2.1 导出方式
**VuePress 1**:
```javascript
module.exports = {
  // 配置内容
}
```

**VuePress 2**:
```javascript
import { defineUserConfig } from 'vuepress'

export default defineUserConfig({
  // 配置内容
})
```

#### 3.2.2 主要配置项变更

| 配置项 | VuePress 1 | VuePress 2 | 说明 |
|-------|-----------|-----------|------|
| port | ✅ 支持 | ✅ 支持 | 端口配置 |
| dest | ✅ 支持 | ✅ 支持 | 构建目标目录 |
| base | ✅ 支持 | ✅ 支持 | 基础路径 |
| chainWebpack | ✅ 支持 | ❌ 不支持 | Vite 中使用 `vite.config.js` |
| markdown | ✅ 支持 | ✅ 支持 | Markdown 配置 |
| locales | ✅ 支持 | ✅ 支持 | 多语言配置 |
| head | ✅ 支持 | ✅ 支持 | HTML head 配置 |
| plugins | ✅ 支持 | ✅ 支持 | 插件配置 |
| themeConfig | ✅ 支持 | ✅ 支持 | 主题配置 |
| enhanceAppFiles | ✅ 支持 | ✅ 支持 | 应用增强文件 |

### 3.3 Vite 配置替代 chainWebpack

**VuePress 1**:
```javascript
chainWebpack: config => {
  if (process.env.NODE_ENV === 'production') {
    const dateTime = new Date().getTime();

    config.output.filename('assets/js/cg-[name].js?v=' + dateTime).end();
    config.output.chunkFilename('assets/js/cg-[name].js?v=' + dateTime).end();

    config.plugin('mini-css-extract-plugin').use(require('mini-css-extract-plugin'), [{
      filename: 'assets/css/[name].css?v=' + dateTime,
      chunkFilename: 'assets/css/[name].css?v=' + dateTime
    }]).end();
  }
}
```

**VuePress 2**:
在 `docs/.vuepress/vite.config.js` 中配置:
```javascript
import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        entryFileNames: 'assets/js/cg-[name].js',
        chunkFileNames: 'assets/js/cg-[name].js',
        assetFileNames: 'assets/css/cg-[name].css'
      }
    }
  },
  plugins: [
    // Vite 插件
  ]
})
```

### 3.4 Markdown 配置变更

**VuePress 1**:
```javascript
markdown: {
  lineNumbers: true,
  externalLinks: {
    target: '_blank',
    rel: 'noopener noreferrer'
  }
}
```

**VuePress 2**:
```javascript
markdown: {
  lineNumbers: true,
  externalLinks: {
    target: '_blank',
    rel: 'noopener noreferrer'
  }
}
```
*注: 格式基本相同，但具体选项名称可能略有差异*

### 3.5 插件配置变更

**VuePress 1**:
```javascript
plugins: [
  ['@vuepress/medium-zoom', {
    selector: 'img:not(.nozoom)',
    options: {
      margin: 16
    }
  }],
  ['vuepress-plugin-baidu-autopush', {}],
  ['vuepress-plugin-code-copy', {
    align: 'bottom',
    color: '#3eaf7c',
    successText: '@冰河: 代码已经复制到剪贴板'
  }],
  ['img-lazy', {}],
  ["vuepress-plugin-tags", {
    type: 'default',
    color: '#42b983',
    border: '1px solid #e2faef',
    backgroundColor: '#f0faf5',
    selector: '.page .content__default h1'
  }],
  ["seo", {
    siteTitle: (_, $site) => $site.title,
    title: $page => $page.title,
    // ...
  }]
]
```

**VuePress 2**:
```javascript
import { mediumZoomPlugin } from '@vuepress/plugin-medium-zoom'
import { baiduAutopushPlugin } from '@vuepress/plugin-baidu-autopush2'
import { copyCodePlugin } from '@vuepress/plugin-copy-code'
import { tagPlugin } from '@vuepress/plugin-tag'
import { seo2Plugin } from 'vuepress-plugin-seo2'
import { sitemap2Plugin } from 'vuepress-sitemap2'
import { lazyPlugin } from 'vue-lazyload/vite'

export default {
  plugins: [
    mediumZoomPlugin({
      selector: 'img:not(.nozoom)',
      options: { margin: 16 }
    }),
    baiduAutopushPlugin({}),
    copyCodePlugin({
      align: 'bottom',
      color: '#3eaf7c',
      successText: '@冰河: 代码已经复制到剪贴板'
    }),
    lazyPlugin({
      // 配置
    }),
    tagPlugin({
      type: 'default',
      color: '#42b983',
      border: '1px solid #e2faef',
      backgroundColor: '#f0faf5',
      selector: '.page .content__default h1'
    }),
    seo2Plugin({
      siteTitle: (_, $site) => $site.title,
      title: $page => $page.title,
      // ...
    }),
    sitemap2Plugin({
      hostname: 'https://binghe.site'
    })
  ]
}
```

---

## 四、组件变更

### 4.1 自定义组件分析

#### 4.1.1 LockArticle.vue
- 使用 `this.$page.frontmatter.lock` 获取文章状态
- 使用 jQuery 操作 DOM (`.theme-default-content`)
- 使用 `window.jQuery` 和全局变量 (`_hmt`)
- 依赖外部资源 (`/js/jquery.min.js`, `/js/global.js`, `/js/fingerprint2.min.js`)

#### 4.1.2 PayArticle.vue
- 使用 `this.$page.frontmatter.pay` 获取支付链接
- 使用 jQuery 操作 DOM
- 逻辑与 LockArticle 类似

#### 4.1.3 RedirectArticle.vue
- 使用 `this.$page.frontmatter.redirectUrl` 获取跳转链接
- 使用 jQuery 操作 DOM

### 4.2 组件迁移方案

**VuePress 2 中的变更**:
1. **this.$page**:
   - VuePress 2 中 `$page` 可能已被移除或改为 `$frontmatter`
   - 需要确认 `$page` 在 Vue 2 中的可用性

2. **this.$themeConfig**:
   - VuePress 2 中获取主题配置的方式可能改变

3. **jQuery 依赖**:
   - VuePress 2 不再内置 jQuery
   - 需要自行引入或使用 Vue 的响应式 API

4. **DOM 操作**:
   - 应改用 Vue 的数据绑定和生命周期钩子

### 4.3 组件重构建议

```javascript
// docs/.vuepress/components/LockArticle.vue
export default {
  name: 'LockArticle',
  data() {
    return {
      isLocked: false,
      articleHeight: 0
    }
  },
  computed: {
    frontmatter() {
      return this.$frontmatter || {}
    },
    isLock() {
      return this.frontmatter.lock === 'need'
    }
  },
  mounted() {
    this._init()
  },
  methods: {
    async _init() {
      // 初始化逻辑
      this.$nextTick(() => {
        this.articleObj = this.getArticleObj()
        this._detect()
      })

      // 定时检查
      setInterval(() => {
        if (this.isLock) {
          this._detect()
        }
      }, 1500)
    },
    getArticleObj() {
      const articleEl = this.$el.querySelector('.theme-default-content')
      if (!articleEl) return null

      return {
        article: articleEl,
        height: articleEl.clientHeight
      }
    },
    _detect() {
      if (!this.articleObj) return

      const res = this.getCookie('_unlock')
      if (res === 'success') return

      this.getToken().then(token => {
        // AJAX 请求逻辑
      })
    },
    getToken() {
      // 获取 token 逻辑
    },
    // ... 其他方法
  }
}
```

---

## 五、样式文件变更

### 5.1 Stylus 支持
VuePress 2 **仍然支持 Stylus**，无需修改样式文件语法。

### 5.2 全局样式注意事项
- VuePress 2 使用 CSS Variables
- 颜色变量命名可能有所变化
- 某些 class 名称可能改变

---

## 六、应用增强脚本

### 6.1 当前代码
```javascript
// docs/.vuepress/enhanceApp.js
export default ({router}) => {
  router.beforeEach((to, from, next) => {
    if (typeof _hmt != "undefined") {
      if (to.path) {
        _hmt.push(["_trackPageview", to.fullPath]);
      }
    }
    next();
  });
}
```

### 6.2 迁移方案
VuePress 2 中的 `enhanceApp` 函数签名相同，但需要注意:
1. `router` 在 VuePress 2 中仍然是可用的
2. 百度统计的调用方式不变
3. 全局变量 `window._hmt` 仍然可用

---

## 七、主题配置变更

### 7.1 主题配置
VuePress 2 使用的主题可能与 VuePress 1 不同:
- 默认主题可能已升级
- 需要检查主题兼容性

### 7.2 GitHub 编辑链接
```javascript
themeConfig: {
  docsRepo: "binghe001/BingheGuide",
  docsDir: 'docs',
  docsBranch: 'master',
  editLinks: true,
  // ... 其他配置
}
```
*注: 这些配置在 VuePress 2 中仍然有效*

---

## 八、迁移步骤

### 第一阶段：准备与备份 (1天)
1. ✅ 创建备份分支: `git checkout -b backup/vuepress2-upgrade`
2. ✅ 备份现有 `docs/.vuepress` 目录
3. ✅ 记录当前所有插件配置和自定义组件
4. ✅ 记录自定义样式和全局脚本

### 第二阶段：依赖升级 (1天)
1. ✅ 更新 `package.json` 中的 VuePress 1 依赖到 VuePress 2
2. ✅ 安装 VuePress 2 及其兼容插件
3. ✅ 卸载 VuePress 1 插件
4. ✅ 更新构建脚本，移除 `NODE_OPTIONS`

### 第三阶段：配置文件迁移 (2天)
1. ✅ 将 `config.js` 迁移为使用 `defineUserConfig`
2. ✅ 更新插件配置到 VuePress 2 版本
3. ✅ 创建 `vite.config.js` 替代 `chainWebpack`
4. ✅ 更新 Markdown 配置
5. ✅ 更新主题配置
6. ✅ 更新 head 配置（检查插件脚本兼容性）

### 第四阶段：组件重构 (2天)
1. ✅ 重构 `LockArticle.vue`
2. ✅ 重构 `PayArticle.vue`
3. ✅ 重构 `RedirectArticle.vue`
4. ✅ 移除 jQuery 依赖或使用 Vue 兼容方案
5. ✅ 测试所有自定义组件功能

### 第五阶段：样式调整 (1天)
1. ✅ 检查并修复样式问题
2. ✅ 测试响应式布局
3. ✅ 确保颜色主题正确

### 第六阶段：增强脚本调整 (0.5天)
1. ✅ 检查 `enhanceApp.js` 在 VuePress 2 中的兼容性
2. ✅ 修复路由钩子问题（如果有）

### 第七阶段：构建测试 (1天)
1. ✅ 运行 `npm run dev` 本地开发
2. ✅ 检查控制台错误
3. ✅ 运行 `npm run build` 构建生产版本
4. ✅ 检查构建输出目录结构
5. ✅ 验证所有页面正确渲染
6. ✅ 测试自定义组件功能
7. ✅ 验证 SEO 插件功能

### 第八阶段：CI/CD 配置调整 (0.5天)
1. ✅ 更新 GitHub Actions 或 CI 配置
2. ✅ 更新代码云 CI 配置
3. ✅ 测试部署流程

### 第九阶段：内容验证 (1天)
1. ✅ 验证所有文章能正常访问
2. ✅ 验证侧边栏导航正确
3. ✅ 验证搜索功能（如果使用）
4. ✅ 验证评论功能（如果启用）
5. ✅ 验证百度统计和百度推送
6. ✅ 验证 Google Analytics（如果使用）

### 第十阶段：优化与清理 (0.5天)
1. ✅ 清理不必要的代码和注释
2. ✅ 更新文档说明
3. ✅ 提交更改并创建 Pull Request

---

## 九、插件迁移详细方案

### 9.1 SEO 插件
**源插件**: `vuepress-plugin-seo`
**目标插件**: `vuepress-plugin-seo2`

```javascript
// VuePress 2 配置
import { defineUserConfig } from 'vuepress'
import { seo2Plugin } from 'vuepress-plugin-seo2'

export default defineUserConfig({
  plugins: [
    seo2Plugin({
      siteTitle: (_, $site) => $site.title,
      title: $page => $page.title,
      description: $page => $page.frontmatter.description,
      author: (_, $site) => $site.themeConfig.author,
      tags: $page => $page.frontmatter.tags,
      type: $page => 'article',
      url: (_, $site, path) => ($site.themeConfig.domain || '') + path,
      image: ($page, $site) => $page.frontmatter.image && (($site.themeConfig.domain && !$page.frontmatter.image.startsWith('http') || '') + $page.frontmatter.image),
      publishedAt: $page => $page.frontmatter.date && new Date($page.frontmatter.date),
      modifiedAt: $page => $page.lastUpdated && new Date($page.lastUpdated),
    })
  ]
})
```

### 9.2 Sitemap 插件
**源插件**: `vuepress-plugin-sitemap`
**目标插件**: `vuepress-sitemap2`

```javascript
import { defineUserConfig } from 'vuepress'
import { sitemap2Plugin } from 'vuepress-sitemap2'

export default defineUserConfig({
  plugins: [
    sitemap2Plugin({
      hostname: 'https://binghe.site'
    })
  ]
})
```

### 9.3 标签插件
**源插件**: `vuepress-plugin-tags`
**目标插件**: `@vuepress/plugin-tag`

```javascript
import { defineUserConfig } from 'vuepress'
import { tagPlugin } from '@vuepress/plugin-tag'

export default defineUserConfig({
  plugins: [
    tagPlugin({
      type: 'default',
      color: '#42b983',
      border: '1px solid #e2faef',
      backgroundColor: '#f0faf5',
      selector: '.page .content__default h1'
    })
  ]
})
```

### 9.4 百度推送插件
**源插件**: `vuepress-plugin-baidu-autopush`
**目标插件**: `@vuepress/plugin-baidu-autopush2`

```javascript
import { defineUserConfig } from 'vuepress'
import { baiduAutopushPlugin } from '@vuepress/plugin-baidu-autopush2'

export default defineUserConfig({
  plugins: [
    baiduAutopushPlugin({})
  ]
})
```

### 9.5 代码复制插件
**源插件**: `vuepress-plugin-code-copy`
**目标插件**: `@vuepress/plugin-copy-code` (内置)

```javascript
import { defineUserConfig } from 'vuepress'
import { copyCodePlugin } from '@vuepress/plugin-copy-code'

export default defineUserConfig({
  plugins: [
    copyCodePlugin({
      align: 'bottom',
      color: '#3eaf7c',
      successText: '@冰河: 代码已经复制到剪贴板'
    })
  ]
})
```

### 9.6 图片懒加载
**源插件**: `vuepress-plugin-img-lazy`
**目标方案**: `vue-lazyload`

```javascript
import { defineUserConfig } from 'vuepress'
import { lazyPlugin } from 'vue-lazyload/vite'

export default defineUserConfig({
  plugins: [
    lazyPlugin({
      lazyComponent: true,
      // 其他配置
    })
  ]
})
```

---

## 十、潜在风险与解决方案

### 10.1 插件兼容性问题
**风险**: 某些第三方插件可能不完全兼容 VuePress 2
**解决方案**:
1. 优先使用官方或社区维护的 VuePress 2 兼容版本
2. 对于不兼容的插件，手动实现功能或寻找替代品
3. 保持 VuePress 1 版本作为备份

### 10.2 自定义组件功能丢失
**风险**: 重构组件时可能丢失某些功能
**解决方案**:
1. 充分测试每个组件的原始功能
2. 保留完整的测试用例
3. 逐步迁移，每迁移一个组件就进行测试

### 10.3 样式冲突
**风险**: 样式可能因为 VuePress 2 的变化而失效
**解决方案**:
1. 使用 CSS Modules 或 Scoped CSS
2. 仔细检查 VuePress 2 的 CSS Variables
3. 使用开发者工具逐步调试

### 10.4 SEO 功能问题
**风险**: SEO 插件配置错误可能影响网站收录
**解决方案**:
1. 在本地充分测试 SEO 插件功能
2. 验证生成的 HTML 标签是否正确
3. 使用工具检查 SEO 配置

### 10.5 评论功能
**风险**: Vssue 插件可能需要重新配置
**解决方案**:
1. 取消注释 Vssue 配置
2. 确认 GitHub App 配置正确
3. 测试评论功能

---

## 十一、测试计划

### 11.1 单元测试
- ✅ 测试自定义组件渲染
- ✅ 测试组件逻辑功能
- ✅ 测试插件配置

### 11.2 集成测试
- ✅ 测试页面构建
- ✅ 测试路由跳转
- ✅ 测试搜索功能
- ✅ 测试侧边栏导航

### 11.3 功能测试
- ✅ 测试所有自定义组件
- ✅ 测试 SEO 功能
- ✅ 测试统计功能（百度、Google）
- ✅ 测试评论功能
- ✅ 测试代码复制功能
- ✅ 测试图片懒加载

### 11.4 性能测试
- ✅ 构建时间对比
- ✅ 页面加载速度
- ✅ 资源优化情况

---

## 十二、回滚方案

如果升级后出现问题，可以快速回滚：

### 12.1 回滚步骤
1. 恢复备份的 `.vuepress` 目录
2. 恢复 `package.json` 中的依赖
3. 恢复 `config.js` 为 VuePress 1 版本
4. 恢复自定义组件为 VuePress 1 版本

### 12.2 Git 回滚命令
```bash
# 回滚到备份分支
git checkout backup/vuepress2-upgrade

# 或者回滚到 VuePress 1 版本
git checkout master-old
```

---

## 十三、迁移检查清单

### 13.1 依赖检查
- [ ] VuePress 1 依赖已移除
- [ ] VuePress 2 依赖已安装
- [ ] 所有插件已迁移到 VuePress 2 版本
- [ ] 构建脚本已更新

### 13.2 配置检查
- [ ] config.js 使用 defineUserConfig
- [ ] 插件配置正确
- [ ] Markdown 配置正确
- [ ] 主题配置正确
- [ ] Vite 配置已创建
- [ ] 环境变量配置正确

### 13.3 组件检查
- [ ] 所有自定义组件已迁移
- [ ] 组件逻辑功能正常
- [ ] 样式正确显示
- [ ] 响应式布局正常

### 13.4 构建检查
- [ ] 开发服务器能正常启动
- [ ] 生产构建成功
- [ ] 构建产物目录结构正确
- [ ] 资源文件正确生成

### 13.5 功能检查
- [ ] 页面能正常访问
- [ ] 侧边栏导航正常
- [ ] 搜索功能正常
- [ ] 代码复制功能正常
- [ ] 图片懒加载正常
- [ ] 百度统计正常
- [ ] Google Analytics 正常
- [ ] 评论功能正常
- [ ] SEO 功能正常

---

## 十四、预计时间

| 阶段 | 预计时间 | 实际时间 | 状态 |
|------|---------|---------|------|
| 准备与备份 | 1天 | - | ⬜ |
| 依赖升级 | 1天 | - | ⬜ |
| 配置文件迁移 | 2天 | - | ⬜ |
| 组件重构 | 2天 | - | ⬜ |
| 样式调整 | 1天 | - | ⬜ |
| 增强脚本调整 | 0.5天 | - | ⬜ |
| 构建测试 | 1天 | - | ⬜ |
| CI/CD 配置调整 | 0.5天 | - | ⬜ |
| 内容验证 | 1天 | - | ⬜ |
| 优化与清理 | 0.5天 | - | ⬜ |
| **总计** | **10天** | - | ⬜ |

---

## 十五、参考资料

### VuePress 2 官方文档
- [VuePress 2.0 迁移指南](https://v2.vuepress.vuejs.org/guide/migration.html)
- [VuePress 2 配置选项](https://v2.vuepress.vuejs.org/config/)
- [VuePress 2 插件开发](https://v2.vuepress.vuejs.org/plugin/)

### VuePress 1 到 2 迁移资源
- [VuePress 2 Beta 发布说明](https://v2.vuepress.vuejs.org/guide/release-notes.html)
- [VuePress 1 到 2 迁移指南](https://v2.vuepress.vuejs.org/guide/migration.html)
- [VuePress 2 社区插件列表](https://v2.vuepress.vuejs.org/plugin/official/)

### 插件迁移资源
- [vuepress-plugin-seo2](https://github.com/hypuer/vuepress-plugin-seo2)
- [vuepress-sitemap2](https://github.com/ekoeryanto/vuepress-sitemap2)
- [@vuepress/plugin-tag](https://github.com/vuepress/plugin-components)
- [@vuepress/plugin-baidu-autopush2](https://github.com/BugZzz/vuepress-plugin-baidu-autopush2)

---

## 十六、注意事项

1. **备份数据**: 在开始迁移前，务必完整备份项目
2. **测试环境**: 在本地充分测试后再部署到生产环境
3. **逐步迁移**: 建议先在一个小型分支上测试，确认无误后再合并
4. **监控错误**: 升级后密切关注控制台错误和构建错误
5. **保留备份**: 保持 VuePress 1 版本作为备份，以便快速回滚
6. **更新文档**: 更新项目文档说明升级内容

---

**文档创建时间**: 2026-04-28
**文档版本**: 1.0
**文档作者**: Claude
