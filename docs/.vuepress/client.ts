import { defineClientConfig } from 'vuepress/client'
import { useRouter } from 'vue-router'
import LockArticle from './components/LockArticle.vue'
import PayArticle from './components/PayArticle.vue'
import RedirectArticle from './components/RedirectArticle.vue'
import PageSidebar from './components/PageSidebar.vue'
import mermaid from 'mermaid'

export default defineClientConfig({
  rootComponents: [LockArticle, PayArticle, RedirectArticle, PageSidebar],
  setup() {
    // Initialize mermaid on client-side
    mermaid.initialize({
      startOnLoad: false,
      theme: 'default',
      securityLevel: 'loose',
      themeVariables: {
        primaryColor: '#f0f9ff',
        primaryTextColor: '#0c4a6e',
        primaryBorderColor: '#0284c7',
        lineColor: '#334155',
        secondaryColor: '#f1f5f9',
        tertiaryColor: '#e2e8f0',
      },
    })

    // Render all mermaid elements on page load
    const renderMermaid = async () => {
      try {
        const mermaidElements = document.querySelectorAll('.mermaid[data-code]')
        for (const el of Array.from(mermaidElements)) {
          const code = el.getAttribute('data-code')
          const id = el.getAttribute('data-id')
          if (code && id) {
            const decodedCode = decodeURIComponent(code)
            const { svg } = await mermaid.render(id, decodedCode)
            el.outerHTML = svg
          }
        }
      } catch (error) {
        console.error('Mermaid 渲染失败:', error)
      }
    }

    // Run on route change to ensure all mermaid elements are rendered
    if (typeof window !== 'undefined') {
      const router = useRouter()
      router.afterEach(() => {
        renderMermaid()
      })

      // Also run once on mount
      renderMermaid()
    }

    if (typeof window !== 'undefined') {
      const router = useRouter()
      router.beforeEach((to, from, next) => {
        if (typeof (window as any)._hmt !== 'undefined') {
          if (to.path) {
            (window as any)._hmt.push(['_trackPageview', to.fullPath])
          }
        }
        next()
      })
    }
  }
})
