import { defineClientConfig } from 'vuepress/client'
import { useRouter } from 'vue-router'
import LockArticle from './components/LockArticle.vue'
import PayArticle from './components/PayArticle.vue'
import RedirectArticle from './components/RedirectArticle.vue'
import PageSidebar from './components/PageSidebar.vue'

export default defineClientConfig({
  rootComponents: [LockArticle, PayArticle, RedirectArticle, PageSidebar],
  setup() {
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
