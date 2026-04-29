<template>
  <ClientOnly>
    <aside class="page-sidebar">
      <div class="page-side-toolbar">

        <!-- Fixed TOC (wide screens): positioned to the left of the toolbar -->
        <div v-if="headers.length > 0" class="option-box-toc-fixed">
          <div class="toc-container-sidebar">
            <div class="pos-box">
              <div class="scroll-box" style="max-height:650px">
                <div style="font-weight:bold;text-align:center;">{{ pageTitle }}</div>
                <hr/>
                <div class="toc-box">
                  <ul class="toc-sidebar-links">
                    <li v-for="h in headers" :key="h.slug">
                      <a :href="'#' + h.slug" class="toc-sidebar-link">{{ h.title }}</a>
                      <ul v-if="h.children && h.children.length" class="toc-sidebar-sub-headers">
                        <li v-for="sub in h.children" :key="sub.slug">
                          <a :href="'#' + sub.slug" class="toc-sidebar-link">{{ sub.title }}</a>
                        </li>
                      </ul>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- TOC hover button (medium screens, shown via CSS media query) -->
        <div v-if="headers.length > 0" class="option-box-toc-over">
          <img src="/images/system/toc.png" class="nozoom" />
          <span class="show-txt">目录</span>
          <div class="toc-container">
            <div class="pos-box">
              <div class="scroll-box" style="max-height:550px">
                <div style="font-weight:bold;text-align:center;">{{ pageTitle }}</div>
                <hr/>
                <div class="toc-box">
                  <ul class="toc-sidebar-links">
                    <li v-for="h in headers" :key="h.slug">
                      <a :href="'#' + h.slug" class="toc-sidebar-link">{{ h.title }}</a>
                      <ul v-if="h.children && h.children.length" class="toc-sidebar-sub-headers">
                        <li v-for="sub in h.children" :key="sub.slug">
                          <a :href="'#' + sub.slug" class="toc-sidebar-link">{{ sub.title }}</a>
                        </li>
                      </ul>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Mobile QR code -->
        <div class="option-box">
          <img src="/images/system/wechat.png" class="nozoom" />
          <span class="show-txt">手机看</span>
          <div class="toc-container">
            <div class="pos-box">
              <div class="scroll-box" style="text-align:center">
                <span style="font-size:0.9rem">微信扫一扫</span>
                <img :src="'https://api.qrserver.com/v1/create-qr-code/?data=https://binghe.site' + route.fullPath" height="180px" style="margin:10px;" class="nozoom" />
                可以<b>手机看</b>或分享至<b>朋友圈</b>
              </div>
            </div>
          </div>
        </div>

        <!-- Toggle left sidebar -->
        <div class="option-box" @click="toggleSidebar">
          <img src="/images/system/toggle.png" width="30px" class="nozoom" />
          <span class="show-txt">左栏</span>
        </div>

        <!-- Knowledge planet -->
        <div class="option-box">
          <img class="nozoom" src="/images/system/xingqiu.png" width="25px" />
          <span class="show-txt">星球</span>
          <div class="toc-container">
            <div class="pos-box">
              <div class="scroll-box" style="text-align:center">
                <span style="font-size:0.8rem;font-weight:bold;">实战项目<span style="font-size:8px;color:red;">「SpringCloud Alibaba实战项目」</span>、专属电子书、问题解答、简历指导、技术分享、晋升指导、视频课程</span>
                <img height="180px" src="/images/personal/xingqiu.png" style="margin:10px;" class="nozoom" />
                <b>知识星球</b>：冰河技术
              </div>
            </div>
          </div>
        </div>

        <!-- Reader group -->
        <div class="option-box">
          <img class="nozoom" src="/images/system/wexin4.png" width="25px" />
          <span class="show-txt">读者群</span>
          <div class="toc-container">
            <div class="pos-box">
              <div class="scroll-box" style="text-align:center">
                <span style="font-size:0.8rem;font-weight:bold;">添加冰河微信<span style="color:red;">(hacker_binghe)</span>进冰河技术学习交流圈「无任何套路」</span>
                <img src="/images/personal/hacker_binghe.jpg" height="180px" style="margin:10px;" class="nozoom" />
                PS：添加时请备注<b>读者加群</b>，谢谢！
              </div>
            </div>
          </div>
        </div>

        <!-- Download resources -->
        <div class="option-box">
          <img class="nozoom" src="/images/system/download-2.png" width="25px" />
          <span class="show-txt">下资料</span>
          <div class="toc-container">
            <div class="pos-box">
              <div class="scroll-box" style="text-align:center">
                <span style="font-size:0.8rem;font-weight:bold;">扫描公众号，回复<span style="color:red;">"1024"</span>下载<span style="color:red;">100GB+</span>学习技术资料、PDF书籍、实战项目、简历模板等「无任何套路」</span>
                <img src="/images/personal/qrcode.png" height="180px" style="margin:10px;" class="nozoom" />
                <b>公众号:</b> 冰河技术
              </div>
            </div>
          </div>
        </div>

        <!-- Appreciation -->
        <div class="option-box">
          <img class="nozoom" src="/images/system/heart-1.png" width="25px" />
          <span class="show-txt">赞赏我</span>
          <div class="toc-container">
            <div class="pos-box">
              <div class="scroll-box" style="text-align:center">
                <span style="font-size:0.8rem;font-weight:bold;">鼓励/支持/赞赏我</span>
                <img height="180px" src="/images/personal/encourage-head.png" style="margin:5px;" class="nozoom" />
                <br>1. 不靠它生存但仍希望得到你的鼓励；
                <br>2. 时刻警醒自己保持技术人的初心；
              </div>
            </div>
          </div>
        </div>

        <!-- Previous page -->
        <div v-if="prevLink" class="option-box" style="padding-left:2px;text-align:center;" :title="prevLink.text">
          <router-link :to="prevLink.link">
            <img src="/images/system/pre2.png" width="30px" class="nozoom" />
            <span class="show-txt">上一篇</span>
          </router-link>
        </div>

        <!-- Next page -->
        <div v-if="nextLink" class="option-box" style="padding-left:2px;text-align:center;" :title="nextLink.text">
          <router-link :to="nextLink.link">
            <img src="/images/system/next2.png" width="30px" class="nozoom" />
            <span class="show-txt">下一篇</span>
          </router-link>
        </div>

      </div>

      <PageSidebarBackToTop />
    </aside>
  </ClientOnly>
</template>

<script setup>
import { computed } from 'vue'
import { usePageData } from 'vuepress/client'
import { useRoute } from 'vue-router'
import { useRelatedLinks } from '@vuepress/theme-default/client'
import PageSidebarBackToTop from './PageSidebarBackToTop.vue'

const page = usePageData()
const route = useRoute()
const { prevLink, nextLink } = useRelatedLinks()

const pageTitle = computed(() => page.value.title)
const headers = computed(() => page.value.headers || [])

function toggleSidebar() {
  document.documentElement.classList.toggle('sidebar-force-hidden')
}
</script>
