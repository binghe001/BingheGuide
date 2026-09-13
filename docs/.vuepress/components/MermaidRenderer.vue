<template>
  <div class="mermaid-container">
    <component :is="dynamicComponent" v-if="rendered" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import mermaid from 'mermaid'

const code = ref('')
const dynamicComponent = ref<any>(null)
const rendered = ref(false)

onMounted(async () => {
  try {
    // 从 data-mermaid-code 属性读取代码
    const mermaidCode = (document.currentScript as any)?.getAttribute('data-mermaid-code')
    if (mermaidCode) {
      code.value = decodeURIComponent(mermaidCode)
    }

    // 初始化 mermaid
    await mermaid.initialize({
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

    // 渲染 mermaid
    const { svg } = await mermaid.render('mermaid-' + Date.now(), code.value)
    dynamicComponent.value = {
      __v_isSuspense: true,
      __v_isDynamicComponent: true,
      render: () => ({
        tag: 'div',
        props: {},
        children: [svg],
      }),
    }
    rendered.value = true
  } catch (error) {
    console.error('Mermaid 渲染失败:', error)
  }
})
</script>

<style scoped>
.mermaid-container {
  overflow-x: auto;
  padding: 1rem 0;
}

.mermaid-container :deep(svg) {
  max-width: 100%;
  height: auto;
}
</style>
