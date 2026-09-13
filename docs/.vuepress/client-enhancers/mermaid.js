// Mermaid 渲染脚本
import mermaid from 'mermaid'

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

// 页面加载完成后渲染所有 Mermaid 元素
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const mermaidElements = document.querySelectorAll('.mermaid[data-mermaid-code]')

    for (const el of Array.from(mermaidElements)) {
      const code = el.getAttribute('data-mermaid-code')
      if (code) {
        const decodedCode = decodeURIComponent(code)

        // 渲染 mermaid 并替换元素
        const { svg } = await mermaid.render('mermaid-' + Math.random().toString(36).substr(2, 9), decodedCode)
        el.outerHTML = svg
      }
    }
  } catch (error) {
    console.error('Mermaid 渲染失败:', error)
  }
})
