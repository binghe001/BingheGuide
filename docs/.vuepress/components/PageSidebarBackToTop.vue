<template>
  <transition name="fade">
    <svg
      v-if="show"
      class="go-to-top"
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 49.484 28.284"
      @click="scrollToTop"
    >
      <g transform="translate(-229 -126.358)">
        <rect fill="currentColor" width="35" height="5" rx="2" transform="translate(229 151.107) rotate(-45)" />
        <rect fill="currentColor" width="35" height="5" rx="2" transform="translate(274.949 154.642) rotate(-135)" />
      </g>
    </svg>
  </transition>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const show = ref(false)
const threshold = 300

function getScrollTop() {
  return window.pageYOffset || document.documentElement.scrollTop || document.body.scrollTop || 0
}

function scrollToTop() {
  window.scrollTo({ top: 0, behavior: 'smooth' })
  show.value = false
}

onMounted(() => {
  show.value = getScrollTop() > threshold
  window.addEventListener('scroll', () => {
    show.value = getScrollTop() > threshold
  })
})
</script>
