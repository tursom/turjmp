<script setup lang="ts">
import { computed, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useAppStore } from '@/stores/app'
import AppSidebar from './AppSidebar.vue'
import AppHeader from './AppHeader.vue'

const route = useRoute()
const appStore = useAppStore()

const isCollapse = computed(() => appStore.sidebarCollapse)

const activeMenu = computed(() => {
  const path = route.path
  if (path.startsWith('/dashboard')) return '/dashboard'
  if (path.startsWith('/assets')) return '/assets'
  if (path.startsWith('/users')) return '/users'
  if (path.startsWith('/roles')) return '/roles'
  if (path.startsWith('/permissions')) return '/permissions'
  if (path.startsWith('/sessions')) return '/sessions'
  if (path.startsWith('/audit-logs')) return '/audit-logs'
  if (path.startsWith('/settings')) return '/settings'
  return path
})

function toggleCollapse() {
  appStore.toggleSidebar()
}

function currentPageTitle(): string | undefined {
  return route.meta?.title as string | undefined
}

onMounted(() => {
  appStore.loadBranding(currentPageTitle())
})

watch(
  () => route.meta?.title as string | undefined,
  (title) => {
    appStore.loadBranding(title)
  },
)
</script>

<template>
  <el-container class="app-layout">
    <el-aside :width="isCollapse ? '64px' : '220px'" class="app-aside">
      <div class="logo">
        <img src="/favicon.svg" class="logo-img" alt="Turjmp 标志" />
        <span v-show="!isCollapse" class="logo-text">{{ appStore.siteName }}</span>
      </div>
      <AppSidebar :collapse="isCollapse" :active-menu="activeMenu" />
    </el-aside>
    <el-container>
      <el-header class="app-header">
        <AppHeader :collapse="isCollapse" @toggle-collapse="toggleCollapse" />
      </el-header>
      <el-main class="app-main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>
