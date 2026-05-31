<script setup lang="ts">
import { Monitor, User, Setting, Lock, Connection, Document, Tools } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'

defineProps<{
  collapse: boolean
  activeMenu: string
}>()

const authStore = useAuthStore()

interface MenuItem {
  index: string
  icon: typeof Monitor
  label: string
  access?: string
}

const menuItems: MenuItem[] = [
  { index: '/dashboard', icon: Monitor, label: '仪表盘', access: 'dashboard' },
  { index: '/assets', icon: Monitor, label: '资产', access: 'assets' },
  { index: '/platforms', icon: Tools, label: '平台模板', access: 'platforms' },
  { index: '/users', icon: User, label: '用户', access: 'users' },
  { index: '/roles', icon: Setting, label: '角色', access: 'roles' },
  { index: '/permissions', icon: Lock, label: '资产授权', access: 'permissions' },
  { index: '/sessions', icon: Connection, label: '会话', access: 'sessions' },
  { index: '/audit-logs', icon: Document, label: '审计日志', access: 'audit_logs' },
  { index: '/settings', icon: Tools, label: '系统设置', access: 'settings' },
]

function canShow(item: MenuItem): boolean {
  if (!item.access) return true
  return authStore.canAccess(item.access)
}
</script>

<template>
  <el-scrollbar>
    <el-menu
      :router="true"
      :default-active="activeMenu"
      :collapse="collapse"
      :unique-opened="true"
      background-color="#304156"
      text-color="#bfcbd9"
      active-text-color="#409EFF"
    >
      <template v-for="item in menuItems" :key="item.index">
        <el-menu-item
          v-if="canShow(item)"
          :index="item.index"
        >
          <el-icon><component :is="item.icon" /></el-icon>
          <span>{{ item.label }}</span>
        </el-menu-item>
      </template>
    </el-menu>
  </el-scrollbar>
</template>
