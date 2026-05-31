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
  { index: '/dashboard', icon: Monitor, label: 'Dashboard', access: 'dashboard' },
  { index: '/assets', icon: Monitor, label: 'Assets', access: 'assets' },
  { index: '/platforms', icon: Tools, label: 'Platforms', access: 'platforms' },
  { index: '/users', icon: User, label: 'Users', access: 'users' },
  { index: '/roles', icon: Setting, label: 'Roles', access: 'roles' },
  { index: '/permissions', icon: Lock, label: 'Permissions', access: 'permissions' },
  { index: '/sessions', icon: Connection, label: 'Sessions', access: 'sessions' },
  { index: '/audit-logs', icon: Document, label: 'Audit Logs', access: 'audit_logs' },
  { index: '/settings', icon: Tools, label: 'Settings', access: 'settings' },
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
