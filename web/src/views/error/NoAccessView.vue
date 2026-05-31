<template>
  <div class="no-access-page">
    <el-result
      icon="warning"
      title="没有可访问的管理页面"
      sub-title="你已登录，但当前权限无法访问任何管理台页面。请联系管理员调整角色权限。"
    >
      <template #extra>
        <el-button type="primary" @click="authStore.doLogout()">返回登录</el-button>
      </template>
    </el-result>
  </div>
</template>

<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
</script>

<style scoped>
.no-access-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px;
  background: #f5f7fa;
}
</style>
