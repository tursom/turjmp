<template>
  <div class="no-access-page">
    <el-result
      icon="warning"
      title="No accessible console pages"
      sub-title="Your account is signed in, but current permissions do not allow any management console page. Ask an administrator to adjust your role permissions."
    >
      <template #extra>
        <el-button type="primary" @click="authStore.doLogout()">Back to Login</el-button>
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
