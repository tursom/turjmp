<script setup lang="ts">
import { Fold, Expand } from '@element-plus/icons-vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

defineProps<{
  collapse: boolean
}>()

const emit = defineEmits<{
  toggleCollapse: []
}>()

const authStore = useAuthStore()
const router = useRouter()

function handleCommand(command: string) {
  if (command === 'mfa') {
    router.push('/mfa-setup')
    return
  }
  if (command === 'logout') {
    authStore.doLogout()
  }
}
</script>

<template>
  <div class="header-left">
    <el-icon class="collapse-btn" @click="emit('toggleCollapse')">
      <Fold v-if="!collapse" />
      <Expand v-else />
    </el-icon>
  </div>
  <div class="header-right">
    <el-dropdown @command="handleCommand">
      <span class="user-info">
        {{ authStore.user?.name || authStore.user?.username || '用户' }}
      </span>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item command="mfa">MFA 设置</el-dropdown-item>
          <el-dropdown-item command="logout">退出登录</el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<style scoped>
.header-left {
  display: flex;
  align-items: center;
}

.header-right {
  display: flex;
  align-items: center;
}

.user-info {
  cursor: pointer;
  color: #303133;
}
</style>
