<template>
  <div class="page-container">
    <div class="page-header">
      <h2>用户</h2>
      <el-button v-if="canCreateUsers" type="primary" @click="goCreate">
        <el-icon><Plus /></el-icon>
        新建用户
      </el-button>
    </div>

    <div class="page-filters">
      <el-input
        v-model="searchQuery"
        placeholder="按用户名或姓名搜索..."
        clearable
        class="search-input"
        @input="handleSearch"
      />
    </div>

    <div v-if="loading" class="page-loading">
      <el-icon class="is-loading" :size="24"><Loading /></el-icon>
      <span>正在加载用户...</span>
    </div>

    <div v-else-if="error" class="page-error">
      <el-result icon="error" title="加载用户失败" :sub-title="error">
        <template #extra>
          <el-button type="primary" @click="fetchUsers">重试</el-button>
        </template>
      </el-result>
    </div>

    <el-table
      v-else
      :data="filteredUsers"
      border
      stripe
      style="width: 100%"
      empty-text="未找到用户"
    >
      <el-table-column prop="id" label="ID" width="70" align="center" />
      <el-table-column prop="username" label="用户名" min-width="130" />
      <el-table-column prop="name" label="姓名" min-width="130" />
      <el-table-column prop="email" label="邮箱" min-width="180" />
      <el-table-column label="MFA" width="80" align="center">
        <template #default="{ row }">
          <el-tag :type="row.mfa_enabled ? 'success' : 'info'" size="small">
            {{ row.mfa_enabled ? '已启用' : '未启用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90" align="center">
        <template #default="{ row }">
          <el-tag :type="row.is_active ? 'success' : 'danger'" size="small">
            {{ row.is_active ? '活跃' : '停用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="最后登录" width="180" align="center">
        <template #default="{ row }">
          {{ row.last_login_at ? formatDate(row.last_login_at) : '—' }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="160" align="center" fixed="right">
        <template #default="{ row }">
          <el-button v-if="canUpdateUsers" size="small" @click="goEdit(row.id)">编辑</el-button>
          <el-button v-if="canDeleteUsers" size="small" type="danger" @click="handleDelete(row)">
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Loading } from '@element-plus/icons-vue'
import type { User } from '@/types'
import * as usersApi from '@/api/users'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const users = ref<User[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const searchQuery = ref('')
const canCreateUsers = computed(() => authStore.canAccess('user_create'))
const canUpdateUsers = computed(() => authStore.canAccess('user_update'))
const canDeleteUsers = computed(() => authStore.canAccess('user_delete'))

const filteredUsers = computed(() => {
  if (!searchQuery.value.trim()) return users.value
  const q = searchQuery.value.trim().toLowerCase()
  return users.value.filter(
    (u) =>
      u.username.toLowerCase().includes(q) ||
      u.name.toLowerCase().includes(q),
  )
})

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString()
}

function goCreate() {
  router.push('/users/new')
}

function goEdit(id: number) {
  router.push(`/users/${id}/edit`)
}

async function fetchUsers() {
  loading.value = true
  error.value = null
  try {
    users.value = await usersApi.list()
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '加载用户失败'
    error.value = msg
    ElMessage.error(msg)
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  // filteredUsers is computed, so no-op needed — just used for @input binding
}

async function handleDelete(user: User) {
  try {
    await ElMessageBox.confirm(
      `确认删除用户“${user.username}”吗？此操作不可撤销。`,
      '确认删除',
      { confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return // cancelled
  }

  try {
    await usersApi.remove(user.id)
    ElMessage.success(`用户“${user.username}”已删除`)
    users.value = users.value.filter((u) => u.id !== user.id)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '删除失败'
    ElMessage.error(msg)
  }
}

onMounted(() => {
  fetchUsers()
})
</script>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  color: #303133;
}

.page-filters {
  margin-bottom: 16px;
}

.search-input {
  width: 300px;
}

.page-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 60px 0;
  color: #909399;
}

.page-error {
  padding: 20px 0;
}
</style>
