<template>
  <div class="page-container">
    <div class="page-header">
      <h2>资产授权</h2>
      <el-button v-if="canCreatePermissions" type="primary" @click="goCreate">
        <el-icon><Plus /></el-icon>
        新建授权
      </el-button>
    </div>

    <div v-if="loading" class="page-loading">
      <el-icon class="is-loading" :size="24"><Loading /></el-icon>
      <span>正在加载授权...</span>
    </div>

    <div v-else-if="error" class="page-error">
      <el-result icon="error" title="加载授权失败" :sub-title="error">
        <template #extra>
          <el-button type="primary" @click="fetchPermissions">重试</el-button>
        </template>
      </el-result>
    </div>

    <el-table
      v-else
      :data="permissions"
      border
      stripe
      style="width: 100%"
      empty-text="未找到授权"
    >
      <el-table-column prop="id" label="ID" width="70" align="center" />
      <el-table-column prop="name" label="名称" min-width="160" />
      <el-table-column prop="actions" label="动作" min-width="200" />
      <el-table-column label="开始时间" width="160" align="center">
        <template #default="{ row }">
          {{ row.date_start ? formatDate(row.date_start) : '—' }}
        </template>
      </el-table-column>
      <el-table-column label="过期时间" width="160" align="center">
        <template #default="{ row }">
          {{ row.date_expired ? formatDate(row.date_expired) : '—' }}
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90" align="center">
        <template #default="{ row }">
          <el-tag :type="row.is_active ? 'success' : 'danger'" size="small">
            {{ row.is_active ? '活跃' : '停用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="160" align="center" fixed="right">
        <template #default="{ row }">
          <el-button v-if="canUpdatePermissions" size="small" @click="goEdit(row.id)">编辑</el-button>
          <el-button v-if="canDeletePermissions" size="small" type="danger" @click="handleDelete(row)">
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
import type { AssetPermission } from '@/types'
import * as permissionsApi from '@/api/permissions'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const permissions = ref<AssetPermission[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const canCreatePermissions = computed(() => authStore.canAccess('permission_create'))
const canUpdatePermissions = computed(() => authStore.canAccess('permission_update'))
const canDeletePermissions = computed(() => authStore.canAccess('permission_delete'))

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString()
}

function goCreate() {
  router.push('/permissions/new')
}

function goEdit(id: number) {
  router.push(`/permissions/${id}/edit`)
}

async function fetchPermissions() {
  loading.value = true
  error.value = null
  try {
    permissions.value = await permissionsApi.list()
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '加载授权失败'
    error.value = msg
    ElMessage.error(msg)
  } finally {
    loading.value = false
  }
}

async function handleDelete(perm: AssetPermission) {
  try {
    await ElMessageBox.confirm(
      `确认删除授权“${perm.name}”吗？此操作不可撤销。`,
      '确认删除',
      { confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }

  try {
    await permissionsApi.remove(perm.id)
    ElMessage.success(`授权“${perm.name}”已删除`)
    permissions.value = permissions.value.filter((p) => p.id !== perm.id)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '删除失败'
    ElMessage.error(msg)
  }
}

onMounted(() => {
  fetchPermissions()
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
