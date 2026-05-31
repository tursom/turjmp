<template>
  <div class="page-container">
    <div class="page-header">
      <h2>Roles</h2>
      <el-button v-if="canCreateRoles" type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon>
        New Role
      </el-button>
    </div>

    <div v-if="loading" class="page-loading">
      <el-icon class="is-loading" :size="24"><Loading /></el-icon>
      <span>Loading roles...</span>
    </div>

    <div v-else-if="error" class="page-error">
      <el-result icon="error" title="Failed to load roles" :sub-title="error">
        <template #extra>
          <el-button type="primary" @click="fetchRoles">Retry</el-button>
        </template>
      </el-result>
    </div>

    <el-table
      v-else
      :data="roles"
      border
      stripe
      style="width: 100%"
      empty-text="No roles found"
    >
      <el-table-column prop="id" label="ID" width="80" align="center" />
      <el-table-column prop="name" label="Name" min-width="160" />
      <el-table-column prop="description" label="Description" min-width="260" />
      <el-table-column label="Actions" width="200" align="center" fixed="right">
        <template #default="{ row }">
          <el-button v-if="canUpdateRoles" size="small" @click="goEdit(row.id)">Edit</el-button>
          <el-button v-if="canDeleteRoles" size="small" type="danger" @click="handleDelete(row)">
            Delete
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- Create Role Dialog -->
    <el-dialog v-model="dialogVisible" title="New Role" width="480px" @close="resetForm">
      <el-form ref="dialogFormRef" :model="createForm" :rules="createRules" label-width="100px">
        <el-form-item label="Name" prop="name">
          <el-input v-model="createForm.name" placeholder="Enter role name" />
        </el-form-item>
        <el-form-item label="Description" prop="description">
          <el-input
            v-model="createForm.description"
            type="textarea"
            :rows="3"
            placeholder="Enter description"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">Cancel</el-button>
        <el-button type="primary" :loading="creating" @click="handleCreate">
          Create
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { Plus, Loading } from '@element-plus/icons-vue'
import type { Role } from '@/types'
import * as rolesApi from '@/api/roles'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const roles = ref<Role[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const canCreateRoles = computed(() => authStore.canAccess('role_create'))
const canUpdateRoles = computed(() => authStore.canAccess('role_update'))
const canDeleteRoles = computed(() => authStore.canAccess('role_delete'))

const dialogVisible = ref(false)
const dialogFormRef = ref<FormInstance>()
const creating = ref(false)

const createForm = reactive({
  name: '',
  description: '',
})

const createRules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  description: [{ required: true, message: 'Description is required', trigger: 'blur' }],
}

function goEdit(id: number) {
  router.push(`/roles/${id}`)
}

function openCreate() {
  dialogVisible.value = true
}

function resetForm() {
  createForm.name = ''
  createForm.description = ''
}

async function fetchRoles() {
  loading.value = true
  error.value = null
  try {
    roles.value = await rolesApi.list()
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to load roles'
    error.value = msg
    ElMessage.error(msg)
  } finally {
    loading.value = false
  }
}

async function handleCreate() {
  if (!dialogFormRef.value) return
  try {
    await dialogFormRef.value.validate()
  } catch {
    return
  }

  creating.value = true
  try {
    const role = await rolesApi.create({ name: createForm.name, description: createForm.description })
    ElMessage.success(`Role "${role.name}" created`)
    dialogVisible.value = false
    resetForm()
    roles.value.push(role)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Creation failed'
    ElMessage.error(msg)
  } finally {
    creating.value = false
  }
}

async function handleDelete(role: Role) {
  try {
    await ElMessageBox.confirm(
      `Delete role "${role.name}"? This action cannot be undone.`,
      'Confirm Delete',
      { confirmButtonText: 'Delete', cancelButtonText: 'Cancel', type: 'warning' },
    )
  } catch {
    return
  }

  try {
    await rolesApi.remove(role.id)
    ElMessage.success(`Role "${role.name}" deleted`)
    roles.value = roles.value.filter((r) => r.id !== role.id)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Delete failed'
    ElMessage.error(msg)
  }
}

onMounted(() => {
  fetchRoles()
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
