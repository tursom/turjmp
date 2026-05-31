<template>
  <div class="page-container">
    <div class="page-header">
      <h2>{{ role ? `Edit Role: ${role.name}` : 'Edit Role' }}</h2>
      <el-button @click="goBack">
        <el-icon><ArrowLeft /></el-icon>
        Back to Roles
      </el-button>
    </div>

    <div v-if="loading" class="page-loading">
      <el-icon class="is-loading" :size="24"><Loading /></el-icon>
      <span>Loading role...</span>
    </div>

    <template v-else-if="role">
      <!-- Basic Info -->
      <el-card class="section-card" shadow="never">
        <template #header>
          <span class="card-title">Basic Information</span>
        </template>
        <el-form
          ref="infoFormRef"
          :model="infoForm"
          :rules="infoRules"
          label-width="120px"
          class="info-form"
        >
          <el-form-item label="Name" prop="name">
            <el-input v-model="infoForm.name" placeholder="Role name" />
          </el-form-item>
          <el-form-item label="Description" prop="description">
            <el-input
              v-model="infoForm.description"
              type="textarea"
              :rows="3"
              placeholder="Description"
            />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingInfo" @click="saveInfo">
              Save
            </el-button>
          </el-form-item>
        </el-form>
      </el-card>

      <!-- Permission Matrix -->
      <el-card class="section-card" shadow="never">
        <template #header>
          <div class="card-header-row">
            <span class="card-title">Permission Matrix</span>
            <div class="card-actions">
              <el-button size="small" @click="selectAll">Select All</el-button>
              <el-button size="small" @click="deselectAll">Deselect All</el-button>
            </div>
          </div>
        </template>

        <div class="perm-matrix-wrapper">
          <table class="perm-matrix">
            <thead>
              <tr>
                <th class="path-col">Endpoint</th>
                <th v-for="m in methods" :key="m" class="method-col">{{ methodLabel(m) }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="permRow in pathRows" :key="permRow.path">
                <td class="path-label">
                  <code>{{ permRow.path }}</code>
                </td>
                <td
                  v-for="m in methods"
                  :key="`${permRow.path}-${m}`"
                  class="method-cell"
                >
                  <el-checkbox
                    :model-value="isChecked(permRow.path, m)"
                    @change="(val: boolean) => togglePerm(permRow.path, m, val)"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="perm-footer">
          <el-button
            type="primary"
            :loading="savingPerms"
            @click="savePermissions"
          >
            Save Permissions
          </el-button>
        </div>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { ArrowLeft, Loading } from '@element-plus/icons-vue'
import type { Role } from '@/types'
import * as rolesApi from '@/api/roles'

const router = useRouter()
const route = useRoute()
const roleId = Number(route.params.id)

const role = ref<Role | null>(null)
const loading = ref(false)

// Basic info form
const infoFormRef = ref<FormInstance>()
const savingInfo = ref(false)

const infoForm = reactive({
  name: '',
  description: '',
})

const infoRules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  description: [{ required: true, message: 'Description is required', trigger: 'blur' }],
}

// Permission matrix. Paths must match Gin c.FullPath(), including /api/v1.
const methods = ['.*', 'GET', 'POST', 'PATCH', 'PUT', 'DELETE'] as const

interface PathRow {
  path: string
  allowed?: string[]
}

const pathRows: PathRow[] = [
  { path: '/api/v1/*' },
  { path: '/api/v1/users' },
  { path: '/api/v1/users/:id' },
  { path: '/api/v1/roles' },
  { path: '/api/v1/roles/:id' },
  { path: '/api/v1/roles/:id/permissions' },
  { path: '/api/v1/user-groups' },
  { path: '/api/v1/assets' },
  { path: '/api/v1/assets/:id' },
  { path: '/api/v1/assets/tree' },
  { path: '/api/v1/assets/:id/accounts' },
  { path: '/api/v1/assets/:id/accounts/:aid' },
  { path: '/api/v1/platforms' },
  { path: '/api/v1/platforms/:id/protocols' },
  { path: '/api/v1/permissions' },
  { path: '/api/v1/permissions/:id' },
  { path: '/api/v1/dashboard/summary' },
  { path: '/api/v1/sessions' },
  { path: '/api/v1/sessions/stream-token' },
  { path: '/api/v1/sessions/:id' },
  { path: '/api/v1/sessions/:id/recording' },
  { path: '/api/v1/sessions/:id/force-finish' },
  { path: '/api/v1/sessions/:id/commands' },
  { path: '/api/v1/settings' },
  { path: '/api/v1/settings/ssh-fingerprint' },
  { path: '/api/v1/settings/:key' },
  { path: '/api/v1/audit-logs' },
  { path: '/api/v1/authentication/connection-tokens/' },
  { path: '/api/v1/authentication/connection-tokens/sdk-url' },
]

const checkedPerms = ref<Set<string>>(new Set())
const preservedPolicies = ref<{ path: string; method: string }[]>([])

const savingPerms = ref(false)

function permKey(path: string, method: string): string {
  return `${method}:${path}`
}

function isChecked(path: string, method: string): boolean {
  return checkedPerms.value.has(permKey(path, method))
}

function methodLabel(method: string): string {
  return method === '.*' ? 'ALL' : method
}

function knownPath(path: string): boolean {
  return pathRows.some((row) => row.path === path)
}

function policyMethods(pattern: string): string[] {
  if (pattern === '.*') return ['.*']
  return pattern
    .split('|')
    .map((item) => item.trim())
    .filter((item) => methods.includes(item as (typeof methods)[number]))
}

function togglePerm(path: string, method: string, val: boolean) {
  const key = permKey(path, method)
  if (val) {
    checkedPerms.value.add(key)
  } else {
    checkedPerms.value.delete(key)
  }
  // Trigger reactivity
  checkedPerms.value = new Set(checkedPerms.value)
}

function selectAll() {
  const s = new Set<string>()
  for (const row of pathRows) {
    s.add(permKey(row.path, '.*'))
  }
  checkedPerms.value = s
}

function deselectAll() {
  checkedPerms.value = new Set()
}

function goBack() {
  router.push('/roles')
}

async function fetchRole() {
  loading.value = true
  try {
    const detail = await rolesApi.get(roleId)
    role.value = detail.role
    infoForm.name = detail.role.name
    infoForm.description = detail.role.description

    // Load existing permissions: 2D array [roleName, path, method]
    const s = new Set<string>()
    const unknown: { path: string; method: string }[] = []
    for (const perm of detail.permissions) {
      const [, path, method] = perm
      if (!path || !method) {
        continue
      }
      if (!knownPath(path)) {
        unknown.push({ path, method })
        continue
      }
      for (const m of policyMethods(method)) {
        s.add(permKey(path, m))
      }
    }
    checkedPerms.value = s
    preservedPolicies.value = unknown
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to load role'
    ElMessage.error(msg)
  } finally {
    loading.value = false
  }
}

async function saveInfo() {
  if (!infoFormRef.value) return
  try {
    await infoFormRef.value.validate()
  } catch {
    return
  }

  savingInfo.value = true
  try {
    const updated = await rolesApi.update(roleId, {
      name: infoForm.name,
      description: infoForm.description,
    })
    role.value = updated
    ElMessage.success('Role info updated')
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to update role'
    ElMessage.error(msg)
  } finally {
    savingInfo.value = false
  }
}

async function savePermissions() {
  const permissions: { path: string; method: string }[] = [...preservedPolicies.value]

  for (const row of pathRows) {
    for (const m of methods) {
      if (checkedPerms.value.has(permKey(row.path, m))) {
        permissions.push({ path: row.path, method: m })
      }
    }
  }

  savingPerms.value = true
  try {
    await rolesApi.setPermissions(roleId, { permissions })
    ElMessage.success('Permissions updated')
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to save permissions'
    ElMessage.error(msg)
  } finally {
    savingPerms.value = false
  }
}

onMounted(() => {
  fetchRole()
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

.section-card {
  margin-bottom: 20px;
}

.card-title {
  font-weight: 600;
  font-size: 15px;
  color: #303133;
}

.card-header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.card-actions {
  display: flex;
  gap: 8px;
}

.info-form {
  max-width: 480px;
}

.perm-matrix-wrapper {
  overflow-x: auto;
}

.perm-matrix {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.perm-matrix th,
.perm-matrix td {
  padding: 8px 12px;
  border: 1px solid #ebeef5;
  text-align: center;
  white-space: nowrap;
}

.perm-matrix thead th {
  background: #f5f7fa;
  font-weight: 600;
  color: #606266;
}

.path-col {
  text-align: left !important;
  min-width: 200px;
}

.method-col {
  min-width: 80px;
  width: 80px;
}

.path-label {
  text-align: left !important;
}

.path-label code {
  font-size: 12px;
  color: #303133;
  background: #f5f7fa;
  padding: 2px 6px;
  border-radius: 3px;
}

.method-cell {
  padding: 4px 12px !important;
}

.perm-footer {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid #ebeef5;
}
</style>
