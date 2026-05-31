<template>
  <div class="page-container">
    <div class="page-header">
      <h2>{{ isEdit ? 'Edit User' : 'New User' }}</h2>
    </div>

    <div v-if="loadingUser" class="page-loading">
      <el-icon class="is-loading" :size="24"><Loading /></el-icon>
      <span>Loading user data...</span>
    </div>

    <el-form
      v-else
      ref="formRef"
      :model="form"
      :rules="rules"
      label-width="120px"
      class="user-form"
      @submit.prevent="handleSubmit"
    >
      <el-form-item label="Username" prop="username">
        <el-input v-model="form.username" placeholder="Enter username" />
      </el-form-item>

      <el-form-item label="Name" prop="name">
        <el-input v-model="form.name" placeholder="Enter full name" />
      </el-form-item>

      <el-form-item label="Email" prop="email">
        <el-input v-model="form.email" placeholder="Enter email" />
      </el-form-item>

      <el-form-item label="Password" :prop="isEdit ? 'password' : 'password'">
        <el-input
          v-model="form.password"
          type="password"
          show-password
          :placeholder="passwordPlaceholder"
        />
      </el-form-item>

      <el-form-item label="Status">
        <el-switch v-model="form.is_active" active-text="Active" inactive-text="Inactive" />
      </el-form-item>

      <el-form-item label="Roles">
        <el-select
          v-model="form.role_ids"
          multiple
          filterable
          placeholder="Select roles"
          style="width: 100%"
        >
          <el-option
            v-for="role in roles"
            :key="role.id"
            :label="role.name"
            :value="role.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item>
        <el-button type="primary" native-type="submit" :loading="submitting">
          {{ isEdit ? 'Update' : 'Create' }}
        </el-button>
        <el-button @click="goBack">Cancel</el-button>
      </el-form-item>
    </el-form>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { Loading } from '@element-plus/icons-vue'
import type { Role } from '@/types'
import * as usersApi from '@/api/users'
import * as rolesApi from '@/api/roles'
import * as settingsApi from '@/api/settings'

const router = useRouter()
const route = useRoute()
const formRef = ref<FormInstance>()

const isEdit = computed(() => !!route.params.id)
const userId = computed(() => (isEdit.value ? Number(route.params.id) : undefined))

const loadingUser = ref(false)
const submitting = ref(false)
const roles = ref<Role[]>([])
const passwordMinLength = ref(8)

const form = reactive({
  username: '',
  name: '',
  email: '',
  password: '',
  is_active: true,
  role_ids: [] as number[],
})

const passwordPlaceholder = computed(() =>
  isEdit.value
    ? `Leave empty to keep current (min ${passwordMinLength.value} if changed)`
    : `Enter password, min ${passwordMinLength.value} characters`,
)

const rules = computed<FormRules>(() => ({
  username: [
    { required: true, message: 'Username is required', trigger: 'blur' },
    { min: 3, message: 'Username must be at least 3 characters', trigger: 'blur' },
  ],
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  email: [
    { required: true, message: 'Email is required', trigger: 'blur' },
    { type: 'email', message: 'Enter a valid email', trigger: 'blur' },
  ],
  password: [
    {
      validator: (_rule, value: string, callback) => {
        if (!isEdit.value && !value) {
          callback(new Error('Password is required'))
          return
        }
        if (value && value.length < passwordMinLength.value) {
          callback(new Error(`Password must be at least ${passwordMinLength.value} characters`))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
}))

async function fetchPasswordPolicy() {
  try {
    const setting = await settingsApi.get('security.password_min_length')
    const parsed: unknown = JSON.parse(setting.value)
    const minLength = typeof parsed === 'number' ? parsed : Number(parsed)
    if (Number.isFinite(minLength) && minLength > 0) {
      passwordMinLength.value = minLength
    }
  } catch {
    // Keep the backend default used by bootstrap settings.
  }
}

function goBack() {
  router.push('/users')
}

async function fetchRoles() {
  try {
    roles.value = await rolesApi.list()
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to load roles'
    ElMessage.error(msg)
  }
}

async function fetchUser() {
  if (!userId.value) return
  loadingUser.value = true
  try {
    const detail = await usersApi.get(userId.value)
    form.username = detail.user.username
    form.name = detail.user.name
    form.email = detail.user.email
    form.is_active = detail.user.is_active
    form.password = ''
    form.role_ids = detail.roles.map((r) => r.id)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to load user'
    ElMessage.error(msg)
  } finally {
    loadingUser.value = false
  }
}

async function handleSubmit() {
  if (!formRef.value) return
  try {
    await formRef.value.validate()
  } catch {
    return
  }

  submitting.value = true
  try {
    const payload = {
      username: form.username,
      name: form.name,
      email: form.email,
      password: form.password || undefined,
      is_active: form.is_active,
      role_ids: form.role_ids,
    }

    if (isEdit.value && userId.value) {
      // Don't send password if empty (no change)
      if (!payload.password) delete payload.password
      await usersApi.update(userId.value, payload)
      ElMessage.success('User updated successfully')
    } else {
      const createPayload = {
        ...payload,
      }
      if (!createPayload.password) {
        ElMessage.error('Password is required')
        submitting.value = false
        return
      }
      await usersApi.create(createPayload as { username: string; name: string; email: string; password: string; is_active: boolean; role_ids: number[] })
      ElMessage.success('User created successfully')
    }
    router.push('/users')
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Save failed'
    ElMessage.error(msg)
  } finally {
    submitting.value = false
  }
}

onMounted(async () => {
  await Promise.all([fetchRoles(), fetchPasswordPolicy()])
  if (isEdit.value) {
    await fetchUser()
  }
})
</script>

<style scoped>
.page-header {
  margin-bottom: 24px;
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

.user-form {
  max-width: 560px;
}
</style>
