<template>
  <div class="page-container">
    <div class="page-header">
      <h2>{{ isEdit ? '编辑用户' : '新建用户' }}</h2>
    </div>

    <div v-if="loadingUser" class="page-loading">
      <el-icon class="is-loading" :size="24"><Loading /></el-icon>
      <span>正在加载用户数据...</span>
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
      <el-form-item label="用户名" prop="username">
        <el-input v-model="form.username" placeholder="输入用户名" />
      </el-form-item>

      <el-form-item label="姓名" prop="name">
        <el-input v-model="form.name" placeholder="输入姓名" />
      </el-form-item>

      <el-form-item label="邮箱" prop="email">
        <el-input v-model="form.email" placeholder="输入邮箱" />
      </el-form-item>

      <el-form-item label="密码" :prop="isEdit ? 'password' : 'password'">
        <el-input
          v-model="form.password"
          type="password"
          show-password
          :placeholder="passwordPlaceholder"
        />
      </el-form-item>

      <el-form-item label="状态">
        <el-switch v-model="form.is_active" active-text="活跃" inactive-text="停用" />
      </el-form-item>

      <el-form-item label="角色">
        <el-select
          v-model="form.role_ids"
          multiple
          filterable
          placeholder="选择角色"
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
          {{ isEdit ? '更新' : '创建' }}
        </el-button>
        <el-button @click="goBack">取消</el-button>
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
    ? `留空则保持当前密码不变（修改时至少 ${passwordMinLength.value} 个字符）`
    : `输入密码，至少 ${passwordMinLength.value} 个字符`,
)

const rules = computed<FormRules>(() => ({
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 3, message: '用户名至少需要 3 个字符', trigger: 'blur' },
  ],
  name: [{ required: true, message: '请输入姓名', trigger: 'blur' }],
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '请输入有效邮箱', trigger: 'blur' },
  ],
  password: [
    {
      validator: (_rule, value: string, callback) => {
        if (!isEdit.value && !value) {
          callback(new Error('请输入密码'))
          return
        }
        if (value && value.length < passwordMinLength.value) {
          callback(new Error(`密码至少需要 ${passwordMinLength.value} 个字符`))
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
    const msg = err instanceof Error ? err.message : '加载角色失败'
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
    const msg = err instanceof Error ? err.message : '加载用户失败'
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
      ElMessage.success('用户已更新')
    } else {
      const createPayload = {
        ...payload,
      }
      if (!createPayload.password) {
        ElMessage.error('请输入密码')
        submitting.value = false
        return
      }
      await usersApi.create(createPayload as { username: string; name: string; email: string; password: string; is_active: boolean; role_ids: number[] })
      ElMessage.success('用户已创建')
    }
    router.push('/users')
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '保存失败'
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
