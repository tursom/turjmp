<template>
  <div class="page-container">
    <div class="page-header">
      <h2>个人安全</h2>
    </div>

    <el-alert
      v-if="error"
      :title="error"
      type="error"
      show-icon
      :closable="false"
      class="section-alert"
    />

    <section v-loading="loading" class="security-section">
      <div class="section-header">
        <div>
          <h3>RDP 代理密码</h3>
          <p>用于 Windows mstsc 连接 Turjmp 原生 RDP 代理，独立于 Web 登录密码。</p>
        </div>
        <el-tag :type="credentialTagType">
          {{ credentialStatusText }}
        </el-tag>
      </div>

      <el-descriptions :column="2" border class="status-descriptions">
        <el-descriptions-item label="配置状态">
          {{ status?.configured ? '已配置' : '未配置' }}
        </el-descriptions-item>
        <el-descriptions-item label="启用状态">
          {{ status?.enabled ? '启用' : '停用' }}
        </el-descriptions-item>
        <el-descriptions-item label="更新时间">
          {{ formatDate(status?.updated_at) }}
        </el-descriptions-item>
        <el-descriptions-item label="禁用时间">
          {{ formatDate(status?.disabled_at) }}
        </el-descriptions-item>
      </el-descriptions>

      <el-divider />

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-width="110px"
        class="credential-form"
        @submit.prevent="submitPassword"
      >
        <el-form-item label="新密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="输入新的 RDP 代理密码"
          />
        </el-form-item>
        <el-form-item label="确认密码" prop="confirmPassword">
          <el-input
            v-model="form.confirmPassword"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="再次输入 RDP 代理密码"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            native-type="submit"
            :loading="saving"
          >
            {{ status?.configured ? '重置密码' : '设置密码' }}
          </el-button>
          <el-button
            v-if="status?.configured && status.enabled"
            type="danger"
            plain
            :loading="disabling"
            @click="disableCredential"
          >
            禁用
          </el-button>
        </el-form-item>
      </el-form>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import * as authApi from '@/api/auth'
import type { RDPProxyCredentialStatus } from '@/types'

const loading = ref(false)
const saving = ref(false)
const disabling = ref(false)
const error = ref('')
const status = ref<RDPProxyCredentialStatus | null>(null)
const formRef = ref<FormInstance>()

const form = reactive({
  password: '',
  confirmPassword: '',
})

const rules: FormRules = {
  password: [
    { required: true, message: '请输入 RDP 代理密码', trigger: 'blur' },
    { min: 8, message: '密码长度至少 8 位', trigger: 'blur' },
  ],
  confirmPassword: [
    { required: true, message: '请再次输入 RDP 代理密码', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        if (value !== form.password) {
          callback(new Error('两次输入的密码不一致'))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
}

const credentialStatusText = computed(() => {
  if (!status.value?.configured) return '未配置'
  return status.value.enabled ? '已启用' : '已禁用'
})

const credentialTagType = computed(() => {
  if (!status.value?.configured) return 'info'
  return status.value.enabled ? 'success' : 'warning'
})

function formatDate(value?: string): string {
  if (!value) return '-'
  return new Date(value).toLocaleString()
}

function clearPasswordFields(): void {
  form.password = ''
  form.confirmPassword = ''
  formRef.value?.clearValidate()
}

async function loadStatus(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    status.value = await authApi.getRDPProxyCredential()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载 RDP 代理密码状态失败'
  } finally {
    loading.value = false
  }
}

async function submitPassword(): Promise<void> {
  if (!formRef.value) return
  try {
    await formRef.value.validate()
  } catch {
    return
  }
  saving.value = true
  try {
    const wasConfigured = status.value?.configured === true
    status.value = wasConfigured
      ? await authApi.resetRDPProxyCredential({ password: form.password })
      : await authApi.setRDPProxyCredential({ password: form.password })
    clearPasswordFields()
    ElMessage.success(wasConfigured ? 'RDP 代理密码已更新' : 'RDP 代理密码已设置')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '保存 RDP 代理密码失败')
  } finally {
    saving.value = false
  }
}

async function disableCredential(): Promise<void> {
  try {
    await ElMessageBox.confirm('禁用后，新的 mstsc 原生 RDP 连接将无法使用此密码认证。', '禁用 RDP 代理密码', {
      confirmButtonText: '禁用',
      cancelButtonText: '取消',
      type: 'warning',
    })
  } catch {
    return
  }
  disabling.value = true
  try {
    status.value = await authApi.disableRDPProxyCredential()
    clearPasswordFields()
    ElMessage.success('RDP 代理密码已禁用')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '禁用 RDP 代理密码失败')
  } finally {
    disabling.value = false
  }
}

onMounted(() => {
  void loadStatus()
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
  font-size: 18px;
  font-weight: 600;
}

.section-alert {
  margin-bottom: 16px;
}

.security-section {
  max-width: 920px;
}

.section-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 16px;
}

.section-header h3 {
  margin: 0 0 6px;
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.section-header p {
  margin: 0;
  color: #606266;
  font-size: 14px;
  line-height: 1.5;
}

.status-descriptions {
  margin-bottom: 16px;
}

.credential-form {
  max-width: 520px;
}

@media (max-width: 768px) {
  .section-header {
    flex-direction: column;
  }
}
</style>
