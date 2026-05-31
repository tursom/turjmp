<template>
  <div class="login-container">
    <div class="login-card">
      <div class="login-header">
        <img src="/favicon.svg" class="login-logo" alt="Turjmp" />
        <h1 class="login-title">Turjmp</h1>
        <p class="login-subtitle">堡垒机管理平台</p>
      </div>
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        @submit.prevent="handleLogin"
      >
        <el-form-item prop="username">
          <el-input
            v-model="form.username"
            placeholder="用户名"
            :prefix-icon="UserIcon"
            size="large"
          />
        </el-form-item>
        <el-form-item prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="密码"
            :prefix-icon="LockIcon"
            show-password
            size="large"
          />
        </el-form-item>
        <el-alert
          v-if="mfaRequired"
          title="需要 MFA 验证"
          type="info"
          :closable="false"
          class="mfa-alert"
        />
        <el-form-item v-if="mfaRequired" prop="mfaCode">
          <el-input
            v-model="form.mfaCode"
            placeholder="MFA 验证码"
            :prefix-icon="KeyIcon"
            maxlength="6"
            size="large"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            native-type="submit"
            :loading="authStore.loginLoading"
            size="large"
            class="login-btn"
          >
            {{ authStore.loginLoading ? '登录中...' : (mfaRequired ? '验证并登录' : '登录') }}
          </el-button>
        </el-form-item>
      </el-form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { User, Lock, Key } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const route = useRoute()
const formRef = ref<FormInstance>()
const mfaRequired = ref(false)

const form = reactive({
  username: '',
  password: '',
  mfaCode: '',
})

const UserIcon = User
const LockIcon = Lock
const KeyIcon = Key

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码至少需要 6 个字符', trigger: 'blur' },
  ],
  mfaCode: [
    {
      validator: (_rule, value: string, callback) => {
        if (mfaRequired.value && !value) {
          callback(new Error('请输入 MFA 验证码'))
          return
        }
        if (value && !/^\d{6}$/.test(value)) {
          callback(new Error('MFA 验证码必须是 6 位数字'))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
}

async function handleLogin() {
  if (!formRef.value) return
  try {
    await formRef.value.validate()
  } catch {
    return
  }
  try {
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : undefined
    const result = await authStore.login(
      form.username,
      form.password,
      form.mfaCode || undefined,
      redirect,
    )
    if (result.require_mfa) {
      mfaRequired.value = true
      form.mfaCode = ''
      ElMessage.info('请输入 MFA 验证码后继续')
      return
    }
    if (result.require_mfa_setup) {
      ElMessage.info('继续使用前需要先完成 MFA 设置')
      return
    }
    ElMessage.success('登录成功')
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '登录失败'
    ElMessage.error(msg)
  }
}
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.login-card {
  width: 420px;
  padding: 40px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}

.login-header {
  text-align: center;
  margin-bottom: 32px;
}

.login-logo {
  width: 64px;
  height: 64px;
  margin-bottom: 16px;
}

.login-title {
  font-size: 28px;
  font-weight: 700;
  color: #303133;
  margin: 0;
}

.login-subtitle {
  font-size: 14px;
  color: #909399;
  margin-top: 8px;
}

.login-btn {
  width: 100%;
}

.mfa-alert {
  margin-bottom: 18px;
}
</style>
