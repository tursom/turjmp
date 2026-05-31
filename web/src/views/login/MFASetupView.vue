<template>
  <div class="mfa-setup-container">
    <div class="mfa-card">
      <div class="mfa-header">
        <h1 class="mfa-title">MFA 多因素认证设置</h1>
        <p class="mfa-subtitle">
          使用认证器应用扫描二维码，或手动输入密钥。随后输入 6 位验证码完成设置。
        </p>
      </div>

      <div v-if="loading" class="mfa-loading">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <p>正在加载 MFA 设置...</p>
      </div>

      <template v-else-if="setupData">
        <div class="mfa-qr-section">
          <img
            v-if="qrCodeUrl"
            :src="qrCodeUrl"
            alt="MFA 二维码"
            class="mfa-qr-image"
          />
          <div class="mfa-secret">
            <label class="mfa-label">密钥</label>
            <div class="mfa-secret-row">
              <code class="mfa-secret-text">{{ setupData.secret }}</code>
              <el-button size="small" text @click="copySecret">
                复制
              </el-button>
            </div>
          </div>
        </div>

        <el-divider />

        <div class="mfa-verify-section">
          <h3>验证设置</h3>
          <p class="mfa-verify-hint">
            输入认证器应用中的 6 位验证码以确认启用。
          </p>
          <el-form
            ref="verifyFormRef"
            :model="verifyForm"
            :rules="verifyRules"
            @submit.prevent="handleVerify"
          >
            <el-form-item prop="code">
              <el-input
                v-model="verifyForm.code"
                placeholder="000000"
                :prefix-icon="Key"
                maxlength="6"
                size="large"
                class="mfa-code-input"
              />
            </el-form-item>
            <el-form-item>
              <el-button
                type="primary"
                native-type="submit"
                :loading="verifying"
                size="large"
                class="mfa-verify-btn"
              >
                {{ verifying ? '验证中...' : '验证并启用' }}
              </el-button>
            </el-form-item>
          </el-form>
        </div>
      </template>

      <div v-else class="mfa-error">
        <el-result icon="error" title="设置失败" sub-title="无法加载 MFA 设置数据。">
          <template #extra>
            <el-button type="primary" @click="fetchSetup">重试</el-button>
          </template>
        </el-result>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { Loading, Key } from '@element-plus/icons-vue'
import { useRouter } from 'vue-router'
import * as QRCode from 'qrcode'
import { defaultRouteForAccess } from '@/router'
import { useAuthStore } from '@/stores/auth'
import * as authApi from '@/api/auth'

const router = useRouter()
const authStore = useAuthStore()
const verifyFormRef = ref<FormInstance>()

const loading = ref(false)
const verifying = ref(false)
const setupData = ref<{ secret: string; url: string } | null>(null)
const qrCodeUrl = ref('')

const verifyForm = reactive({
  code: '',
})

const verifyRules: FormRules = {
  code: [
    { required: true, message: '请输入验证码', trigger: 'blur' },
    { pattern: /^\d{6}$/, message: '验证码必须是 6 位数字', trigger: 'blur' },
  ],
}

async function fetchSetup() {
  loading.value = true
  try {
    setupData.value = await authApi.mfaSetup()
    qrCodeUrl.value = await QRCode.toDataURL(setupData.value.url, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 200,
    })
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '加载 MFA 设置失败'
    ElMessage.error(msg)
  } finally {
    loading.value = false
  }
}

async function handleVerify() {
  if (!verifyFormRef.value) return
  try {
    await verifyFormRef.value.validate()
  } catch {
    return
  }
  verifying.value = true
  try {
    await authApi.mfaVerify(verifyForm.code)
    ElMessage.success('MFA 已成功启用')
    if (authStore.mfaSetupRequired) {
      authStore.resetAuth()
      router.push('/login')
      return
    }
    await authStore.loadAccess()
    router.push(defaultRouteForAccess(authStore.access))
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '验证失败'
    ElMessage.error(msg)
  } finally {
    verifying.value = false
  }
}

async function copySecret() {
  if (!setupData.value) return
  try {
    await globalThis.navigator.clipboard.writeText(setupData.value.secret)
    ElMessage.success('密钥已复制到剪贴板')
  } catch {
    ElMessage.warning('复制到剪贴板失败')
  }
}

onMounted(() => {
  fetchSetup()
})
</script>

<style scoped>
.mfa-setup-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.mfa-card {
  width: 480px;
  padding: 40px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}

.mfa-header {
  text-align: center;
  margin-bottom: 28px;
}

.mfa-title {
  font-size: 22px;
  font-weight: 700;
  color: #303133;
  margin: 0 0 12px;
}

.mfa-subtitle {
  font-size: 14px;
  color: #909399;
  line-height: 1.5;
  margin: 0;
}

.mfa-loading {
  text-align: center;
  padding: 40px 0;
  color: #909399;
}

.mfa-qr-section {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 20px;
}

.mfa-qr-image {
  width: 200px;
  height: 200px;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
}

.mfa-secret {
  width: 100%;
}

.mfa-label {
  display: block;
  font-size: 13px;
  color: #909399;
  margin-bottom: 6px;
  font-weight: 500;
}

.mfa-secret-row {
  display: flex;
  align-items: center;
  gap: 8px;
  background: #f5f7fa;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  padding: 8px 12px;
}

.mfa-secret-text {
  flex: 1;
  font-family: monospace;
  font-size: 14px;
  color: #303133;
  word-break: break-all;
  background: none;
  border: none;
  padding: 0;
}

.mfa-verify-section {
  margin-top: 4px;
}

.mfa-verify-section h3 {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
  margin: 0 0 8px;
}

.mfa-verify-hint {
  font-size: 13px;
  color: #909399;
  margin: 0 0 16px;
}

.mfa-code-input {
  max-width: 240px;
}

.mfa-verify-btn {
  width: 100%;
}

.mfa-error {
  padding: 20px 0;
}
</style>
