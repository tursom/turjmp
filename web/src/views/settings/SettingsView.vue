<template>
  <div class="page-container">
    <div class="page-header">
      <h2>系统设置</h2>
      <el-button type="primary" plain @click="router.push('/settings/ssh-fingerprint')">
        SSH 指纹
      </el-button>
    </div>

    <div v-if="loading" v-loading="loading" class="loading-placeholder" />

    <el-alert
      v-else-if="error"
      :title="error"
      type="error"
      show-icon
      :closable="false"
    />

    <el-empty v-else-if="!categories.length" description="暂无系统设置" />

    <el-tabs v-else v-model="activeCategory" type="border-card">
      <el-tab-pane
        v-for="category in categories"
        :key="category"
        :label="formatCategoryName(category)"
        :name="category"
      >
        <el-form label-position="top" size="default">
          <el-form-item
            v-for="setting in settingsByCategory[category]"
            :key="setting.key"
          >
            <template #label>
              <span class="field-label">{{ displaySettingLabel(setting) }}</span>
              <el-tooltip
                v-if="setting.description"
                :content="displaySettingDescription(setting)"
                placement="top"
                effect="dark"
              >
                <el-icon class="help-icon"><QuestionFilled /></el-icon>
              </el-tooltip>
            </template>

            <!-- text -->
            <div v-if="setting.input_type === 'text'" class="field-row">
              <el-input
                v-model="fieldValues[setting.key]"
                :disabled="isSaving(setting.key)"
                class="field-input"
                @input="markDirty(setting.key)"
              />
              <el-button
                type="primary"
                size="default"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings || !isDirty(setting.key)"
                @click="saveField(setting)"
              >
                保存
              </el-button>
            </div>

            <!-- number -->
            <div v-else-if="setting.input_type === 'number'" class="field-row">
              <el-input-number
                v-model="fieldValues[setting.key]"
                :disabled="isSaving(setting.key)"
                class="field-input"
                @change="markDirty(setting.key)"
              />
              <el-button
                type="primary"
                size="default"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings || !isDirty(setting.key)"
                @click="saveField(setting)"
              >
                保存
              </el-button>
            </div>

            <!-- select -->
            <div v-else-if="setting.input_type === 'select'" class="field-row">
              <el-select
                v-model="fieldValues[setting.key]"
                :disabled="isSaving(setting.key)"
                class="field-input"
                @change="markDirty(setting.key)"
              >
                <el-option
                  v-for="opt in parseSelectOptions(setting.options, setting.key)"
                  :key="opt.value"
                  :label="opt.label"
                  :value="opt.value"
                />
              </el-select>
              <el-button
                type="primary"
                size="default"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings || !isDirty(setting.key)"
                @click="saveField(setting)"
              >
                保存
              </el-button>
            </div>

            <!-- toggle (auto-save) -->
            <div v-else-if="setting.input_type === 'toggle'" class="field-row">
              <el-switch
                v-model="fieldValues[setting.key]"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings"
                active-text="启用"
                inactive-text="停用"
                @change="autoSaveToggle(setting)"
              />
            </div>

            <!-- secret -->
            <div v-else-if="setting.input_type === 'secret'" class="field-row">
              <el-input
                v-model="fieldValues[setting.key]"
                type="password"
                show-password
                :disabled="isSaving(setting.key)"
                class="field-input"
                placeholder="输入新值以修改"
                @input="markDirty(setting.key)"
              />
              <el-button
                type="primary"
                size="default"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings || !isDirty(setting.key)"
                @click="saveSecretField(setting)"
              >
                保存
              </el-button>
            </div>
          </el-form-item>
        </el-form>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import * as settingsApi from '@/api/settings'
import { useAppStore } from '@/stores/app'
import { useAuthStore } from '@/stores/auth'
import { parseSettingString } from '@/utils/branding'
import type { Setting, SettingsByCategory } from '@/types'

interface SelectOption {
  label: string
  value: string
}

const categoryLabels: Record<string, string> = {
  branding: '品牌',
  proxy: '代理',
  recording: '录像',
  security: '安全',
  sftp: '文件传输',
  notification: '通知',
  auth: '认证',
}

const settingLabels: Record<string, string> = {
  'branding.logo_url': 'Logo 地址',
  'branding.site_name': '站点名称',
  'branding.theme_color': '主题色',
  'proxy.session.max_duration': '会话最长持续时间',
  'proxy.ssh.idle_timeout': 'SSH 空闲超时',
  'proxy.ssh.max_connections': 'SSH 最大连接数',
  'proxy.db.max_connections': 'DB 最大连接数',
  'proxy.db.idle_timeout': 'DB 空闲超时',
  'proxy.rdp.max_connections': 'RDP 最大连接数',
  'proxy.rdp.idle_timeout': 'RDP 空闲超时',
  'recording.local.path': '本地录像路径',
  'recording.oss.access_key': 'OSS 访问密钥',
  'recording.oss.bucket': 'OSS 存储桶',
  'recording.oss.endpoint': 'OSS 接入点',
  'recording.oss.secret_key': 'OSS 密钥',
  'recording.s3.access_key': 'S3 访问密钥',
  'recording.s3.bucket': 'S3 存储桶',
  'recording.s3.endpoint': 'S3 接入点',
  'recording.s3.secret_key': 'S3 密钥',
  'recording.storage': '录像存储',
  'sftp.max_file_size': 'SFTP 最大文件大小',
  'sftp.deny_paths': 'SFTP 禁止路径',
  'notification.smtp.host': 'SMTP 主机',
  'notification.smtp.port': 'SMTP 端口',
  'notification.smtp.username': 'SMTP 用户名',
  'notification.smtp.password': 'SMTP 密码',
  'notification.smtp.from': 'SMTP 发件人',
  'notification.email.template': '邮件模板',
  'security.login_failure_lock_enabled': '登录失败锁定',
  'security.login_failure_lock_minutes': '登录失败锁定分钟数',
  'security.login_failure_threshold': '登录失败阈值',
  'security.mfa_required': '强制 MFA',
  'security.password_min_length': '密码最小长度',
  'security.session_timeout': '会话超时',
  'auth.ldap.enabled': '启用 LDAP',
  'auth.ldap.url': 'LDAP 地址',
  'auth.ldap.bind_dn': 'LDAP 绑定 DN',
  'auth.ldap.bind_password': 'LDAP 绑定密码',
  'auth.ldap.user_search_base': 'LDAP 搜索基准',
  'auth.oauth.enabled': '启用 OAuth',
  'auth.oauth.client_id': 'OAuth Client ID',
  'auth.oauth.client_secret': 'OAuth Client Secret',
  'auth.oauth.auth_url': 'OAuth 授权地址',
  'auth.oauth.token_url': 'OAuth Token 地址',
  'auth.oauth.scopes': 'OAuth 权限范围',
}

const settingDescriptions: Record<string, string> = {
  'branding.logo_url': '自定义 Logo 地址',
  'branding.site_name': '页面可见的站点名称',
  'branding.theme_color': '主主题色',
  'proxy.session.max_duration': '代理会话最长持续时间（秒）',
  'proxy.ssh.idle_timeout': 'SSH 空闲超时时间（秒）',
  'proxy.ssh.max_connections': 'SSH 最大并发连接数',
  'proxy.db.max_connections': '数据库代理最大并发连接数',
  'proxy.db.idle_timeout': '数据库空闲超时时间（秒）',
  'proxy.rdp.max_connections': 'RDP 最大并发连接数',
  'proxy.rdp.idle_timeout': 'RDP 空闲超时时间（秒）',
  'recording.local.path': '本地录像目录',
  'recording.oss.access_key': 'OSS 访问密钥',
  'recording.oss.bucket': 'OSS 存储桶名称',
  'recording.oss.endpoint': 'OSS 接入点',
  'recording.oss.secret_key': 'OSS 密钥',
  'recording.s3.access_key': 'S3 访问密钥',
  'recording.s3.bucket': 'S3 存储桶名称',
  'recording.s3.endpoint': 'S3 或 MinIO 接入点',
  'recording.s3.secret_key': 'S3 密钥',
  'recording.storage': '录像存储后端',
  'sftp.max_file_size': 'SFTP 文件大小上限',
  'sftp.deny_paths': 'SFTP 禁止访问的路径',
  'notification.smtp.host': 'SMTP 服务器地址',
  'notification.smtp.port': 'SMTP 服务器端口',
  'notification.smtp.username': 'SMTP 用户名',
  'notification.smtp.password': 'SMTP 密码',
  'notification.smtp.from': '默认发件人地址',
  'notification.email.template': '默认通知邮件模板',
  'security.login_failure_lock_enabled': '重复登录失败后锁定用户',
  'security.login_failure_lock_minutes': '重复失败后的锁定时长',
  'security.login_failure_threshold': '触发锁定前允许的登录失败次数',
  'security.mfa_required': '要求所有用户启用 MFA',
  'security.password_min_length': '密码最小长度',
  'security.session_timeout': '最大会话持续时间（秒）',
  'auth.ldap.enabled': '启用 LDAP 认证',
  'auth.ldap.url': 'LDAP 服务器地址',
  'auth.ldap.bind_dn': 'LDAP 绑定 DN',
  'auth.ldap.bind_password': 'LDAP 绑定密码',
  'auth.ldap.user_search_base': 'LDAP 用户搜索基准 DN',
  'auth.oauth.enabled': '启用 OAuth 认证',
  'auth.oauth.client_id': 'OAuth 客户端 ID',
  'auth.oauth.client_secret': 'OAuth 客户端密钥',
  'auth.oauth.auth_url': 'OAuth 授权端点',
  'auth.oauth.token_url': 'OAuth Token 端点',
  'auth.oauth.scopes': 'OAuth 权限范围，逗号分隔',
}

const selectValueLabels: Record<string, Record<string, string>> = {
  'recording.storage': {
    local: '本地',
    s3: 'S3',
    oss: 'OSS',
    cos: 'COS',
  },
}

const loading = ref(false)
const error = ref('')
const settingsByCategory = ref<SettingsByCategory>({})
const activeCategory = ref('')
const router = useRouter()
const route = useRoute()
const appStore = useAppStore()
const authStore = useAuthStore()
const canUpdateSettings = computed(() => authStore.canAccess('setting_update'))

const fieldValues = reactive<Record<string, string | number | boolean>>({})
const originalValues: Record<string, string> = {}
const dirtyFields = reactive(new Set<string>())
const savingFields = reactive(new Set<string>())

const categories = computed(() => Object.keys(settingsByCategory.value))

function translateSelectLabel(settingKey: string, value: string, fallback: string): string {
  return selectValueLabels[settingKey]?.[value] ?? fallback
}

function parseSelectOptions(raw: string | undefined, settingKey: string): SelectOption[] {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed) || parsed.length === 0) return []
    if (typeof parsed[0] === 'object' && parsed[0] !== null) {
      return parsed.map((item: Record<string, unknown>, idx: number) => ({
        label: translateSelectLabel(
          settingKey,
          String(item.value ?? item.label ?? String(idx)),
          String(item.label ?? item.value ?? String(idx)),
        ),
        value: String(item.value ?? item.label ?? String(idx)),
      }))
    }
    return parsed.map((item: unknown) => ({
      label: translateSelectLabel(settingKey, String(item), String(item)),
      value: String(item),
    }))
  } catch {
    return raw.split(',').map((s) => ({
      label: translateSelectLabel(settingKey, s.trim(), s.trim()),
      value: s.trim(),
    }))
  }
}

function formatCategoryName(category: string): string {
  return categoryLabels[category] ?? category
}

function displaySettingLabel(setting: Setting): string {
  return settingLabels[setting.key] ?? setting.label
}

function displaySettingDescription(setting: Setting): string {
  return settingDescriptions[setting.key] ?? setting.description
}

function isSaving(key: string): boolean {
  return savingFields.has(key)
}

function isDirty(key: string): boolean {
  return dirtyFields.has(key)
}

function markDirty(key: string): void {
  dirtyFields.add(key)
}

function parseSettingValue(raw: string): unknown {
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}

function initDisplayValue(setting: Setting): string | number | boolean {
  const parsed = parseSettingValue(setting.value)
  switch (setting.input_type) {
    case 'toggle':
      return parsed === true || parsed === 'true'
    case 'number':
      return Number(parsed) || 0
    case 'secret':
      return typeof parsed === 'string' ? parsed : String(parsed ?? '')
    default:
      return typeof parsed === 'string' ? parsed : String(parsed ?? '')
  }
}

async function fetchSettings(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const data = await settingsApi.list()
    settingsByCategory.value = data

    // Flatten all settings and initialize display values
    const allSettings = Object.values(data).flat()
    for (const setting of allSettings) {
      const displayValue = initDisplayValue(setting)
      fieldValues[setting.key] = displayValue
      originalValues[setting.key] = String(displayValue)
    }

    // Set default active tab to the first category
    const catKeys = Object.keys(data)
    if (catKeys.length > 0) {
      activeCategory.value = catKeys[0]
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载系统设置失败'
  } finally {
    loading.value = false
  }
}

async function saveField(setting: Setting): Promise<void> {
  if (!canUpdateSettings.value) return
  const key = setting.key
  if (savingFields.has(key)) return

  savingFields.add(key)
  try {
    const rawValue = String(fieldValues[key])
    await settingsApi.update(key, rawValue)
    originalValues[key] = rawValue
    dirtyFields.delete(key)
    if (key === 'branding.site_name') {
      appStore.setSiteName(parseSettingString(rawValue), route.meta?.title as string | undefined)
    }
    ElMessage.success(`已保存“${displaySettingLabel(setting)}”`)
  } catch (err) {
    ElMessage.error(
      err instanceof Error ? err.message : `保存“${displaySettingLabel(setting)}”失败`,
    )
  } finally {
    savingFields.delete(key)
  }
}

async function saveSecretField(setting: Setting): Promise<void> {
  if (!canUpdateSettings.value) return
  const key = setting.key
  if (savingFields.has(key)) return

  savingFields.add(key)
  try {
    const rawValue = dirtyFields.has(key)
      ? String(fieldValues[key])
      : ''
    await settingsApi.update(key, rawValue)
    // After save, reset display to empty placeholder
    fieldValues[key] = ''
    dirtyFields.delete(key)
    originalValues[key] = '******'
    ElMessage.success(`已保存“${displaySettingLabel(setting)}”`)
  } catch (err) {
    ElMessage.error(
      err instanceof Error ? err.message : `保存“${displaySettingLabel(setting)}”失败`,
    )
  } finally {
    savingFields.delete(key)
  }
}

async function autoSaveToggle(setting: Setting): Promise<void> {
  if (!canUpdateSettings.value) return
  const key = setting.key
  if (savingFields.has(key)) return

  savingFields.add(key)
  try {
    const rawValue = fieldValues[key] ? 'true' : 'false'
    await settingsApi.update(key, rawValue)
    originalValues[key] = rawValue
    dirtyFields.delete(key)
    ElMessage.success(`“${displaySettingLabel(setting)}”已更新`)
  } catch (err) {
    // Revert on failure
    if (originalValues[key] !== undefined) {
      fieldValues[key] = originalValues[key] === 'true'
    }
    ElMessage.error(
      err instanceof Error ? err.message : `更新“${displaySettingLabel(setting)}”失败`,
    )
  } finally {
    savingFields.delete(key)
  }
}

onMounted(() => {
  fetchSettings()
})
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.page-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.loading-placeholder {
  min-height: 200px;
}

.field-label {
  font-weight: 500;
}

.help-icon {
  margin-left: 4px;
  font-size: 14px;
  color: var(--el-color-info);
  cursor: help;
  vertical-align: middle;
}

.field-row {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
}

.field-input {
  flex: 1;
  max-width: 480px;
}
</style>
