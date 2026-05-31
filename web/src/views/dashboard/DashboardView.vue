<template>
  <div class="page-container">
    <h2>Dashboard</h2>

    <!-- Loading state -->
    <div v-if="loading" class="loading-container">
      <el-skeleton :rows="6" animated />
    </div>

    <!-- Error state -->
    <div v-else-if="error" class="error-container">
      <el-result icon="error" title="Failed to load dashboard data" :sub-title="error">
        <template #extra>
          <el-button type="primary" @click="loadData">Retry</el-button>
        </template>
      </el-result>
    </div>

    <!-- Main content -->
    <template v-else>
      <!-- Stat cards -->
      <el-row :gutter="20" class="stat-row">
        <el-col :span="6">
          <el-card class="stat-card" shadow="hover">
            <div class="stat-content">
              <div class="stat-icon assets-icon">
                <el-icon :size="28"><Monitor /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-label">Total Assets</div>
                <div class="stat-value">{{ totalAssets }}</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stat-card" shadow="hover">
            <div class="stat-content">
              <div class="stat-icon sessions-icon">
                <el-icon :size="28"><Connection /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-label">Active Sessions</div>
                <div class="stat-value">{{ activeSessions }}</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stat-card" shadow="hover">
            <div class="stat-content">
              <div class="stat-icon today-icon">
                <el-icon :size="28"><Clock /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-label">Today's Sessions</div>
                <div class="stat-value">{{ todaySessions }}</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stat-card" shadow="hover">
            <div class="stat-content">
              <div class="stat-icon users-icon">
                <el-icon :size="28"><UserFilled /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-label">Active Users</div>
                <div class="stat-value">{{ uniqueUsers }}</div>
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>

      <!-- Recent sessions -->
      <el-card class="section-card" shadow="hover">
        <template #header>
          <div class="section-header">
            <span>Recent Sessions</span>
            <el-button type="primary" link @click="$router.push('/sessions')">
              View All
            </el-button>
          </div>
        </template>
        <el-table :data="recentSessions" stripe style="width: 100%">
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column prop="user_id" label="User" width="100" />
          <el-table-column prop="asset_id" label="Asset" width="100" />
          <el-table-column prop="protocol" label="Protocol" width="120" />
          <el-table-column label="Started" min-width="180">
            <template #default="{ row }">
              {{ formatDate(row.date_start) }}
            </template>
          </el-table-column>
          <el-table-column label="Status" width="110">
            <template #default="{ row }">
              <el-tag :type="row.is_finished ? 'info' : 'success'" size="small">
                {{ row.is_finished ? 'Ended' : 'Active' }}
              </el-tag>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <!-- Connection token -->
      <el-card v-if="canIssueConnectionTokens" class="section-card" shadow="hover">
        <template #header>
          <span>Generate Connection Token</span>
        </template>
        <el-form
          ref="tokenFormRef"
          :model="tokenForm"
          :rules="tokenRules"
          label-width="120px"
          @submit.prevent="handleGenerateToken"
        >
          <el-row :gutter="20">
            <el-col :span="8">
              <el-form-item label="Asset ID" prop="asset_id">
                <el-input-number
                  v-model="tokenForm.asset_id"
                  :min="1"
                  placeholder="Asset ID"
                  style="width: 100%"
                />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item label="Account ID" prop="account_id">
                <el-input-number
                  v-model="tokenForm.account_id"
                  :min="1"
                  placeholder="Account ID"
                  style="width: 100%"
                />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item label="Protocol" prop="protocol">
                <el-select v-model="tokenForm.protocol" placeholder="Select protocol" style="width: 100%">
                  <el-option label="SSH" value="ssh" />
                  <el-option label="RDP" value="rdp" />
                  <el-option label="VNC" value="vnc" />
                  <el-option label="Telnet" value="telnet" />
                  <el-option label="MySQL" value="mysql" />
                  <el-option label="PostgreSQL" value="postgresql" />
                  <el-option label="Redis" value="redis" />
                </el-select>
              </el-form-item>
            </el-col>
          </el-row>
          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="Connect Method">
                <el-select
                  v-model="tokenForm.connect_method"
                  placeholder="Optional"
                  clearable
                  style="width: 100%"
                >
                  <el-option label="Web CLI" value="web_cli" />
                  <el-option label="Web SFTP" value="web_sftp" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="Reusable">
                <el-switch v-model="tokenForm.is_reusable" />
              </el-form-item>
            </el-col>
          </el-row>
          <el-form-item>
            <el-button
              type="primary"
              native-type="submit"
              :loading="tokenLoading"
            >
              Generate Token
            </el-button>
          </el-form-item>
        </el-form>

        <div v-if="tokenResult" class="token-result">
          <el-alert
            title="Connection Token Generated"
            type="success"
            :closable="false"
            show-icon
          >
            <template #default>
              <div class="token-value">
                <el-input
                  :model-value="tokenResult.token"
                  readonly
                  size="large"
                >
                  <template #append>
                    <el-button @click="copyToken">
                      <el-icon><DocumentCopy /></el-icon>
                    </el-button>
                  </template>
                </el-input>
              </div>
              <p class="token-expires">
                Expires: {{ formatDate(tokenResult.expires_at) }}
              </p>
            </template>
          </el-alert>
        </div>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, reactive, onMounted, onUnmounted } from 'vue'
import {
  ElMessage,
  type FormInstance,
  type FormRules,
} from 'element-plus'
import {
  Monitor,
  Connection,
  Clock,
  UserFilled,
  DocumentCopy,
} from '@element-plus/icons-vue'
import * as sessionsApi from '@/api/sessions'
import * as tokensApi from '@/api/tokens'
import { useAuthStore } from '@/stores/auth'
import type { ConnectionTokenResult, Session } from '@/types'

const authStore = useAuthStore()
const loading = ref(true)
const error = ref<string | null>(null)
const canIssueConnectionTokens = computed(() => authStore.canAccess('connection_tokens'))

const totalAssets = ref(0)
const activeSessions = ref(0)
const todaySessions = ref(0)
const uniqueUsers = ref(0)
const recentSessions = ref<Session[]>([])
let summaryTimer: ReturnType<typeof globalThis.setInterval> | undefined

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  const d = new Date(dateStr)
  return d.toLocaleString()
}

async function loadData(showLoading = true) {
  if (showLoading) {
    loading.value = true
    error.value = null
  }
  try {
    const summary = await sessionsApi.dashboardSummary()
    totalAssets.value = summary.total_assets
    activeSessions.value = summary.active_sessions
    todaySessions.value = summary.today_sessions
    uniqueUsers.value = summary.active_users
    recentSessions.value = summary.recent_sessions
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to load dashboard data'
    if (showLoading) {
      error.value = msg
    }
  } finally {
    if (showLoading) {
      loading.value = false
    }
  }
}

// --- Token generation ---
const tokenFormRef = ref<FormInstance>()
const tokenLoading = ref(false)
const tokenResult = ref<ConnectionTokenResult | null>(null)

const tokenForm = reactive({
  asset_id: undefined as number | undefined,
  account_id: undefined as number | undefined,
  protocol: undefined as string | undefined,
  connect_method: undefined as string | undefined,
  is_reusable: false,
})

const tokenRules: FormRules = {
  asset_id: [{ required: true, message: 'Asset ID is required', trigger: 'blur' }],
  account_id: [{ required: true, message: 'Account ID is required', trigger: 'blur' }],
}

async function handleGenerateToken() {
  if (!tokenFormRef.value) return
  try {
    await tokenFormRef.value.validate()
  } catch {
    return
  }
  if (tokenForm.asset_id === undefined || tokenForm.account_id === undefined) return

  tokenLoading.value = true
  try {
    const result = await tokensApi.createConnectionToken({
      asset_id: tokenForm.asset_id,
      account_id: tokenForm.account_id,
      protocol: tokenForm.protocol,
      connect_method: tokenForm.connect_method,
      is_reusable: tokenForm.is_reusable,
    })
    tokenResult.value = result
    ElMessage.success('Token generated')
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to generate token'
    ElMessage.error(msg)
  } finally {
    tokenLoading.value = false
  }
}

async function copyToken() {
  if (!tokenResult.value) return
  try {
    await navigator.clipboard.writeText(tokenResult.value.token)
    ElMessage.success('Token copied to clipboard')
  } catch {
    ElMessage.warning('Failed to copy to clipboard')
  }
}

onMounted(() => {
  loadData()
  summaryTimer = globalThis.setInterval(() => {
    loadData(false)
  }, 10000)
})

onUnmounted(() => {
  if (summaryTimer !== undefined) {
    globalThis.clearInterval(summaryTimer)
  }
})
</script>

<style scoped>
h2 {
  margin-bottom: 20px;
  font-size: 22px;
  color: #303133;
}

.stat-row {
  margin-bottom: 20px;
}

.stat-card {
  cursor: default;
}

.stat-card :deep(.el-card__body) {
  padding: 20px;
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 16px;
}

.stat-icon {
  width: 56px;
  height: 56px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.assets-icon {
  background: #ecf5ff;
  color: #409eff;
}

.sessions-icon {
  background: #f0f9eb;
  color: #67c23a;
}

.today-icon {
  background: #fdf6ec;
  color: #e6a23c;
}

.users-icon {
  background: #fef0f0;
  color: #f56c6c;
}

.stat-info {
  flex: 1;
  min-width: 0;
}

.stat-label {
  font-size: 13px;
  color: #909399;
  margin-bottom: 4px;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: #303133;
  line-height: 1.2;
}

.section-card {
  margin-bottom: 20px;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 16px;
  font-weight: 600;
}

.loading-container {
  padding: 40px 0;
}

.error-container {
  padding: 40px 0;
}

.token-result {
  margin-top: 16px;
}

.token-value {
  margin-top: 8px;
}

.token-expires {
  margin-top: 8px;
  font-size: 13px;
  color: #67c23a;
}
</style>
