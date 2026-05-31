<template>
  <div class="page-container">
    <!-- Back button -->
    <div class="back-row">
      <el-button @click="$router.push('/sessions')">
        <el-icon><ArrowLeft /></el-icon>
        返回会话
      </el-button>
    </div>

    <h2>会话详情 #{{ sessionId }}</h2>

    <!-- Loading -->
    <div v-if="loading" class="loading-container">
      <el-skeleton :rows="6" animated />
    </div>

    <!-- Error -->
    <div v-else-if="error" class="error-container">
      <el-result icon="error" title="加载会话失败" :sub-title="error">
        <template #extra>
          <el-button type="primary" @click="loadSession">重试</el-button>
        </template>
      </el-result>
    </div>

    <!-- Content -->
    <template v-else-if="session">
      <el-descriptions :column="2" border class="session-descriptions">
        <el-descriptions-item label="ID">
          {{ session.id }}
        </el-descriptions-item>
        <el-descriptions-item label="用户 ID">
          {{ session.user_id }}
        </el-descriptions-item>
        <el-descriptions-item label="资产 ID">
          {{ session.asset_id }}
        </el-descriptions-item>
        <el-descriptions-item label="账号 ID">
          {{ session.account_id }}
        </el-descriptions-item>
        <el-descriptions-item label="协议">
          <el-tag>{{ session.protocol.toUpperCase() }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="类型">
          {{ session.type }}
        </el-descriptions-item>
        <el-descriptions-item label="登录来源">
          <el-tag type="info" size="small">{{ session.login_from }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="远端地址">
          {{ session.remote_addr }}
        </el-descriptions-item>
        <el-descriptions-item label="录像路径" :span="2">
          <div class="recording-row">
            <span>{{ session.recording_path || '无' }}</span>
            <el-button
              v-if="session.recording_path"
              size="small"
              type="primary"
              plain
              :loading="recordingLoading"
              @click="openRecording"
            >
              打开录像
            </el-button>
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="开始时间">
          {{ formatDate(session.date_start) }}
        </el-descriptions-item>
        <el-descriptions-item label="结束时间">
          {{ session.date_end ? formatDate(session.date_end) : '仍在活跃' }}
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="session.is_finished ? 'info' : 'success'">
            {{ session.is_finished ? '已结束' : '活跃' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="持续时间">
          {{ computedDuration }}
        </el-descriptions-item>
        <el-descriptions-item label="创建时间">
          {{ formatDate(session.created_at) }}
        </el-descriptions-item>
        <el-descriptions-item label="更新时间">
          {{ formatDate(session.updated_at) }}
        </el-descriptions-item>
      </el-descriptions>

      <el-card class="command-card" shadow="never">
        <template #header>
          <div class="card-header">
            <span>命令记录</span>
            <el-button link type="primary" @click="loadCommands">刷新</el-button>
          </div>
        </template>
        <el-table v-loading="commandsLoading" :data="commands" stripe empty-text="暂无命令记录">
          <el-table-column label="时间" width="180">
            <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
          </el-table-column>
          <el-table-column prop="action" label="动作" width="120" />
          <el-table-column label="命令 / SQL" min-width="260">
            <template #default="{ row }">
              <code>{{ commandText(row.detail) }}</code>
            </template>
          </el-table-column>
          <el-table-column label="结果" width="160">
            <template #default="{ row }">{{ commandResult(row.detail) }}</template>
          </el-table-column>
        </el-table>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { ArrowLeft } from '@element-plus/icons-vue'
import * as sessionsApi from '@/api/sessions'
import type { AuditLog, Session } from '@/types'

const route = useRoute()

const sessionId = computed(() => Number(route.params.id))

const loading = ref(true)
const error = ref<string | null>(null)
const session = ref<Session | null>(null)
const commands = ref<AuditLog[]>([])
const commandsLoading = ref(false)
const recordingLoading = ref(false)

const computedDuration = computed(() => {
  if (!session.value) return '-'
  const start = dateMs(session.value.date_start)
  if (!start) return '-'
  const end = dateMs(session.value.date_end)
  if (!end) return '进行中'
  const diffMs = end - start
  if (diffMs < 0) return '-'
  const seconds = Math.floor(diffMs / 1000)
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60
  if (hours > 0) {
    return `${hours}小时 ${minutes}分 ${secs}秒`
  }
  if (minutes > 0) {
    return `${minutes}分 ${secs}秒`
  }
  return `${secs}秒`
})

function dateMs(dateStr: string | undefined | null): number | null {
  if (!dateStr) return null
  const ms = new Date(dateStr).getTime()
  return Number.isNaN(ms) ? null : ms
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr)
  return d.toLocaleString()
}

async function loadSession() {
  loading.value = true
  error.value = null
  try {
    session.value = await sessionsApi.get(sessionId.value)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '加载会话失败'
    error.value = msg
  } finally {
    loading.value = false
  }
}

async function loadCommands() {
  if (!sessionId.value) return
  commandsLoading.value = true
  try {
    commands.value = await sessionsApi.listCommands(sessionId.value)
  } finally {
    commandsLoading.value = false
  }
}

async function openRecording() {
  if (!sessionId.value) return
  recordingLoading.value = true
  try {
    const result = await sessionsApi.recording(sessionId.value)
    const target = result.download_url || result.url
    if (!result.available || !target) {
      ElMessage.warning('录像文件不可用')
      return
    }
    globalThis.open(target, '_blank', 'noopener,noreferrer')
  } catch (err: unknown) {
    ElMessage.error(err instanceof Error ? err.message : '打开录像失败')
  } finally {
    recordingLoading.value = false
  }
}

function parseDetail(detail: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(detail) as unknown
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {}
  } catch {
    return {}
  }
}

function commandText(detail: string): string {
  const parsed = parseDetail(detail)
  return String(parsed.sql ?? parsed.command ?? parsed.path ?? detail)
}

function commandResult(detail: string): string {
  const parsed = parseDetail(detail)
  if (parsed.error) return String(parsed.error)
  if (parsed.rows_affected !== undefined) return `${String(parsed.rows_affected)} 行`
  return '成功'
}

onMounted(() => {
  loadSession()
  loadCommands()
})
</script>

<style scoped>
.back-row {
  margin-bottom: 16px;
}

h2 {
  margin-bottom: 20px;
  font-size: 22px;
  color: #303133;
}

.session-descriptions {
  margin-top: 8px;
}

.recording-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.command-card {
  margin-top: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.loading-container,
.error-container {
  padding: 40px 0;
}
</style>
