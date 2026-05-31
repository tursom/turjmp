<template>
  <div class="page-container">
    <h2>会话</h2>

    <div class="filter-bar">
      <el-radio-group v-model="statusFilter" @change="onFilterChange">
        <el-radio-button label="all">全部会话</el-radio-button>
        <el-radio-button label="active">活跃</el-radio-button>
        <el-radio-button label="ended">已结束</el-radio-button>
      </el-radio-group>
      <el-input
        v-model="searchQuery"
        placeholder="搜索协议、来源或 ID..."
        clearable
        class="search-input"
        @keyup.enter="onFilterChange"
        @clear="onFilterChange"
      />
      <el-input-number
        v-model="userFilter"
        :min="1"
        controls-position="right"
        placeholder="用户 ID"
        class="id-filter"
        @change="onFilterChange"
      />
      <el-input-number
        v-model="assetFilter"
        :min="1"
        controls-position="right"
        placeholder="资产 ID"
        class="id-filter"
        @change="onFilterChange"
      />
      <el-date-picker
        v-model="dateRange"
        type="daterange"
        start-placeholder="开始日期"
        end-placeholder="结束日期"
        value-format="YYYY-MM-DD"
        class="date-filter"
        @change="onFilterChange"
      />
      <el-button type="primary" @click="onFilterChange">搜索</el-button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="loading-container">
      <el-skeleton :rows="6" animated />
    </div>

    <!-- Error -->
    <div v-else-if="error" class="error-container">
      <el-result icon="error" title="加载会话失败" :sub-title="error">
        <template #extra>
          <el-button type="primary" @click="loadSessions">重试</el-button>
        </template>
      </el-result>
    </div>

    <!-- Empty -->
    <div v-else-if="sessions.length === 0" class="empty-container">
      <el-empty description="未找到会话">
        <el-button v-if="statusFilter !== 'all'" @click="statusFilter = 'all'">
          显示全部
        </el-button>
      </el-empty>
    </div>

    <!-- Table -->
    <el-table
      v-else
      :data="sessions"
      stripe
      border
      style="width: 100%"
    >
      <el-table-column prop="id" label="ID" width="80" sortable />
      <el-table-column prop="user_id" label="用户 ID" width="100" />
      <el-table-column prop="asset_id" label="资产 ID" width="100" />
      <el-table-column prop="protocol" label="协议" width="110" />
      <el-table-column prop="type" label="类型" width="100" />
      <el-table-column prop="login_from" label="登录来源" width="130">
        <template #default="{ row }">
          <el-tag size="small" type="info">{{ row.login_from }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="remote_addr" label="远端地址" width="150" />
      <el-table-column label="状态" width="110">
        <template #default="{ row }">
          <el-tag :type="row.is_finished ? 'info' : 'success'" size="small">
            {{ row.is_finished ? '已结束' : '活跃' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="开始时间" min-width="180">
        <template #default="{ row }">
          {{ formatDate(row.date_start) }}
        </template>
      </el-table-column>
      <el-table-column label="结束时间" min-width="180">
        <template #default="{ row }">
          {{ row.date_end ? formatDate(row.date_end) : '-' }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="180" fixed="right">
        <template #default="{ row }">
          <el-button type="primary" link @click="$router.push(`/sessions/${row.id}`)">
            详情
          </el-button>
          <el-button
            v-if="canForceFinish && !row.is_finished"
            type="danger"
            link
            @click="handleForceFinish(row)"
          >
            断开
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as sessionsApi from '@/api/sessions'
import type { Session } from '@/types'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const loading = ref(true)
const error = ref<string | null>(null)
const sessions = ref<Session[]>([])
const statusFilter = ref<'all' | 'active' | 'ended'>('all')
const searchQuery = ref('')
const userFilter = ref<number | undefined>()
const assetFilter = ref<number | undefined>()
const dateRange = ref<[string, string] | ''>('')
let refreshTimer: ReturnType<typeof globalThis.setInterval> | undefined
let reconnectTimer: ReturnType<typeof globalThis.setTimeout> | undefined
let sessionSocket: InstanceType<typeof globalThis.WebSocket> | undefined
let streamGeneration = 0
let streamWarningShown = false

const canForceFinish = computed(() => authStore.canAccess('session_force_finish'))

function formatDate(dateStr: string): string {
  const d = new Date(dateStr)
  return d.toLocaleString()
}

function onFilterChange() {
  loadSessions()
  void connectSessionStream()
}

async function loadSessions() {
  loading.value = true
  error.value = null
  try {
    const [dateFrom, dateTo] = Array.isArray(dateRange.value) ? dateRange.value : ['', '']
    sessions.value = await sessionsApi.list({
      status: statusFilter.value,
      search: searchQuery.value || undefined,
      user_id: userFilter.value || undefined,
      asset_id: assetFilter.value || undefined,
      date_from: dateFrom || undefined,
      date_to: dateTo || undefined,
    })
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '加载会话失败'
    error.value = msg
  } finally {
    loading.value = false
  }
}

function sessionQueryParams(): InstanceType<typeof globalThis.URLSearchParams> {
  const [dateFrom, dateTo] = Array.isArray(dateRange.value) ? dateRange.value : ['', '']
  const params = new globalThis.URLSearchParams()
  params.set('status', statusFilter.value)
  if (searchQuery.value) params.set('search', searchQuery.value)
  if (userFilter.value) params.set('user_id', String(userFilter.value))
  if (assetFilter.value) params.set('asset_id', String(assetFilter.value))
  if (dateFrom) params.set('date_from', dateFrom)
  if (dateTo) params.set('date_to', dateTo)
  return params
}

async function connectSessionStream() {
  streamGeneration += 1
  const generation = streamGeneration
  if (reconnectTimer !== undefined) {
    globalThis.clearTimeout(reconnectTimer)
    reconnectTimer = undefined
  }
  sessionSocket?.close()
  let socket: InstanceType<typeof globalThis.WebSocket>
  try {
    const streamToken = await sessionsApi.createStreamToken()
    const scheme = globalThis.location.protocol === 'https:' ? 'wss' : 'ws'
    const params = sessionQueryParams()
    params.set('stream_token', streamToken.token)
    const url = `${scheme}://${globalThis.location.host}/api/v1/sessions/stream?${params}`
    socket = new globalThis.WebSocket(url)
  } catch (err) {
    if (generation === streamGeneration) {
      if (!streamWarningShown) {
        streamWarningShown = true
        ElMessage.warning(err instanceof Error ? err.message : '会话实时流不可用')
      }
      scheduleSessionStreamReconnect()
    }
    return
  }
  sessionSocket = socket
  sessionSocket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data) as { type?: string; sessions?: Session[] }
      if (payload.type === 'sessions' && Array.isArray(payload.sessions)) {
        sessions.value = payload.sessions
        loading.value = false
        error.value = null
        streamWarningShown = false
      }
    } catch {
      // Ignore malformed stream messages and keep the last known list.
    }
  }
  sessionSocket.onerror = () => {
    sessionSocket?.close()
  }
  sessionSocket.onclose = () => {
    if (generation === streamGeneration) {
      scheduleSessionStreamReconnect()
    }
  }
}

function scheduleSessionStreamReconnect() {
  if (reconnectTimer !== undefined) {
    return
  }
  reconnectTimer = globalThis.setTimeout(async () => {
    reconnectTimer = undefined
    await loadSessions()
    await connectSessionStream()
  }, 5000)
}

async function handleForceFinish(session: Session) {
  try {
    await ElMessageBox.confirm(
      `确认强制断开会话 #${session.id} 吗？`,
      '确认断开',
      { confirmButtonText: '断开', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  try {
    const updated = await sessionsApi.forceFinish(session.id)
    sessions.value = sessions.value.map((item) => (item.id === updated.id ? updated : item))
    ElMessage.success(`会话 #${session.id} 已标记为断开`)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '断开会话失败')
  }
}

onMounted(() => {
  loadSessions()
  void connectSessionStream()
  refreshTimer = globalThis.setInterval(() => {
    if (statusFilter.value === 'active' && sessionSocket?.readyState !== globalThis.WebSocket.OPEN) {
      loadSessions()
    }
  }, 10000)
})

onUnmounted(() => {
  streamGeneration += 1
  if (refreshTimer !== undefined) {
    globalThis.clearInterval(refreshTimer)
  }
  if (reconnectTimer !== undefined) {
    globalThis.clearTimeout(reconnectTimer)
  }
  sessionSocket?.close()
})
</script>

<style scoped>
h2 {
  margin-bottom: 16px;
  font-size: 22px;
  color: #303133;
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
}

.search-input {
  width: 260px;
}

.id-filter {
  width: 130px;
}

.date-filter {
  width: 260px;
}

.loading-container,
.error-container,
.empty-container {
  padding: 40px 0;
}
</style>
