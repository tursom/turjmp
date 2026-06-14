<template>
  <div class="page-container replay-page">
    <div class="page-header">
      <div class="header-left">
        <el-button @click="router.push(`/sessions/${sessionId}`)">
          <el-icon><ArrowLeft /></el-icon>
          返回详情
        </el-button>
        <h2>会话回放 #{{ sessionId }}</h2>
      </div>
      <el-button
        v-if="downloadUrl"
        type="primary"
        plain
        @click="downloadRecording"
      >
        <el-icon><Download /></el-icon>
        下载录像
      </el-button>
    </div>

    <div v-if="loading" class="loading-container">
      <el-skeleton :rows="8" animated />
    </div>

    <div v-else-if="error && !available" class="error-container">
      <el-result icon="warning" title="录像不可用" :sub-title="error">
        <template #extra>
          <el-button type="primary" @click="loadReplay">重试</el-button>
        </template>
      </el-result>
    </div>

    <template v-else>
      <el-descriptions v-if="session" :column="3" border class="metadata">
        <el-descriptions-item label="用户 ID">{{ session.user_id }}</el-descriptions-item>
        <el-descriptions-item label="资产 ID">{{ session.asset_id }}</el-descriptions-item>
        <el-descriptions-item label="账号 ID">{{ session.account_id }}</el-descriptions-item>
        <el-descriptions-item label="协议">
          <el-tag>{{ session.protocol.toUpperCase() }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="开始时间">{{ formatDate(session.date_start) }}</el-descriptions-item>
        <el-descriptions-item label="结束时间">
          {{ session.date_end ? formatDate(session.date_end) : '仍在活跃' }}
        </el-descriptions-item>
        <el-descriptions-item label="录像路径" :span="3">
          <span class="recording-path">{{ recording?.recording_path || '—' }}</span>
        </el-descriptions-item>
      </el-descriptions>

      <div class="player-panel">
        <div
          ref="playerContainer"
          v-loading="playerLoading"
          class="player-container"
        />
      </div>

      <div class="replay-controls">
        <el-button-group>
          <el-button
            type="primary"
            :disabled="!available"
            @click="isPlaying ? pause() : play()"
          >
            <el-icon><component :is="isPlaying ? VideoPause : VideoPlay" /></el-icon>
            {{ isPlaying ? '暂停' : '播放' }}
          </el-button>
        </el-button-group>

        <div class="timeline">
          <span>{{ formatDuration(currentTime) }}</span>
          <el-slider
            :model-value="currentTime"
            :min="0"
            :max="duration || 0"
            :step="0.1"
            :disabled="!available || duration <= 0"
            :format-tooltip="formatDuration"
            @change="handleSeek"
          />
          <span>{{ formatDuration(duration) }}</span>
        </div>

        <el-select
          v-model="speedModel"
          class="speed-select"
          size="small"
          :disabled="!available"
          @change="remountPlayer"
        >
          <el-option
            v-for="option in speedOptions"
            :key="option"
            :label="`${option}x`"
            :value="option"
          />
        </el-select>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Download, VideoPause, VideoPlay } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useSessionReplay } from '@/composables/useSessionReplay'

const route = useRoute()
const router = useRouter()
const playerContainer = ref<HTMLElement | null>(null)
const sessionId = computed(() => Number(route.params.id))
const speedOptions = [0.5, 1, 1.5, 2, 4]

const {
  loading,
  playerLoading,
  error,
  session,
  recording,
  currentTime,
  duration,
  isPlaying,
  speed,
  downloadUrl,
  available,
  load,
  mount,
  play,
  pause,
  seek,
} = useSessionReplay(sessionId)

const speedModel = computed({
  get: () => speed.value,
  set: (value: number) => {
    speed.value = value
  },
})

function formatDate(dateStr: string): string {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleString()
}

function formatDuration(value: number): string {
  const safe = Number.isFinite(value) && value > 0 ? value : 0
  const totalSeconds = Math.floor(safe)
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${minutes}:${String(seconds).padStart(2, '0')}`
}

async function loadReplay() {
  await load()
  await nextTick()
  await remountPlayer()
}

async function remountPlayer() {
  if (!playerContainer.value || !available.value) return
  await mount(playerContainer.value)
}

async function handleSeek(value: number | number[]) {
  const target = Array.isArray(value) ? value[0] : value
  await seek(target)
}

function downloadRecording() {
  if (!downloadUrl.value) {
    ElMessage.warning('录像下载地址不可用')
    return
  }
  globalThis.open(downloadUrl.value, '_blank', 'noopener,noreferrer')
}

watch(
  () => route.params.id,
  () => {
    void loadReplay()
  },
)

onMounted(() => {
  void loadReplay()
})
</script>

<style scoped>
.replay-page {
  min-height: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.header-left h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  color: #303133;
}

.metadata {
  margin-bottom: 16px;
}

.recording-path {
  word-break: break-all;
}

.player-panel {
  background: #1f2329;
  border: 1px solid #303642;
  border-radius: 4px;
  padding: 12px;
}

.player-container {
  min-height: 420px;
}

.replay-controls {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-top: 16px;
}

.timeline {
  display: grid;
  grid-template-columns: 48px minmax(160px, 1fr) 48px;
  align-items: center;
  gap: 12px;
  flex: 1;
  min-width: 0;
  color: #606266;
}

.speed-select {
  width: 96px;
}

.loading-container,
.error-container {
  padding: 40px 0;
}

@media (max-width: 768px) {
  .page-header,
  .replay-controls {
    align-items: stretch;
    flex-direction: column;
  }

  .header-left {
    align-items: flex-start;
    flex-direction: column;
  }

  .timeline {
    width: 100%;
  }

  .speed-select {
    width: 100%;
  }
}
</style>
