<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue'
import { useTerminal } from '@/composables/useTerminal'
import { useTerminalWebSocket } from '@/composables/useTerminalWebSocket'

interface Props {
  wsUrl: string
  tabId: string
}

const props = defineProps<Props>()

const emit = defineEmits<{
  'status-change': [id: string, status: string]
  reconnect: [id: string]
}>()

const containerRef = ref<HTMLElement | null>(null)
let resizeObserver: ResizeObserver | null = null

const term = useTerminal()
const { status, connect, disconnect } = useTerminalWebSocket(term)

onMounted(() => {
  if (containerRef.value) {
    term.mount(containerRef.value)
  }
  connect(props.wsUrl)

  if (containerRef.value) {
    resizeObserver = new ResizeObserver(() => {
      term.fitAddon.value?.fit()
    })
    resizeObserver.observe(containerRef.value)
  }
})

onUnmounted(() => {
  resizeObserver?.disconnect()
})

watch(status, (newStatus) => {
  emit('status-change', props.tabId, newStatus)
})

watch(
  () => props.wsUrl,
  (url, previousUrl) => {
    if (!url || url === previousUrl) return
    disconnect()
    connect(url)
  },
)

defineExpose({
  disconnect,
  terminal: term.terminal,
  fitAddon: term.fitAddon,
})

function handleReconnect() {
  emit('reconnect', props.tabId)
}
</script>

<template>
  <div ref="containerRef" class="terminal-container">
    <!-- Connecting overlay -->
    <div v-if="status === 'connecting'" class="terminal-overlay">
      <el-icon class="is-loading" :size="32">
        <Loading />
      </el-icon>
      <span class="overlay-text">正在连接...</span>
    </div>

    <!-- Disconnected/Error overlay -->
    <div v-if="status === 'disconnected'" class="terminal-overlay terminal-overlay--disconnected">
      <span class="overlay-text">连接已断开</span>
      <el-button size="small" @click="handleReconnect">重新连接</el-button>
    </div>
  </div>
</template>

<style scoped>
.terminal-container {
  width: 100%;
  height: calc(100vh - 40px);
  background: #282a36;
  position: relative;
}

.terminal-overlay {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: #282a36;
  gap: 12px;
  z-index: 10;
}

.terminal-overlay--disconnected {
  background: rgba(40, 42, 54, 0.95);
}

.overlay-text {
  color: #a0a4b8;
  font-size: 14px;
}
</style>
