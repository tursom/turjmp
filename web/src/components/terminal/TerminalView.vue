<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import type { Terminal } from '@xterm/xterm'
import type { FitAddon } from '@xterm/addon-fit'
import { ElMessage, ElMessageBox } from 'element-plus'
import { MAX_TERMINAL_TABS, useTerminalTabs } from '@/composables/useTerminalTabs'
import * as tokensApi from '@/api/tokens'
import { buildWebTerminalWsUrl } from '@/utils/terminal'
import TerminalToolbar from './TerminalToolbar.vue'
import TerminalTab from './TerminalTab.vue'
import TerminalConnectDialog from './TerminalConnectDialog.vue'
import type { ConnectParams } from '@/types'

interface Props {
  preselectedAssetId?: number
  preselectedAccountId?: number
  preselectedProtocol?: string
  autoConnect?: boolean
}

const props = defineProps<Props>()

interface ConnectedResult {
  wsUrl: string
  params: ConnectParams
  assetName: string
  accountName: string
  platformType: string
}

interface TabRef {
  disconnect: () => void
  terminal: Terminal | null
  fitAddon: FitAddon | null
}

const { tabs, activeTabId, addTab, closeTab, switchTab } = useTerminalTabs()
const dialogVisible = ref(false)
const dialogAssetId = ref<number | undefined>(undefined)
const dialogAccountId = ref<number | undefined>(undefined)
const dialogProtocol = ref<string | undefined>(undefined)
const dialogAutoConnect = ref(false)
const tabRefs = ref<Map<string, TabRef>>(new Map())
const tabWsUrls = ref<Record<string, string>>({})

function openDialog(): void {
  openConnectDialog()
}

function openConnectDialog(
  assetId?: number,
  accountId?: number,
  protocol?: string,
  autoConnect = false,
): void {
  dialogAssetId.value = assetId
  dialogAccountId.value = accountId
  dialogProtocol.value = protocol
  dialogAutoConnect.value = autoConnect
  dialogVisible.value = true
}

function handleConnected(result: ConnectedResult): void {
  const tabId = addTab({
    assetId: result.params.assetId,
    accountId: result.params.accountId,
    assetName: result.assetName,
    accountName: result.accountName,
    protocol: result.params.protocol,
    platformType: result.platformType,
    connectMethod: result.params.connectMethod,
    status: 'connecting',
  })
  if (tabId) {
    tabWsUrls.value[tabId] = result.wsUrl
  } else {
    ElMessage.warning(`最多同时打开 ${MAX_TERMINAL_TABS} 个终端`)
  }
}

async function handleReconnect(id: string): Promise<void> {
  const tab = tabs.value.find((t) => t.id === id)
  if (!tab || tab.status === 'connecting') return

  try {
    tab.status = 'connecting'
    tab.duration = 0
    tab.connectedAt = null
    const result = await tokensApi.createConnectionToken({
      asset_id: tab.assetId,
      account_id: tab.accountId,
      protocol: tab.protocol,
      connect_method: tab.connectMethod,
    })
    tabWsUrls.value[id] = buildWebTerminalWsUrl(tab.protocol, result.token)
  } catch (err) {
    tab.status = 'disconnected'
    ElMessage.error(err instanceof Error ? err.message : '重新连接失败')
  }
}

async function handleCloseTab(id: string): Promise<void> {
  const tab = tabs.value.find((t) => t.id === id)
  if (tab?.status === 'connected') {
    try {
      await ElMessageBox.confirm('当前会话仍在运行，确定要关闭吗？')
    } catch {
      return
    }
    const tabRef = tabRefs.value.get(id)
    tabRef?.disconnect()
    tab.status = 'disconnected'
  }
  closeTab(id)
  delete tabWsUrls.value[id]
  tabRefs.value.delete(id)
}

function handleDisconnect(id: string): void {
  const tabRef = tabRefs.value.get(id)
  tabRef?.disconnect()
  const tab = tabs.value.find((t) => t.id === id)
  if (tab) {
    tab.status = 'disconnected'
  }
}

function handleStatusChange(id: string, newStatus: string): void {
  const tab = tabs.value.find((t) => t.id === id)
  if (tab) {
    tab.status = newStatus as 'connecting' | 'connected' | 'disconnected'
    if (newStatus === 'connected' && !tab.connectedAt) {
      tab.connectedAt = new Date().toISOString()
    }
  }
}

// Duration timer: increment duration for each connected tab every second
let durationTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  if (props.preselectedAssetId !== undefined) {
    openConnectDialog(
      props.preselectedAssetId,
      props.preselectedAccountId,
      props.preselectedProtocol,
      props.autoConnect === true,
    )
  }

  durationTimer = setInterval(() => {
    for (const tab of tabs.value) {
      if (tab.status === 'connected') {
        tab.duration++
      }
    }
  }, 1000)

  window.addEventListener('beforeunload', handleBeforeUnload)
})

onUnmounted(() => {
  if (durationTimer) clearInterval(durationTimer)
  window.removeEventListener('beforeunload', handleBeforeUnload)
})

function handleBeforeUnload(e: BeforeUnloadEvent) {
  const hasActive = tabs.value.some((t) => t.status === 'connected')
  if (hasActive) {
    e.preventDefault()
    e.returnValue = ''
  }
}

function handleCopy(id: string): void {
  const tabRef = tabRefs.value.get(id)
  const selection = tabRef?.terminal?.getSelection()
  if (selection) {
    navigator.clipboard.writeText(selection).catch(() => {})
  }
}

function handlePaste(id: string): void {
  const tabRef = tabRefs.value.get(id)
  navigator.clipboard
    .readText()
    .then((text) => {
      tabRef?.terminal?.paste(text)
    })
    .catch(() => {})
}

function setTabRef(id: string, el: unknown): void {
  if (el) {
    tabRefs.value.set(id, el as TabRef)
  } else {
    tabRefs.value.delete(id)
  }
}
</script>

<template>
  <div class="terminal-view">
    <TerminalToolbar
      :tabs="tabs"
      :active-tab-id="activeTabId"
      @update:active-tab-id="switchTab"
      @add-tab="openDialog"
      @close-tab="handleCloseTab"
      @disconnect="handleDisconnect"
      @copy="handleCopy"
      @paste="handlePaste"
    />
    <div class="terminal-panels">
      <TerminalTab
        v-for="tab in tabs"
        v-show="tab.id === activeTabId"
        :key="tab.id"
        :ref="(el: unknown) => setTabRef(tab.id, el)"
        :ws-url="tabWsUrls[tab.id] ?? ''"
        :tab-id="tab.id"
        @reconnect="handleReconnect"
        @status-change="handleStatusChange"
      />
      <div v-if="tabs.length === 0" class="terminal-empty">
        <el-empty description="点击 + 新建终端连接" />
      </div>
    </div>
    <TerminalConnectDialog
      :visible="dialogVisible"
      :preselected-asset-id="dialogAssetId"
      :preselected-account-id="dialogAccountId"
      :preselected-protocol="dialogProtocol"
      :auto-connect="dialogAutoConnect"
      @update:visible="dialogVisible = $event"
      @connected="handleConnected"
    />
  </div>
</template>

<style scoped>
.terminal-view {
  display: flex;
  flex-direction: column;
  height: 100vh;
  width: 100vw;
  background: #1a1b26;
  color: #e0e0e0;
}

.terminal-panels {
  flex: 1;
  overflow: hidden;
  position: relative;
}

.terminal-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
}

.terminal-empty :deep(.el-empty__description) {
  color: #6272a4;
}
</style>
