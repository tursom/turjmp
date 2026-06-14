<template>
  <div class="native-panel">
    <el-alert
      v-if="!canGenerate"
      title="当前账号缺少生成原生连接信息所需权限"
      type="warning"
      :closable="false"
      class="panel-alert"
    />

    <el-alert
      v-else-if="protocolOptions.length === 0"
      title="该资产暂无可用的 SSH/MySQL/PostgreSQL 原生连接协议"
      type="info"
      :closable="false"
      class="panel-alert"
    />

    <template v-else>
      <el-form
        :model="form"
        label-width="96px"
        class="native-form"
        @submit.prevent="generateConnection"
      >
        <el-row :gutter="16">
          <el-col :xs="24" :sm="12" :md="8">
            <el-form-item label="协议">
              <el-select v-model="form.protocol" placeholder="选择协议" style="width: 100%">
                <el-option
                  v-for="protocol in protocolOptions"
                  :key="protocol"
                  :label="protocolLabel(protocol)"
                  :value="protocol"
                />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8">
            <el-form-item label="账号">
              <el-select
                v-model="form.accountId"
                placeholder="选择账号"
                :loading="accountsLoading"
                style="width: 100%"
              >
                <el-option
                  v-for="account in accountOptions"
                  :key="account.id"
                  :label="accountLabel(account)"
                  :value="account.id"
                />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8">
            <el-form-item label="代理主机">
              <el-input
                v-model="form.proxyHost"
                placeholder="默认使用后端配置"
                clearable
              />
            </el-form-item>
          </el-col>
        </el-row>

        <el-form-item>
          <el-button
            type="primary"
            native-type="submit"
            :loading="generating"
            :disabled="!form.protocol || !form.accountId || !asset.is_active"
          >
            生成连接信息
          </el-button>
        </el-form-item>
      </el-form>

      <el-empty
        v-if="accountOptions.length === 0 && !accountsLoading"
        description="暂无可用账号"
      />

      <div v-if="result" class="connection-result">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="协议">
            <el-tag>{{ result.protocol.toUpperCase() }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="连接方式">
            {{ result.connect_method }}
          </el-descriptions-item>
          <el-descriptions-item label="代理地址">
            {{ result.host }}:{{ result.port }}
          </el-descriptions-item>
          <el-descriptions-item label="过期时间">
            {{ formatDate(result.expires_at) }}
          </el-descriptions-item>
          <el-descriptions-item label="文件名">
            {{ result.filename || '—' }}
          </el-descriptions-item>
          <el-descriptions-item label="剩余有效期">
            {{ formatTTL(result.expires_in) }}
          </el-descriptions-item>
        </el-descriptions>

        <div class="command-block">
          <div class="command-header">
            <span>连接命令</span>
            <div>
              <el-button size="small" @click="copyCommand">
                <el-icon><DocumentCopy /></el-icon>
                复制
              </el-button>
              <el-button size="small" type="primary" plain @click="downloadFile">
                <el-icon><Download /></el-icon>
                下载
              </el-button>
            </div>
          </div>
          <pre>{{ result.command }}</pre>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { DocumentCopy, Download } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import * as assetsApi from '@/api/assets'
import * as tokensApi from '@/api/tokens'
import type { Account, Asset, PlatformProtocol, SDKURLResult } from '@/types'
import { useAuthStore } from '@/stores/auth'
import { normalizeProtocol } from '@/utils/terminal'

type NativeProtocol = 'ssh' | 'mysql' | 'postgres'

const props = defineProps<{
  asset: Asset
  protocols: PlatformProtocol[]
}>()

const authStore = useAuthStore()
const accounts = ref<Account[]>([])
const accountsLoading = ref(false)
const generating = ref(false)
const result = ref<SDKURLResult | null>(null)
const form = reactive({
  protocol: '' as NativeProtocol | '',
  accountId: undefined as number | undefined,
  proxyHost: '',
})

const canGenerate = computed(() => (
  authStore.canAccess('connection_tokens') &&
  authStore.canAccess('assets') &&
  authStore.canAccess('accounts') &&
  authStore.canAccess('platforms') &&
  authStore.canAccess('platform_protocols')
))

const protocolOptions = computed<NativeProtocol[]>(() => {
  const seen = new Set<NativeProtocol>()
  for (const protocol of props.protocols) {
    const normalized = normalizeNativeProtocol(protocol.name)
    if (normalized) seen.add(normalized)
  }
  return [...seen]
})

const accountOptions = computed(() => accounts.value.filter((account) => account.is_active))

function normalizeNativeProtocol(protocol?: string): NativeProtocol | null {
  switch (normalizeProtocol(protocol)) {
    case 'ssh':
      return 'ssh'
    case 'mysql':
      return 'mysql'
    case 'postgres':
    case 'postgresql':
      return 'postgres'
    default:
      return null
  }
}

function protocolLabel(protocol: NativeProtocol): string {
  switch (protocol) {
    case 'ssh':
      return 'SSH'
    case 'mysql':
      return 'MySQL'
    case 'postgres':
      return 'PostgreSQL'
  }
}

function accountLabel(account: Account): string {
  return account.name ? `${account.name} (${account.username})` : account.username
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleString()
}

function formatTTL(seconds: number): string {
  if (seconds <= 0) return '已过期'
  const minutes = Math.floor(seconds / 60)
  const secs = seconds % 60
  if (minutes <= 0) return `${secs} 秒`
  const hours = Math.floor(minutes / 60)
  const mins = minutes % 60
  if (hours <= 0) return `${mins} 分 ${secs} 秒`
  return `${hours} 小时 ${mins} 分`
}

function syncDefaultSelection() {
  if (!form.protocol || !protocolOptions.value.includes(form.protocol)) {
    form.protocol = protocolOptions.value[0] ?? ''
  }
  if (
    form.accountId === undefined ||
    !accountOptions.value.some((account) => account.id === form.accountId)
  ) {
    form.accountId = accountOptions.value[0]?.id
  }
}

async function loadAccounts() {
  if (!canGenerate.value) return
  accountsLoading.value = true
  try {
    accounts.value = await assetsApi.listAccounts(props.asset.id)
    syncDefaultSelection()
  } catch (err: unknown) {
    accounts.value = []
    ElMessage.error(err instanceof Error ? err.message : '加载账号失败')
  } finally {
    accountsLoading.value = false
  }
}

async function generateConnection() {
  if (!form.protocol || form.accountId === undefined) return
  generating.value = true
  try {
    result.value = await tokensApi.createSDKUrl({
      asset_id: props.asset.id,
      account_id: form.accountId,
      protocol: form.protocol,
      proxy_host: form.proxyHost || undefined,
    })
  } catch (err: unknown) {
    ElMessage.error(err instanceof Error ? err.message : '生成连接信息失败')
  } finally {
    generating.value = false
  }
}

async function copyCommand() {
  if (!result.value?.command) return
  try {
    await globalThis.navigator.clipboard.writeText(result.value.command)
    ElMessage.success('连接命令已复制')
  } catch {
    ElMessage.error('复制失败')
  }
}

function downloadFile() {
  if (!result.value) return
  const content = result.value.content || `${result.value.command}\n`
  const blob = new globalThis.Blob([content], { type: result.value.mime_type || 'text/plain' })
  const link = globalThis.document.createElement('a')
  link.href = globalThis.URL.createObjectURL(blob)
  link.download = result.value.filename || `turjmp-${result.value.protocol}.txt`
  link.click()
  globalThis.URL.revokeObjectURL(link.href)
}

watch(
  () => props.asset.id,
  () => {
    result.value = null
    form.accountId = undefined
    void loadAccounts()
  },
)

watch(protocolOptions, syncDefaultSelection)
watch(accountOptions, syncDefaultSelection)

onMounted(() => {
  syncDefaultSelection()
  void loadAccounts()
})
</script>

<style scoped>
.native-panel {
  margin-top: 8px;
}

.panel-alert {
  margin-bottom: 16px;
}

.native-form {
  max-width: 100%;
}

.connection-result {
  margin-top: 16px;
}

.command-block {
  margin-top: 16px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  overflow: hidden;
}

.command-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  background: #f5f7fa;
  border-bottom: 1px solid #dcdfe6;
  font-weight: 600;
}

pre {
  margin: 0;
  padding: 14px;
  background: #1f2329;
  color: #f2f6fc;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  font-size: 13px;
  line-height: 1.6;
}

@media (max-width: 768px) {
  .command-header {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
