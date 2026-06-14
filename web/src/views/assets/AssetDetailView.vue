<template>
  <div class="page-container">
    <div class="page-header">
      <div class="header-left">
        <el-button @click="handleBack">← 返回</el-button>
        <h2 v-if="asset">{{ asset.name }}</h2>
        <h2 v-else>资产详情</h2>
      </div>
      <el-button v-if="canOpenTerminal && terminalProtocol" type="success" @click="handleWebTerminal">
        Web 终端
      </el-button>
      <el-button v-if="canUpdateAssets" type="primary" @click="handleEdit">编辑</el-button>
    </div>

    <el-tabs v-model="activeTab">
      <el-tab-pane label="基本信息" name="info">
        <el-descriptions v-if="asset" :column="2" border class="info-descriptions">
          <el-descriptions-item label="名称">{{ asset.name }}</el-descriptions-item>
          <el-descriptions-item label="地址">{{ asset.address }}</el-descriptions-item>
          <el-descriptions-item label="平台">
            {{ platformName }}
          </el-descriptions-item>
          <el-descriptions-item label="节点">
            {{ nodeName || '—' }}
          </el-descriptions-item>
          <el-descriptions-item label="备注">
            {{ asset.comment || '—' }}
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="asset.is_active ? 'success' : 'info'" size="small">
              {{ asset.is_active ? '活跃' : '停用' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="创建时间">
            {{ formatDate(asset.created_at) }}
          </el-descriptions-item>
          <el-descriptions-item label="更新时间">
            {{ formatDate(asset.updated_at) }}
          </el-descriptions-item>
        </el-descriptions>
        <el-skeleton v-else :rows="8" animated />
      </el-tab-pane>

      <el-tab-pane label="账号" name="accounts">
        <AccountManagement
          v-if="asset"
          :asset-id="asset.id"
          :platform-type="platformType"
        />
      </el-tab-pane>

      <el-tab-pane label="协议" name="protocols">
        <el-table
          v-loading="protocolsLoading"
          :data="protocols"
          stripe
          border
          empty-text="未找到协议配置"
        >
          <el-table-column prop="name" label="协议" min-width="140" />
          <el-table-column prop="port" label="端口" width="120" />
          <el-table-column label="设置" min-width="240">
            <template #default="{ row }">
              <code>{{ row.settings || '{}' }}</code>
            </template>
          </el-table-column>
          <el-table-column label="终端" width="140">
            <template #default="{ row }">
              <el-button
                v-if="canOpenTerminal && asset?.is_active && isSupportedWebTerminalProtocol(row.name)"
                size="small"
                type="success"
                @click="handleProtocolTerminal(row.name)"
              >
                打开
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import * as assetsApi from '@/api/assets'
import type { Asset, Platform, Node, PlatformProtocol } from '@/types'
import AccountManagement from './AccountManagement.vue'
import { useAuthStore } from '@/stores/auth'
import {
  canUseWebTerminal,
  isSupportedWebTerminalProtocol,
  normalizeProtocol,
  supportedWebTerminalProtocols,
} from '@/utils/terminal'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const activeTab = ref('info')
const asset = ref<Asset | null>(null)
const platforms = ref<Platform[]>([])
const nodes = ref<Node[]>([])
const protocols = ref<PlatformProtocol[]>([])
const protocolsLoading = ref(false)
const canUpdateAssets = computed(() => authStore.canAccess('asset_update'))
const canOpenTerminal = computed(() => canUseWebTerminal(authStore.access))

const assetId = computed(() => {
  const id = route.params.id
  return typeof id === 'string' ? Number(id) : 0
})

const platformName = computed(() => {
  if (!asset.value) return '—'
  const p = platforms.value.find((pl) => pl.id === asset.value!.platform_id)
  return p?.name ?? '—'
})

const platformType = computed(() => {
  if (!asset.value) return ''
  const p = platforms.value.find((pl) => pl.id === asset.value!.platform_id)
  return p?.type ?? ''
})

const supportedProtocols = computed(() => supportedWebTerminalProtocols(protocols.value))
const terminalProtocol = computed(() => {
  if (!asset.value?.is_active) return undefined
  return normalizeProtocol(supportedProtocols.value[0]?.name) || undefined
})

const nodeName = computed(() => {
  if (!asset.value?.node_id) return null
  const n = nodes.value.find((nd) => nd.id === asset.value!.node_id)
  return n?.name ?? null
})

function formatDate(iso: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

async function loadData() {
  try {
    const [assetData, platData, treeData] = await Promise.all([
      assetsApi.get(assetId.value),
      assetsApi.listPlatforms(),
      assetsApi.getTree(),
    ])
    asset.value = assetData
    platforms.value = platData
    nodes.value = treeData.nodes
    await loadProtocols(assetData.platform_id)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '加载资产失败')
    router.push('/assets')
  }
}

async function loadProtocols(platformId: number) {
  protocolsLoading.value = true
  try {
    protocols.value = await assetsApi.listPlatformProtocols(platformId)
  } catch (err) {
    protocols.value = []
    ElMessage.error(err instanceof Error ? err.message : '加载协议失败')
  } finally {
    protocolsLoading.value = false
  }
}

function handleWebTerminal() {
  if (!terminalProtocol.value) return
  router.push(`/terminal?asset_id=${assetId.value}&protocol=${terminalProtocol.value}&auto_connect=1`)
}

function handleProtocolTerminal(protocol: string) {
  if (!asset.value?.is_active) return
  const normalized = normalizeProtocol(protocol)
  if (!isSupportedWebTerminalProtocol(normalized)) return
  router.push(`/terminal?asset_id=${assetId.value}&protocol=${normalized}&auto_connect=1`)
}

function handleEdit() {
  router.push(`/assets/${assetId.value}/edit`)
}

function handleBack() {
  router.push('/assets')
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.header-left h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.info-descriptions {
  margin-top: 8px;
}
</style>
