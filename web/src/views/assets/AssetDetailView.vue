<template>
  <div class="page-container">
    <div class="page-header">
      <div class="header-left">
        <el-button @click="handleBack">← Back</el-button>
        <h2 v-if="asset">{{ asset.name }}</h2>
        <h2 v-else>Asset Detail</h2>
      </div>
      <el-button v-if="canUpdateAssets" type="primary" @click="handleEdit">Edit</el-button>
    </div>

    <el-tabs v-model="activeTab">
      <el-tab-pane label="Information" name="info">
        <el-descriptions v-if="asset" :column="2" border class="info-descriptions">
          <el-descriptions-item label="Name">{{ asset.name }}</el-descriptions-item>
          <el-descriptions-item label="Address">{{ asset.address }}</el-descriptions-item>
          <el-descriptions-item label="Platform">
            {{ platformName }}
          </el-descriptions-item>
          <el-descriptions-item label="Node">
            {{ nodeName || '—' }}
          </el-descriptions-item>
          <el-descriptions-item label="Comment">
            {{ asset.comment || '—' }}
          </el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="asset.is_active ? 'success' : 'info'" size="small">
              {{ asset.is_active ? 'Active' : 'Inactive' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Created">
            {{ formatDate(asset.created_at) }}
          </el-descriptions-item>
          <el-descriptions-item label="Updated">
            {{ formatDate(asset.updated_at) }}
          </el-descriptions-item>
        </el-descriptions>
        <el-skeleton v-else :rows="8" animated />
      </el-tab-pane>

      <el-tab-pane label="Accounts" name="accounts">
        <AccountManagement
          v-if="asset"
          :asset-id="asset.id"
          :platform-type="platformType"
        />
      </el-tab-pane>

      <el-tab-pane label="Protocols" name="protocols">
        <el-table
          v-loading="protocolsLoading"
          :data="protocols"
          stripe
          border
          empty-text="No protocol configuration found"
        >
          <el-table-column prop="name" label="Protocol" min-width="140" />
          <el-table-column prop="port" label="Port" width="120" />
          <el-table-column label="Settings" min-width="240">
            <template #default="{ row }">
              <code>{{ row.settings || '{}' }}</code>
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
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load asset')
    router.push('/assets')
  }
}

async function loadProtocols(platformId: number) {
  protocolsLoading.value = true
  try {
    protocols.value = await assetsApi.listPlatformProtocols(platformId)
  } catch (err) {
    protocols.value = []
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load protocols')
  } finally {
    protocolsLoading.value = false
  }
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
