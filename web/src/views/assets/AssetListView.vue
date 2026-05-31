<template>
  <div class="page-container">
    <div class="page-header">
      <h2>Assets</h2>
      <el-button v-if="canCreateAssets" type="primary" @click="handleCreate">
        New Asset
      </el-button>
    </div>

    <el-row :gutter="16" class="asset-workspace">
      <el-col :xs="24" :lg="6">
        <el-card shadow="never" class="tree-card">
          <template #header>
            <div class="tree-header">
              <span>Asset Tree</span>
              <el-button link type="primary" @click="fetchAssetTree">Refresh</el-button>
            </div>
          </template>
          <AssetTree
            v-if="assetTree"
            :nodes="assetTree.nodes"
            :assets="assetTree.assets"
            @node-click="handleTreeClick"
          />
          <el-skeleton v-else :rows="6" animated />
          <div v-if="selectedTreeLabel" class="tree-selection">
            Selected: {{ selectedTreeLabel }}
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :lg="18">
        <div class="toolbar">
          <el-input
            v-model="searchQuery"
            placeholder="Search by name or address..."
            clearable
            class="search-input"
            @input="applyFilters"
          />
          <el-select
            v-model="platformFilter"
            placeholder="All protocols"
            clearable
            class="filter-select"
            @change="applyFilters"
          >
            <el-option
              v-for="pt in platformTypes"
              :key="pt"
              :label="pt"
              :value="pt"
            />
          </el-select>
          <el-select
            v-model="statusFilter"
            placeholder="All statuses"
            class="filter-select"
            @change="applyFilters"
          >
            <el-option label="All statuses" value="all" />
            <el-option label="Active" value="active" />
            <el-option label="Inactive" value="inactive" />
          </el-select>
        </div>

        <el-table
          v-loading="loading"
          :data="assets"
          stripe
          border
          empty-text="No assets found"
        >
          <el-table-column prop="name" label="Name" min-width="140" />
          <el-table-column prop="address" label="Address" min-width="160" />
          <el-table-column prop="platform_name" label="Platform" min-width="120" />
          <el-table-column prop="platform_type" label="Type" width="120" />
          <el-table-column label="Status" width="100">
            <template #default="{ row }">
              <el-tag :type="row.is_active ? 'success' : 'info'" size="small">
                {{ row.is_active ? 'Active' : 'Inactive' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Created" width="180">
            <template #default="{ row }">
              {{ formatDate(row.created_at) }}
            </template>
          </el-table-column>
          <el-table-column label="Actions" width="200" fixed="right">
            <template #default="{ row }">
              <el-button size="small" @click="handleView(row.id)">View</el-button>
              <el-button
                v-if="canUpdateAssets"
                size="small"
                type="primary"
                @click="handleEdit(row.id)"
              >
                Edit
              </el-button>
              <el-button
                v-if="canDeleteAssets"
                size="small"
                type="danger"
                @click="handleDelete(row)"
              >
                Delete
              </el-button>
            </template>
          </el-table-column>
        </el-table>

        <div class="pagination-row">
          <el-pagination
            v-model:current-page="page"
            v-model:page-size="pageSize"
            :total="total"
            :page-sizes="[10, 20, 50, 100]"
            layout="total, sizes, prev, pager, next"
            @size-change="handleSizeChange"
            @current-change="fetchAssets"
          />
        </div>

        <el-empty
          v-if="!loading && total === 0"
          description="No assets yet. Create your first asset."
        />
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as assetsApi from '@/api/assets'
import { useAuthStore } from '@/stores/auth'
import AssetTree from '@/components/asset-tree/AssetTree.vue'
import type { AssetTreeData, AssetWithPlatform, Platform, Node as AssetNode } from '@/types'

const router = useRouter()
const authStore = useAuthStore()

const loading = ref(false)
const assets = ref<AssetWithPlatform[]>([])
const platforms = ref<Platform[]>([])
const assetTree = ref<AssetTreeData | null>(null)
const selectedTreeLabel = ref('')
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const searchQuery = ref('')
const platformFilter = ref('')
const statusFilter = ref('all')

const canCreateAssets = computed(() => authStore.canAccess('asset_create'))
const canUpdateAssets = computed(() => authStore.canAccess('asset_update'))
const canDeleteAssets = computed(() => authStore.canAccess('asset_delete'))

const platformTypes = computed(() => {
  const types = new Set(platforms.value.map((p) => p.type))
  return [...types].sort()
})

function applyFilters() {
  page.value = 1
  fetchAssets()
}

function formatDate(iso: string): string {
  if (!iso) return ''
  return new Date(iso).toLocaleString()
}

async function fetchAssets() {
  loading.value = true
  try {
    const result = await assetsApi.listPaged({
      page: page.value,
      per_page: pageSize.value,
      search: searchQuery.value || undefined,
      protocol: platformFilter.value || undefined,
      status: statusFilter.value,
    })
    assets.value = result.items
    total.value = result.total
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load assets')
  } finally {
    loading.value = false
  }
}

async function fetchPlatforms() {
  try {
    platforms.value = await assetsApi.listPlatforms()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load platforms')
  }
}

async function fetchAssetTree() {
  try {
    assetTree.value = await assetsApi.getTree()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load asset tree')
  }
}

function handleSizeChange() {
  page.value = 1
  fetchAssets()
}

function handleCreate() {
  router.push('/assets/new')
}

function handleView(id: number) {
  router.push(`/assets/${id}`)
}

function handleTreeClick(payload: { type: 'node' | 'asset'; data: AssetNode | AssetWithPlatform }) {
  selectedTreeLabel.value = payload.data.name
  if (payload.type === 'asset') {
    router.push(`/assets/${payload.data.id}`)
  }
}

function handleEdit(id: number) {
  router.push(`/assets/${id}/edit`)
}

async function handleDelete(row: AssetWithPlatform) {
  try {
    await ElMessageBox.confirm(
      `Delete asset "${row.name}"? This action cannot be undone.`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      },
    )
    await assetsApi.remove(row.id)
    ElMessage.success('Asset deleted')
    await fetchAssets()
    await fetchAssetTree()
  } catch (err) {
    if (err !== 'cancel' && err !== 'close') {
      ElMessage.error(err instanceof Error ? err.message : 'Delete failed')
    }
  }
}

onMounted(() => {
  fetchPlatforms()
  fetchAssetTree()
  fetchAssets()
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

.toolbar {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  align-items: center;
}

.asset-workspace {
  row-gap: 16px;
}

.tree-card {
  min-height: 360px;
}

.tree-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.tree-selection {
  margin-top: 12px;
  font-size: 12px;
  color: #909399;
}

.search-input {
  width: 280px;
}

.filter-select {
  width: 180px;
}

.pagination-row {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
