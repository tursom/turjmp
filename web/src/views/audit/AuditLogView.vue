<template>
  <div class="page-container">
    <h2>Audit Logs</h2>

    <div class="filter-bar">
      <el-input
        v-model="filters.search"
        placeholder="Search action, resource, address, detail..."
        clearable
        class="search-input"
        @input="resetPage"
        @keyup.enter="loadAuditLogs"
        @clear="loadAuditLogs"
      />
      <el-input-number
        v-model="filters.userId"
        :min="1"
        controls-position="right"
        placeholder="User ID"
        class="user-filter"
        @change="applyFilters"
      />
      <el-select
        v-model="filters.action"
        placeholder="All actions"
        clearable
        class="action-filter"
        @change="applyFilters"
      >
        <el-option
          v-for="action in actionOptions"
          :key="action"
          :label="action"
          :value="action"
        />
      </el-select>
      <el-date-picker
        v-model="filters.dateRange"
        type="daterange"
        start-placeholder="Start date"
        end-placeholder="End date"
        value-format="YYYY-MM-DD"
        class="date-filter"
        @change="applyFilters"
      />
      <el-button type="primary" @click="applyFilters">Search</el-button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="loading-container">
      <el-skeleton :rows="6" animated />
    </div>

    <!-- Error -->
    <div v-else-if="error" class="error-container">
      <el-result icon="error" title="Failed to load audit logs" :sub-title="error">
        <template #extra>
          <el-button type="primary" @click="loadAuditLogs">Retry</el-button>
        </template>
      </el-result>
    </div>

    <!-- Empty -->
    <div v-else-if="logs.length === 0" class="empty-container">
      <el-empty description="No audit logs found" />
    </div>

    <!-- Table -->
    <el-table
      v-else
      :data="logs"
      stripe
      border
      style="width: 100%"
    >
      <el-table-column prop="id" label="ID" width="80" sortable />
      <el-table-column prop="user_id" label="User ID" width="100">
        <template #default="{ row }">
          {{ row.user_id ?? '-' }}
        </template>
      </el-table-column>
      <el-table-column prop="action" label="Action" min-width="160">
        <template #default="{ row }">
          <el-tag size="small">{{ row.action }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="resource" label="Resource" min-width="180" />
      <el-table-column prop="remote_addr" label="Remote Addr" width="150" />
      <el-table-column label="Detail" min-width="200">
        <template #default="{ row }">
          <el-tooltip
            :content="formatDetail(row.detail)"
            placement="top"
            :show-after="300"
            effect="light"
          >
            <span class="detail-text">{{ truncateDetail(row.detail) }}</span>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column label="Created At" min-width="180">
        <template #default="{ row }">
          {{ formatDate(row.created_at) }}
        </template>
      </el-table-column>
    </el-table>

    <div v-if="total > 0" class="pagination-row">
      <el-pagination
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :total="total"
        :page-sizes="[20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        @size-change="handleSizeChange"
        @current-change="loadAuditLogs"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref, onMounted } from 'vue'
import * as auditApi from '@/api/audit'
import type { AuditLog } from '@/types'

const loading = ref(true)
const error = ref<string | null>(null)
const logs = ref<AuditLog[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const filters = reactive({
  search: '',
  userId: undefined as number | undefined,
  action: '',
  dateRange: '' as [string, string] | '',
})

const actionOptions = computed(() => {
  return [...new Set(logs.value.map((log) => log.action).filter(Boolean))].sort()
})

function resetPage() {
  page.value = 1
}

function applyFilters() {
  resetPage()
  loadAuditLogs()
}

function handleSizeChange() {
  resetPage()
  loadAuditLogs()
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr)
  return d.toLocaleString()
}

function formatDetail(detail: string): string {
  if (!detail) return '-'
  try {
    const parsed = JSON.parse(detail)
    return JSON.stringify(parsed, null, 2)
  } catch {
    return detail
  }
}

function truncateDetail(detail: string): string {
  if (!detail) return '-'
  const maxLen = 60
  try {
    // For JSON, show a compact preview
    const parsed = JSON.parse(detail)
    const compact = JSON.stringify(parsed)
    return compact.length > maxLen ? compact.slice(0, maxLen) + '…' : compact
  } catch {
    return detail.length > maxLen ? detail.slice(0, maxLen) + '…' : detail
  }
}

async function loadAuditLogs() {
  loading.value = true
  error.value = null
  try {
    const [dateFrom, dateTo] = Array.isArray(filters.dateRange) ? filters.dateRange : ['', '']
    const result = await auditApi.listPaged({
      page: page.value,
      per_page: pageSize.value,
      search: filters.search || undefined,
      user_id: filters.userId || undefined,
      action: filters.action || undefined,
      date_from: dateFrom || undefined,
      date_to: dateTo || undefined,
    })
    logs.value = result.items
    total.value = result.total
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to load audit logs'
    error.value = msg
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadAuditLogs()
})
</script>

<style scoped>
h2 {
  margin-bottom: 16px;
  font-size: 22px;
  color: #303133;
}

.loading-container,
.error-container,
.empty-container {
  padding: 40px 0;
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
}

.search-input {
  width: 320px;
}

.user-filter {
  width: 130px;
}

.action-filter,
.date-filter {
  width: 240px;
}

.pagination-row {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}

.detail-text {
  font-family: 'Courier New', Courier, monospace;
  font-size: 12px;
  color: #606266;
  cursor: pointer;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  display: inline-block;
  max-width: 280px;
}

.detail-text:hover {
  color: #409eff;
}
</style>
