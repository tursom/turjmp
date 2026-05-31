<template>
  <div class="page-container">
    <div class="page-header">
      <h2>SSH Host Key Fingerprints</h2>
    </div>

    <div v-if="loading" v-loading="loading" class="loading-placeholder" />

    <el-alert
      v-else-if="error"
      :title="error"
      type="error"
      show-icon
      :closable="false"
    />

    <el-empty
      v-else-if="!loading && fingerprints.length === 0"
      description="No SSH host keys configured"
    />

    <el-table
      v-else
      :data="fingerprints"
      stripe
      border
      empty-text="No fingerprints available"
    >
      <el-table-column prop="algorithm" label="Algorithm" width="160" />

      <el-table-column label="Fingerprint" min-width="340">
        <template #default="scope">
          <div class="fingerprint-cell">
            <code class="fingerprint-text">{{ scope.row.fingerprint }}</code>
            <el-button
              size="small"
              text
              type="primary"
              :icon="CopyDocument"
              @click="copyFingerprint(scope.row.fingerprint)"
            >
              Copy
            </el-button>
          </div>
        </template>
      </el-table-column>

      <el-table-column label="Public Key" min-width="320">
        <template #default="scope">
          <div class="pubkey-cell">
            <code class="pubkey-text">
              {{ expandedKeys.has(scope.row.fingerprint)
                ? scope.row.public_key
                : truncateKey(scope.row.public_key)
              }}
            </code>
            <el-button
              v-if="scope.row.public_key.length > 80"
              size="small"
              text
              type="primary"
              @click="toggleKeyExpansion(scope.row.fingerprint)"
            >
              {{ expandedKeys.has(scope.row.fingerprint) ? 'Show less' : 'Show more' }}
            </el-button>
          </div>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { CopyDocument } from '@element-plus/icons-vue'
import * as settingsApi from '@/api/settings'
import type { SSHFingerprint } from '@/types'

const loading = ref(false)
const error = ref('')
const fingerprints = ref<SSHFingerprint[]>([])
const expandedKeys = ref(new Set<string>())

function truncateKey(key: string): string {
  if (key.length <= 80) return key
  return key.slice(0, 77) + '...'
}

function toggleKeyExpansion(fingerprint: string): void {
  const set = expandedKeys.value
  if (set.has(fingerprint)) {
    set.delete(fingerprint)
  } else {
    set.add(fingerprint)
  }
}

async function copyFingerprint(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('Fingerprint copied to clipboard')
  } catch {
    ElMessage.error('Failed to copy fingerprint')
  }
}

async function fetchFingerprints(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    fingerprints.value = await settingsApi.sshFingerprint()
  } catch (err) {
    error.value =
      err instanceof Error ? err.message : 'Failed to load SSH fingerprints'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchFingerprints()
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

.loading-placeholder {
  min-height: 200px;
}

.fingerprint-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.fingerprint-text {
  font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
  font-size: 13px;
  background: var(--el-fill-color-light);
  padding: 2px 8px;
  border-radius: 4px;
  word-break: break-all;
}

.pubkey-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.pubkey-text {
  font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
  font-size: 12px;
  background: var(--el-fill-color-light);
  padding: 4px 8px;
  border-radius: 4px;
  word-break: break-all;
  line-height: 1.4;
}
</style>
