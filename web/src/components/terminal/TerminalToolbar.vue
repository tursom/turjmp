<script setup lang="ts">
import { computed } from 'vue'
import { CopyDocument, CirclePlus, VideoPause, Document as PasteIcon } from '@element-plus/icons-vue'
import type { TerminalTabState } from '@/types'
import { formatDuration } from '@/utils/duration'

interface Props {
  tabs: TerminalTabState[]
  activeTabId: string | null
}

const props = defineProps<Props>()

const emit = defineEmits<{
  'update:activeTabId': [id: string]
  'add-tab': []
  'close-tab': [id: string]
  disconnect: [id: string]
  copy: [id: string]
  paste: [id: string]
}>()

const tabModel = computed({
  get: () => props.activeTabId ?? '',
  set: (val: string) => emit('update:activeTabId', val),
})
</script>

<template>
  <div class="terminal-toolbar">
    <el-tabs
      v-model="tabModel"
      type="card"
      closable
      class="terminal-tabs"
      @tab-remove="(name: string | number) => emit('close-tab', String(name))"
    >
      <el-tab-pane
        v-for="tab in tabs"
        :key="tab.id"
        :name="tab.id"
      >
        <template #label>
          <span class="tab-label">
            <span
              class="status-dot"
              :class="`status-${tab.status}`"
            />
            <span class="tab-name">{{ tab.assetName }}</span>
            <span class="tab-protocol">{{ tab.protocol }}</span>
            <span v-if="tab.status === 'connected' && tab.duration > 0" class="tab-duration">
              {{ formatDuration(tab.duration) }}
            </span>
          </span>
        </template>
      </el-tab-pane>
    </el-tabs>
    <div class="toolbar-actions">
      <el-button
        :icon="CopyDocument"
        size="small"
        text
        :disabled="!activeTabId"
        @click="emit('copy', activeTabId!)"
      />
      <el-button
        :icon="PasteIcon"
        size="small"
        text
        :disabled="!activeTabId"
        @click="emit('paste', activeTabId!)"
      />
      <el-button
        :icon="VideoPause"
        size="small"
        text
        :disabled="!activeTabId"
        @click="emit('disconnect', activeTabId!)"
      />
      <el-button
        :icon="CirclePlus"
        size="small"
        text
        @click="emit('add-tab')"
      />
    </div>
  </div>
</template>

<style scoped>
.terminal-toolbar {
  display: flex;
  align-items: center;
  background: #1a1b26;
  border-bottom: 1px solid #3b3d4e;
  height: 40px;
  padding-right: 8px;
  flex-shrink: 0;
}

.terminal-tabs {
  flex: 1;
  min-width: 0;
}

.terminal-tabs :deep(.el-tabs__header) {
  margin: 0;
  border-bottom: none;
}

.terminal-tabs :deep(.el-tabs__nav-wrap) {
  padding: 0;
}

.terminal-tabs :deep(.el-tabs__nav-wrap::after) {
  background-color: transparent;
}

.terminal-tabs :deep(.el-tabs__item) {
  height: 40px;
  line-height: 40px;
  color: #a0a4b8;
  background: #232533;
  border: none;
  border-right: 1px solid #3b3d4e;
  font-size: 13px;
  padding: 0 16px;
}

.terminal-tabs :deep(.el-tabs__item.is-active) {
  color: #f8f8f2;
  background: #282a36;
}

.terminal-tabs :deep(.el-tabs__item:hover) {
  color: #e0e0e0;
}

.terminal-tabs :deep(.el-tabs__nav) {
  border: none;
}

.tab-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.status-dot.status-connected {
  background: #50fa7b;
  box-shadow: 0 0 4px #50fa7b;
}

.status-dot.status-disconnected {
  background: #ff5555;
  box-shadow: 0 0 4px #ff5555;
}

.status-dot.status-connecting {
  background: #f1fa8c;
  box-shadow: 0 0 4px #f1fa8c;
  animation: pulse 1s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.tab-name {
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tab-protocol {
  font-size: 11px;
  color: #6272a4;
  text-transform: uppercase;
}

.tab-duration {
  font-size: 11px;
  color: #6272a4;
  font-variant-numeric: tabular-nums;
}

.toolbar-actions {
  display: flex;
  align-items: center;
  gap: 2px;
  margin-left: 8px;
  flex-shrink: 0;
}

.toolbar-actions :deep(.el-button) {
  color: #a0a4b8;
  padding: 4px;
  border-radius: 4px;
}

.toolbar-actions :deep(.el-button:hover) {
  color: #f8f8f2;
  background: #3b3d4e;
}

.toolbar-actions :deep(.el-button.is-disabled) {
  color: #4a4d5e;
}
</style>
