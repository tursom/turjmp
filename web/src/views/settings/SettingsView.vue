<template>
  <div class="page-container">
    <div class="page-header">
      <h2>System Settings</h2>
      <el-button type="primary" plain @click="router.push('/settings/ssh-fingerprint')">
        SSH Fingerprints
      </el-button>
    </div>

    <div v-if="loading" v-loading="loading" class="loading-placeholder" />

    <el-alert
      v-else-if="error"
      :title="error"
      type="error"
      show-icon
      :closable="false"
    />

    <el-empty v-else-if="!categories.length" description="No settings available" />

    <el-tabs v-else v-model="activeCategory" type="border-card">
      <el-tab-pane
        v-for="category in categories"
        :key="category"
        :label="formatCategoryName(category)"
        :name="category"
      >
        <el-form label-position="top" size="default">
          <el-form-item
            v-for="setting in settingsByCategory[category]"
            :key="setting.key"
          >
            <template #label>
              <span class="field-label">{{ setting.label }}</span>
              <el-tooltip
                v-if="setting.description"
                :content="setting.description"
                placement="top"
                effect="dark"
              >
                <el-icon class="help-icon"><QuestionFilled /></el-icon>
              </el-tooltip>
            </template>

            <!-- text -->
            <div v-if="setting.input_type === 'text'" class="field-row">
              <el-input
                v-model="fieldValues[setting.key]"
                :disabled="isSaving(setting.key)"
                class="field-input"
                @input="markDirty(setting.key)"
              />
              <el-button
                type="primary"
                size="default"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings || !isDirty(setting.key)"
                @click="saveField(setting)"
              >
                Save
              </el-button>
            </div>

            <!-- number -->
            <div v-else-if="setting.input_type === 'number'" class="field-row">
              <el-input-number
                v-model="fieldValues[setting.key]"
                :disabled="isSaving(setting.key)"
                class="field-input"
                @change="markDirty(setting.key)"
              />
              <el-button
                type="primary"
                size="default"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings || !isDirty(setting.key)"
                @click="saveField(setting)"
              >
                Save
              </el-button>
            </div>

            <!-- select -->
            <div v-else-if="setting.input_type === 'select'" class="field-row">
              <el-select
                v-model="fieldValues[setting.key]"
                :disabled="isSaving(setting.key)"
                class="field-input"
                @change="markDirty(setting.key)"
              >
                <el-option
                  v-for="opt in parseSelectOptions(setting.options)"
                  :key="opt.value"
                  :label="opt.label"
                  :value="opt.value"
                />
              </el-select>
              <el-button
                type="primary"
                size="default"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings || !isDirty(setting.key)"
                @click="saveField(setting)"
              >
                Save
              </el-button>
            </div>

            <!-- toggle (auto-save) -->
            <div v-else-if="setting.input_type === 'toggle'" class="field-row">
              <el-switch
                v-model="fieldValues[setting.key]"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings"
                active-text="Enabled"
                inactive-text="Disabled"
                @change="autoSaveToggle(setting)"
              />
            </div>

            <!-- secret -->
            <div v-else-if="setting.input_type === 'secret'" class="field-row">
              <el-input
                v-model="fieldValues[setting.key]"
                type="password"
                show-password
                :disabled="isSaving(setting.key)"
                class="field-input"
                placeholder="Enter new value to change"
                @input="markDirty(setting.key)"
              />
              <el-button
                type="primary"
                size="default"
                :loading="isSaving(setting.key)"
                :disabled="!canUpdateSettings || !isDirty(setting.key)"
                @click="saveSecretField(setting)"
              >
                Save
              </el-button>
            </div>
          </el-form-item>
        </el-form>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import * as settingsApi from '@/api/settings'
import { useAppStore } from '@/stores/app'
import { useAuthStore } from '@/stores/auth'
import { parseSettingString } from '@/utils/branding'
import type { Setting, SettingsByCategory } from '@/types'

interface SelectOption {
  label: string
  value: string
}

const loading = ref(false)
const error = ref('')
const settingsByCategory = ref<SettingsByCategory>({})
const activeCategory = ref('')
const router = useRouter()
const route = useRoute()
const appStore = useAppStore()
const authStore = useAuthStore()
const canUpdateSettings = computed(() => authStore.canAccess('setting_update'))

const fieldValues = reactive<Record<string, string | number | boolean>>({})
const originalValues: Record<string, string> = {}
const dirtyFields = reactive(new Set<string>())
const savingFields = reactive(new Set<string>())

const categories = computed(() => Object.keys(settingsByCategory.value))

function parseSelectOptions(raw: string | undefined): SelectOption[] {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed) || parsed.length === 0) return []
    // Array of objects with label/value
    if (typeof parsed[0] === 'object' && parsed[0] !== null) {
      return parsed.map((item: Record<string, unknown>, idx: number) => ({
        label: String(item.label ?? item.value ?? String(idx)),
        value: String(item.value ?? item.label ?? String(idx)),
      }))
    }
    // Array of strings
    return parsed.map((item: unknown) => ({
      label: String(item),
      value: String(item),
    }))
  } catch {
    // Not valid JSON — treat as comma-separated
    return raw.split(',').map((s) => ({
      label: s.trim(),
      value: s.trim(),
    }))
  }
}

function formatCategoryName(category: string): string {
  return category.charAt(0).toUpperCase() + category.slice(1)
}

function isSaving(key: string): boolean {
  return savingFields.has(key)
}

function isDirty(key: string): boolean {
  return dirtyFields.has(key)
}

function markDirty(key: string): void {
  dirtyFields.add(key)
}

function parseSettingValue(raw: string): unknown {
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}

function initDisplayValue(setting: Setting): string | number | boolean {
  const parsed = parseSettingValue(setting.value)
  switch (setting.input_type) {
    case 'toggle':
      return parsed === true || parsed === 'true'
    case 'number':
      return Number(parsed) || 0
    case 'secret':
      return typeof parsed === 'string' ? parsed : String(parsed ?? '')
    default:
      return typeof parsed === 'string' ? parsed : String(parsed ?? '')
  }
}

async function fetchSettings(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const data = await settingsApi.list()
    settingsByCategory.value = data

    // Flatten all settings and initialize display values
    const allSettings = Object.values(data).flat()
    for (const setting of allSettings) {
      const displayValue = initDisplayValue(setting)
      fieldValues[setting.key] = displayValue
      originalValues[setting.key] = String(displayValue)
    }

    // Set default active tab to the first category
    const catKeys = Object.keys(data)
    if (catKeys.length > 0) {
      activeCategory.value = catKeys[0]
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load settings'
  } finally {
    loading.value = false
  }
}

async function saveField(setting: Setting): Promise<void> {
  if (!canUpdateSettings.value) return
  const key = setting.key
  if (savingFields.has(key)) return

  savingFields.add(key)
  try {
    const rawValue = String(fieldValues[key])
    await settingsApi.update(key, rawValue)
    originalValues[key] = rawValue
    dirtyFields.delete(key)
    if (key === 'branding.site_name') {
      appStore.setSiteName(parseSettingString(rawValue), route.meta?.title as string | undefined)
    }
    ElMessage.success(`Saved "${setting.label}"`)
  } catch (err) {
    ElMessage.error(
      err instanceof Error ? err.message : `Failed to save "${setting.label}"`,
    )
  } finally {
    savingFields.delete(key)
  }
}

async function saveSecretField(setting: Setting): Promise<void> {
  if (!canUpdateSettings.value) return
  const key = setting.key
  if (savingFields.has(key)) return

  savingFields.add(key)
  try {
    const rawValue = dirtyFields.has(key)
      ? String(fieldValues[key])
      : ''
    await settingsApi.update(key, rawValue)
    // After save, reset display to empty placeholder
    fieldValues[key] = ''
    dirtyFields.delete(key)
    originalValues[key] = '******'
    ElMessage.success(`Saved "${setting.label}"`)
  } catch (err) {
    ElMessage.error(
      err instanceof Error ? err.message : `Failed to save "${setting.label}"`,
    )
  } finally {
    savingFields.delete(key)
  }
}

async function autoSaveToggle(setting: Setting): Promise<void> {
  if (!canUpdateSettings.value) return
  const key = setting.key
  if (savingFields.has(key)) return

  savingFields.add(key)
  try {
    const rawValue = fieldValues[key] ? 'true' : 'false'
    await settingsApi.update(key, rawValue)
    originalValues[key] = rawValue
    dirtyFields.delete(key)
    ElMessage.success(`"${setting.label}" updated`)
  } catch (err) {
    // Revert on failure
    if (originalValues[key] !== undefined) {
      fieldValues[key] = originalValues[key] === 'true'
    }
    ElMessage.error(
      err instanceof Error ? err.message : `Failed to update "${setting.label}"`,
    )
  } finally {
    savingFields.delete(key)
  }
}

onMounted(() => {
  fetchSettings()
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

.field-label {
  font-weight: 500;
}

.help-icon {
  margin-left: 4px;
  font-size: 14px;
  color: var(--el-color-info);
  cursor: help;
  vertical-align: middle;
}

.field-row {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
}

.field-input {
  flex: 1;
  max-width: 480px;
}
</style>
