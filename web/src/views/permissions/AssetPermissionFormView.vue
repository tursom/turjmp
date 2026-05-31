<template>
  <div class="page-container">
    <div class="page-header">
      <h2>{{ isEdit ? 'Edit Permission' : 'New Permission' }}</h2>
      <el-button @click="goBack">
        <el-icon><ArrowLeft /></el-icon>
        Back to Permissions
      </el-button>
    </div>

    <div v-if="loadingDetail" class="page-loading">
      <el-icon class="is-loading" :size="24"><Loading /></el-icon>
      <span>Loading permission...</span>
    </div>

    <el-form
      v-else
      ref="formRef"
      :model="form"
      :rules="rules"
      label-width="140px"
      class="perm-form"
      @submit.prevent="handleSubmit"
    >
      <el-form-item label="Name" prop="name">
        <el-input v-model="form.name" placeholder="Enter permission name" />
      </el-form-item>

      <el-form-item label="Actions" prop="actions">
        <div class="actions-group">
          <el-checkbox-group v-model="actionChecks">
            <el-checkbox label="connect">Connect</el-checkbox>
            <el-checkbox label="upload">Upload</el-checkbox>
            <el-checkbox label="download">Download</el-checkbox>
          </el-checkbox-group>
          <el-input
            v-model="actionCustom"
            placeholder="Custom actions (comma-separated)"
            class="action-custom"
          />
        </div>
      </el-form-item>

      <el-form-item label="Date Start">
        <el-date-picker
          v-model="form.date_start"
          type="datetime"
          placeholder="Start date (optional)"
          style="width: 100%"
          value-format="YYYY-MM-DDTHH:mm:ssZ"
        />
      </el-form-item>

      <el-form-item label="Date Expired">
        <el-date-picker
          v-model="form.date_expired"
          type="datetime"
          placeholder="Expiry date (optional)"
          style="width: 100%"
          value-format="YYYY-MM-DDTHH:mm:ssZ"
        />
      </el-form-item>

      <el-form-item label="Users">
        <el-select
          v-model="form.user_ids"
          multiple
          filterable
          placeholder="Select users"
          style="width: 100%"
        >
          <el-option
            v-for="u in users"
            :key="u.id"
            :label="`${u.username} (${u.name})`"
            :value="u.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="User Groups">
        <el-select
          v-model="form.group_ids"
          multiple
          filterable
          placeholder="Select user groups"
          style="width: 100%"
        >
          <el-option
            v-for="g in groups"
            :key="g.id"
            :label="g.name"
            :value="g.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="Assets">
        <el-select
          v-model="form.asset_ids"
          multiple
          filterable
          placeholder="Select assets"
          style="width: 100%"
        >
          <el-option
            v-for="a in assets"
            :key="a.id"
            :label="`${a.name} (${a.address})`"
            :value="a.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="Nodes">
        <el-select
          v-model="form.node_ids"
          multiple
          filterable
          placeholder="Select nodes"
          style="width: 100%"
        >
          <el-option
            v-for="n in nodes"
            :key="n.id"
            :label="n.name"
            :value="n.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="Accounts">
        <el-select
          v-model="form.account_ids"
          multiple
          filterable
          placeholder="Select assets first, then accounts"
          style="width: 100%"
        >
          <el-option
            v-for="a in accounts"
            :key="a.id"
            :label="`${a.name} (${a.username})`"
            :value="a.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="Status">
        <el-switch v-model="form.is_active" active-text="Active" inactive-text="Inactive" />
      </el-form-item>

      <el-form-item>
        <el-button type="primary" native-type="submit" :loading="submitting">
          {{ isEdit ? 'Update' : 'Create' }}
        </el-button>
        <el-button @click="goBack">Cancel</el-button>
      </el-form-item>
    </el-form>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { ArrowLeft, Loading } from '@element-plus/icons-vue'
import type { User, UserGroup, AssetWithPlatform, Node, Account } from '@/types'
import * as permissionsApi from '@/api/permissions'
import * as usersApi from '@/api/users'
import * as assetsApi from '@/api/assets'
import * as groupsApi from '@/api/groups'

const router = useRouter()
const route = useRoute()
const formRef = ref<FormInstance>()

const isEdit = computed(() => !!route.params.id)
const permissionId = computed(() => (isEdit.value ? Number(route.params.id) : undefined))

const loadingDetail = ref(false)
const submitting = ref(false)

const users = ref<User[]>([])
const groups = ref<UserGroup[]>([])
const assets = ref<AssetWithPlatform[]>([])
const nodes = ref<Node[]>([])
const accounts = ref<Account[]>([])

const form = reactive({
  name: '',
  date_start: '',
  date_expired: '',
  is_active: true,
  user_ids: [] as number[],
  group_ids: [] as number[],
  asset_ids: [] as number[],
  node_ids: [] as number[],
  account_ids: [] as number[],
})

const actionChecks = ref<string[]>([])
const actionCustom = ref('')
let accountsRequestSeq = 0

const rules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
}

function buildActions(): string[] {
  const parts: string[] = [...actionChecks.value]
  if (actionCustom.value.trim()) {
    parts.push(
      ...actionCustom.value
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    )
  }
  return [...new Set(parts)]
}

function parseActions(raw: string): { checks: string[]; custom: string } {
  if (!raw) return { checks: [], custom: '' }
  const parts = raw.split(',').map((s) => s.trim()).filter(Boolean)
  const std = ['connect', 'upload', 'download']
  const checks = parts.filter((p) => std.includes(p))
  const custom = parts.filter((p) => !std.includes(p)).join(', ')
  return { checks, custom }
}

function toPickerDateTime(value?: string): string {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  const pad = (n: number) => String(n).padStart(2, '0')
  const offsetMinutes = -date.getTimezoneOffset()
  const sign = offsetMinutes >= 0 ? '+' : '-'
  const absOffset = Math.abs(offsetMinutes)
  const offset = `${sign}${pad(Math.floor(absOffset / 60))}:${pad(absOffset % 60)}`

  return [
    date.getFullYear(),
    '-',
    pad(date.getMonth() + 1),
    '-',
    pad(date.getDate()),
    'T',
    pad(date.getHours()),
    ':',
    pad(date.getMinutes()),
    ':',
    pad(date.getSeconds()),
    offset,
  ].join('')
}

function goBack() {
  router.push('/permissions')
}

async function loadOptions() {
  const [userResult, groupResult, assetResult, treeResult] = await Promise.allSettled([
    usersApi.list(),
    groupsApi.list(),
    assetsApi.list(),
    assetsApi.getTree(),
  ])

  if (userResult.status === 'fulfilled') {
    users.value = userResult.value
  }
  if (groupResult.status === 'fulfilled') {
    groups.value = groupResult.value
  }
  if (assetResult.status === 'fulfilled') {
    assets.value = assetResult.value
  }
  if (treeResult.status === 'fulfilled') {
    nodes.value = treeResult.value.nodes
  }

  await loadAccountsForAssets(form.asset_ids)
}

async function loadAccountsForAssets(assetIDs: number[]) {
  const requestID = ++accountsRequestSeq
  const uniqueAssetIDs = [...new Set(assetIDs)]
  if (uniqueAssetIDs.length === 0) {
    accounts.value = []
    return
  }

  const accountResults = await Promise.allSettled(
    uniqueAssetIDs.map((assetID) => assetsApi.listAccounts(assetID)),
  )
  if (requestID !== accountsRequestSeq) {
    return
  }
  accounts.value = accountResults
    .filter((result): result is PromiseFulfilledResult<Account[]> => result.status === 'fulfilled')
    .flatMap((result) => result.value)
}

async function fetchPermission() {
  if (!permissionId.value) return
  loadingDetail.value = true
  try {
    const detail = await permissionsApi.get(permissionId.value)
    const p = detail.permission
    form.name = p.name
    form.date_start = toPickerDateTime(p.date_start)
    form.date_expired = toPickerDateTime(p.date_expired)
    form.is_active = p.is_active

    const parsed = parseActions(p.actions)
    actionChecks.value = parsed.checks
    actionCustom.value = parsed.custom

    // Pre-populate linked entity IDs from links
    if (detail.links) {
      form.user_ids = detail.links.user_ids ?? []
      form.group_ids = detail.links.group_ids ?? []
      form.asset_ids = detail.links.asset_ids ?? []
      form.node_ids = detail.links.node_ids ?? []
      form.account_ids = detail.links.account_ids ?? []
      await loadAccountsForAssets(form.asset_ids)
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to load permission'
    ElMessage.error(msg)
  } finally {
    loadingDetail.value = false
  }
}

async function handleSubmit() {
  if (!formRef.value) return
  try {
    await formRef.value.validate()
  } catch {
    return
  }

  const payload = {
    name: form.name,
    actions: buildActions(),
    date_start: form.date_start || undefined,
    date_expired: form.date_expired || undefined,
    is_active: form.is_active,
    user_ids: form.user_ids.length > 0 ? form.user_ids : undefined,
    group_ids: form.group_ids.length > 0 ? form.group_ids : undefined,
    asset_ids: form.asset_ids.length > 0 ? form.asset_ids : undefined,
    node_ids: form.node_ids.length > 0 ? form.node_ids : undefined,
    account_ids: form.account_ids.length > 0 ? form.account_ids : undefined,
  }

  submitting.value = true
  try {
    if (isEdit.value && permissionId.value) {
      await permissionsApi.update(permissionId.value, payload)
      ElMessage.success('Permission updated')
    } else {
      await permissionsApi.create(payload)
      ElMessage.success('Permission created')
    }
    router.push('/permissions')
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Save failed'
    ElMessage.error(msg)
  } finally {
    submitting.value = false
  }
}

onMounted(async () => {
  await loadOptions()
  if (isEdit.value) {
    await fetchPermission()
  }
})

watch(
  () => form.asset_ids.slice(),
  async (assetIDs) => {
    await loadAccountsForAssets(assetIDs)
    form.account_ids = form.account_ids.filter((accountID) =>
      accounts.value.some((account) => account.id === accountID),
    )
  },
)
</script>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  color: #303133;
}

.page-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 60px 0;
  color: #909399;
}

.perm-form {
  max-width: 640px;
}

.actions-group {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.action-custom {
  margin-top: 4px;
}
</style>
