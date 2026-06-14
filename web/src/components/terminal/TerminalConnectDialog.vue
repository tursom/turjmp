<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useConnectDialog } from '@/composables/useConnectDialog'
import * as accountsApi from '@/api/assets'
import type { Asset, ConnectParams } from '@/types'

interface Props {
  visible: boolean
  preselectedAssetId?: number
  preselectedAccountId?: number
  preselectedProtocol?: string
  autoConnect?: boolean
}

interface ConnectedResult {
  wsUrl: string
  params: ConnectParams
  assetName: string
  accountName: string
  platformType: string
}

const props = defineProps<Props>()

const emit = defineEmits<{
  'update:visible': [visible: boolean]
  connected: [result: ConnectedResult]
}>()

const dialogVisible = computed({
  get: () => props.visible,
  set: (val: boolean) => emit('update:visible', val),
})

const {
  connecting,
  selectedAsset,
  selectedAccount,
  selectedProtocol,
  accountOptions,
  protocolOptions,
  open,
  close,
  fetchAccounts,
  connect: doConnect,
} = useConnectDialog()

const assetName = ref('')
const platformType = ref('')
const assetOptions = ref<{ value: number; label: string }[]>([])
const assetSearchLoading = ref(false)
const autoConnectStarted = ref(false)

function syncAssetOption(asset: Asset): void {
  assetName.value = asset.name
  const exists = assetOptions.value.some((opt) => opt.value === asset.id)
  if (!exists) {
    assetOptions.value = [{ value: asset.id, label: asset.name }, ...assetOptions.value]
  }
}

async function searchAssets(query: string): Promise<void> {
  assetSearchLoading.value = true
  try {
    const result = await accountsApi.listPaged({
      page: 1,
      per_page: 20,
      search: query || undefined,
      status: 'active',
    })
    assetOptions.value = result.items.map((a) => ({ value: a.id, label: a.name }))
  } catch {
    assetOptions.value = []
  } finally {
    assetSearchLoading.value = false
  }
}

async function onAssetChange(assetId: number): Promise<void> {
  selectedAccount.value = null
  try {
    const [asset, platforms] = await Promise.all([
      accountsApi.get(assetId),
      accountsApi.listPlatforms(),
      fetchAccounts(assetId),
    ])
    syncAssetOption(asset)
    const platform = platforms.find((p) => p.id === asset.platform_id)
    platformType.value = platform?.type ?? ''
  } catch {
    assetName.value = ''
    platformType.value = ''
  }
  if (
    props.preselectedAccountId !== undefined &&
    accountOptions.value.some((opt) => opt.value === props.preselectedAccountId)
  ) {
    selectedAccount.value = props.preselectedAccountId
  } else if (accountOptions.value.length === 1) {
    selectedAccount.value = accountOptions.value[0]?.value ?? null
  }
  if (
    props.autoConnect === true &&
    !autoConnectStarted.value &&
    selectedAsset.value !== null &&
    selectedAccount.value !== null &&
    selectedProtocol.value
  ) {
    autoConnectStarted.value = true
    await handleConnect()
  }
}

const selectedAccountName = computed(() => {
  const opt = accountOptions.value.find(
    (o) => o.value === selectedAccount.value,
  )
  return opt?.label ?? ''
})

const assetModel = computed({
  get: () => selectedAsset.value ?? '',
  set: (val: string | number) => {
    const id = typeof val === 'string' ? parseInt(val, 10) : val
    if (id > 0) {
      onAssetChange(id)
    }
  },
})

const accountModel = computed({
  get: () => selectedAccount.value ?? '',
  set: (val: string | number) => {
    selectedAccount.value = typeof val === 'string' ? parseInt(val, 10) : val
  },
})

const protocolModel = computed({
  get: () => selectedProtocol.value,
  set: (val: string) => {
    selectedProtocol.value = val
  },
})

async function handleConnect(): Promise<void> {
  try {
    const result = await doConnect()
    if (result) {
      emit('connected', {
        wsUrl: result.wsUrl,
        params: result.params,
        assetName: assetName.value,
        accountName: selectedAccountName.value,
        platformType: platformType.value,
      })
      emit('update:visible', false)
    }
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : '未知错误'
    ElMessage.error('连接失败：' + message)
  }
}

watch(
  () => props.visible,
  (val) => {
    if (!val) {
      close()
      assetName.value = ''
      platformType.value = ''
      assetOptions.value = []
      autoConnectStarted.value = false
      return
    }
    open(props.preselectedAssetId, props.preselectedProtocol)
    autoConnectStarted.value = false
    if (props.preselectedAssetId !== undefined) {
      void onAssetChange(props.preselectedAssetId)
    } else {
      void searchAssets('')
    }
  },
)
</script>

<template>
  <el-dialog
    v-model="dialogVisible"
    title="新建终端连接"
    width="500px"
    destroy-on-close
  >
    <el-select
      v-model="assetModel"
      filterable
      remote
      :remote-method="searchAssets"
      :loading="assetSearchLoading"
      placeholder="选择资产"
      class="dialog-field"
    >
      <el-option
        v-for="opt in assetOptions"
        :key="opt.value"
        :label="opt.label"
        :value="opt.value"
      />
    </el-select>

    <el-select
      v-model="accountModel"
      placeholder="选择账号"
      :disabled="!selectedAsset"
      class="dialog-field"
    >
      <el-option
        v-for="opt in accountOptions"
        :key="opt.value"
        :label="opt.label"
        :value="opt.value"
      />
    </el-select>

    <el-select
      v-model="protocolModel"
      placeholder="选择协议"
      :disabled="!selectedAsset || protocolOptions.length === 0"
      class="dialog-field"
    >
      <el-option
        v-for="opt in protocolOptions"
        :key="opt.id"
        :label="opt.name.toUpperCase()"
        :value="opt.name"
      />
    </el-select>

    <el-alert
      v-if="selectedAsset && protocolOptions.length === 0"
      title="该资产暂无可用的 Web 终端协议"
      type="warning"
      :closable="false"
      class="dialog-alert"
    />

    <template #footer>
      <el-button @click="emit('update:visible', false)">取消</el-button>
      <el-button
        type="primary"
        :loading="connecting"
        :disabled="!selectedAsset || !selectedAccount || !selectedProtocol"
        @click="handleConnect"
      >
        连接
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.dialog-field {
  width: 100%;
  margin-bottom: 16px;
}

.dialog-alert {
  margin-bottom: 16px;
}
</style>
