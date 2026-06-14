import { ref } from 'vue'
import type { Ref } from 'vue'
import type { ConnectParams, PlatformProtocol } from '@/types'
import * as accountsApi from '@/api/assets'
import * as tokensApi from '@/api/tokens'
import {
  buildWebTerminalWsUrl,
  normalizeProtocol,
  supportedWebTerminalProtocols,
  webTerminalConnectMethod,
} from '@/utils/terminal'

interface AccountOption {
  value: number
  label: string
}

export function useConnectDialog() {
  const visible: Ref<boolean> = ref(false)
  const connecting: Ref<boolean> = ref(false)
  const selectedAsset: Ref<number | null> = ref(null)
  const selectedAccount: Ref<number | null> = ref(null)
  const selectedProtocol: Ref<string> = ref('')
  const accountOptions: Ref<AccountOption[]> = ref([])
  const protocolOptions: Ref<PlatformProtocol[]> = ref([])

  function open(preselectedAssetId?: number, preselectedProtocol?: string): void {
    visible.value = true
    connecting.value = false
    selectedAccount.value = null
    selectedProtocol.value = normalizeProtocol(preselectedProtocol)
    accountOptions.value = []
    protocolOptions.value = []
    if (preselectedAssetId !== undefined) {
      selectedAsset.value = preselectedAssetId
    } else {
      selectedAsset.value = null
    }
  }

  function close(): void {
    visible.value = false
    connecting.value = false
    selectedAsset.value = null
    selectedAccount.value = null
    selectedProtocol.value = ''
    accountOptions.value = []
    protocolOptions.value = []
  }

  async function fetchAccounts(assetId: number): Promise<void> {
    selectedAsset.value = assetId
    selectedAccount.value = null
    accountOptions.value = []
    const preferredProtocol = selectedProtocol.value

    const [accounts, asset] = await Promise.all([
      accountsApi.listAccounts(assetId),
      accountsApi.get(assetId),
    ])

    if (!asset.is_active) {
      selectedProtocol.value = ''
      return
    }

    accountOptions.value = accounts
      .filter((a) => a.is_active)
      .map((a) => ({
        value: a.id,
        label: a.username,
      }))

    protocolOptions.value = supportedWebTerminalProtocols(
      await accountsApi.listPlatformProtocols(asset.platform_id),
    )
    if (
      preferredProtocol &&
      protocolOptions.value.some((item) => normalizeProtocol(item.name) === preferredProtocol)
    ) {
      selectedProtocol.value = preferredProtocol
    } else {
      selectedProtocol.value = normalizeProtocol(protocolOptions.value[0]?.name)
    }
  }

  async function connect(): Promise<{ wsUrl: string; params: ConnectParams } | null> {
    const protocol = normalizeProtocol(selectedProtocol.value)
    if (selectedAsset.value === null || selectedAccount.value === null || !protocol) {
      return null
    }
    const connectMethod = webTerminalConnectMethod(protocol)

    connecting.value = true
    try {
      const result = await tokensApi.createConnectionToken({
        asset_id: selectedAsset.value,
        account_id: selectedAccount.value,
        protocol,
        connect_method: connectMethod,
      })

      return {
        wsUrl: buildWebTerminalWsUrl(protocol, result.token),
        params: {
          assetId: selectedAsset.value,
          accountId: selectedAccount.value,
          protocol,
          connectMethod,
        },
      }
    } finally {
      connecting.value = false
    }
  }

  return {
    visible,
    connecting,
    selectedAsset,
    selectedAccount,
    selectedProtocol,
    accountOptions,
    protocolOptions,
    open,
    close,
    fetchAccounts,
    connect,
  }
}
