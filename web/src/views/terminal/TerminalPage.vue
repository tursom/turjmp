<script setup lang="ts">
import { useRoute } from 'vue-router'
import TerminalView from '@/components/terminal/TerminalView.vue'

const route = useRoute()
const preselectedAssetId = route.query.asset_id ? Number(route.query.asset_id) : undefined
const preselectedAccountId = route.query.account_id ? Number(route.query.account_id) : undefined
const preselectedProtocol = typeof route.query.protocol === 'string' ? route.query.protocol : undefined
const autoConnect = route.query.auto_connect === '1'
</script>

<template>
  <TerminalView
    :preselected-asset-id="preselectedAssetId"
    :preselected-account-id="preselectedAccountId"
    :preselected-protocol="preselectedProtocol"
    :auto-connect="autoConnect"
  />
</template>
