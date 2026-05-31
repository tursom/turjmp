import { defineStore } from 'pinia'
import { ref } from 'vue'
import * as settingsApi from '@/api/settings'
import {
  applyDocumentTitle,
  getStoredSiteName,
  parseSettingString,
  setStoredSiteName,
} from '@/utils/branding'

export const useAppStore = defineStore('app', () => {
  const sidebarCollapse = ref(false)
  const globalLoading = ref(false)
  const siteName = ref(getStoredSiteName())

  function toggleSidebar() {
    sidebarCollapse.value = !sidebarCollapse.value
  }

  function setLoading(loading: boolean) {
    globalLoading.value = loading
  }

  function setSiteName(name: string, pageTitle?: string) {
    siteName.value = setStoredSiteName(name)
    applyDocumentTitle(pageTitle)
  }

  async function loadBranding(pageTitle?: string) {
    try {
      const setting = await settingsApi.get('branding.site_name')
      setSiteName(parseSettingString(setting.value), pageTitle)
    } catch {
      applyDocumentTitle(pageTitle)
    }
  }

  return {
    sidebarCollapse,
    globalLoading,
    siteName,
    toggleSidebar,
    setLoading,
    setSiteName,
    loadBranding,
  }
})
