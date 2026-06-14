import { ref } from 'vue'
import type { Ref } from 'vue'
import type { TerminalTabState } from '@/types'

export const MAX_TERMINAL_TABS = 10

export function useTerminalTabs() {
  const tabs: Ref<TerminalTabState[]> = ref([])
  const activeTabId: Ref<string | null> = ref(null)

  function addTab(state: Omit<TerminalTabState, 'id' | 'duration' | 'connectedAt'>): string {
    if (tabs.value.length >= MAX_TERMINAL_TABS) {
      return ''
    }
    const id = crypto.randomUUID()
    const newTab: TerminalTabState = {
      ...state,
      id,
      duration: 0,
      connectedAt: null,
    }
    tabs.value.push(newTab)
    activeTabId.value = id
    return id
  }

  function closeTab(id: string): void {
    const tab = tabs.value.find((t) => t.id === id)
    if (!tab || tab.status === 'connected') return

    tabs.value = tabs.value.filter((t) => t.id !== id)
    if (activeTabId.value === id) {
      activeTabId.value = tabs.value.length > 0 ? (tabs.value[0]?.id ?? null) : null
    }
  }

  function switchTab(id: string): void {
    if (tabs.value.some((t) => t.id === id)) {
      activeTabId.value = id
    }
  }

  return { tabs, activeTabId, addTab, closeTab, switchTab }
}
