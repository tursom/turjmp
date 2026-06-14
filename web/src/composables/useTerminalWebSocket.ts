import { ref, onUnmounted } from 'vue'
import type { Ref } from 'vue'
import { useTerminal } from './useTerminal'

type TerminalInstance = ReturnType<typeof useTerminal>

export function useTerminalWebSocket(terminal: TerminalInstance) {
  const status: Ref<'connecting' | 'connected' | 'disconnected'> = ref('disconnected')

  let ws: WebSocket | null = null
  let onDataDisposable: { dispose(): void } | null = null
  let onResizeDisposable: { dispose(): void } | null = null

  function attachTerminalHandlers(): void {
    onDataDisposable?.dispose()
    onResizeDisposable?.dispose()

    onDataDisposable = terminal.terminal.value?.onData((data: string) => {
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data))
      }
    }) ?? null

    onResizeDisposable = terminal.terminal.value?.onResize((size: { rows: number; cols: number }) => {
      if (ws?.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', rows: size.rows, cols: size.cols }))
      }
    }) ?? null
  }

  function sendCurrentSize(): void {
    const current = terminal.terminal.value
    if (!current || ws?.readyState !== WebSocket.OPEN) return
    ws.send(JSON.stringify({ type: 'resize', rows: current.rows, cols: current.cols }))
  }

  function detachTerminalHandlers(): void {
    onDataDisposable?.dispose()
    onResizeDisposable?.dispose()
    onDataDisposable = null
    onResizeDisposable = null
  }

  function connect(url: string): void {
    if (!url) return
    if (ws?.readyState === WebSocket.OPEN || ws?.readyState === WebSocket.CONNECTING) return

    status.value = 'connecting'
    ws = new WebSocket(url)
    ws.binaryType = 'arraybuffer'

    ws.onopen = () => {
      status.value = 'connected'
      attachTerminalHandlers()
      terminal.fitAddon.value?.fit()
      sendCurrentSize()
    }

    ws.onmessage = (event: MessageEvent) => {
      if (event.data instanceof ArrayBuffer) {
        terminal.terminal.value?.write(new Uint8Array(event.data))
      } else if (typeof event.data === 'string') {
        try {
          const msg: unknown = JSON.parse(event.data)
          if (msg !== null && typeof msg === 'object' && 'type' in msg && (msg as Record<string, unknown>).type === 'resize') return
        } catch {
          terminal.terminal.value?.write(event.data)
        }
      }
    }

    ws.onclose = () => {
      status.value = 'disconnected'
      detachTerminalHandlers()
    }

    ws.onerror = () => {
      detachTerminalHandlers()
      status.value = 'disconnected'
    }
  }

  function disconnect(): void {
    detachTerminalHandlers()
    if (ws !== null) {
      ws.close()
      ws = null
    }
    status.value = 'disconnected'
  }

  onUnmounted(() => {
    disconnect()
    terminal.dispose()
  })

  return { status, connect, disconnect }
}
