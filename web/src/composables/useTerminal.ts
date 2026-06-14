import { ref } from 'vue'
import type { Ref } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'

const draculaTheme = {
  foreground: '#F8F8F2',
  background: '#282A36',
  cursor: '#F8F8F2',
  selectionBackground: '#44475A',
  black: '#21222C',
  red: '#FF5555',
  green: '#50FA7B',
  yellow: '#F1FA8C',
  blue: '#BD93F9',
  magenta: '#FF79C6',
  cyan: '#8BE9FD',
  white: '#F8F8F2',
  brightBlack: '#6272A4',
  brightRed: '#FF6E6E',
  brightGreen: '#69FF94',
  brightYellow: '#FFFFA5',
  brightBlue: '#D6ACFF',
  brightMagenta: '#FF92DF',
  brightCyan: '#A4FFFF',
  brightWhite: '#FFFFFF',
}

export function useTerminal() {
  const terminal: Ref<Terminal | null> = ref(null)
  const fitAddon: Ref<FitAddon | null> = ref(null)

  function mount(element: HTMLElement): void {
    const fit = new FitAddon()
    const webLinks = new WebLinksAddon()
    const term = new Terminal({
      theme: draculaTheme,
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
    })
    term.loadAddon(fit)
    term.loadAddon(webLinks)
    term.open(element)
    fit.fit()
    terminal.value = term
    fitAddon.value = fit
  }

  function dispose(): void {
    terminal.value?.dispose()
    fitAddon.value?.dispose()
    terminal.value = null
    fitAddon.value = null
  }

  return { terminal, fitAddon, mount, dispose }
}
