import type { AccessMap, PlatformProtocol } from '@/types'

const DB_PROTOCOLS = new Set(['mysql', 'postgres', 'postgresql'])
const SUPPORTED_WEB_TERMINAL_PROTOCOLS = new Set(['ssh', ...DB_PROTOCOLS])
const WEB_TERMINAL_REQUIRED_ACCESS = [
  'connection_tokens',
  'assets',
  'accounts',
  'platforms',
  'platform_protocols',
] as const

export function normalizeProtocol(protocol?: string): string {
  return (protocol ?? '').trim().toLowerCase()
}

export function isDatabaseProtocol(protocol?: string): boolean {
  return DB_PROTOCOLS.has(normalizeProtocol(protocol))
}

export function isSupportedWebTerminalProtocol(protocol?: string): boolean {
  return SUPPORTED_WEB_TERMINAL_PROTOCOLS.has(normalizeProtocol(protocol))
}

export function canUseWebTerminal(access: AccessMap): boolean {
  return WEB_TERMINAL_REQUIRED_ACCESS.every((key) => access[key] === true)
}

export function webTerminalConnectMethod(protocol?: string): string {
  return isDatabaseProtocol(protocol) ? 'web_db' : 'web_cli'
}

export function supportedWebTerminalProtocols(protocols: PlatformProtocol[]): PlatformProtocol[] {
  return protocols.filter((protocol) => isSupportedWebTerminalProtocol(protocol.name))
}

export function defaultWebTerminalProtocolForPlatformType(platformType?: string): string | undefined {
  switch (normalizeProtocol(platformType)) {
    case 'linux':
      return 'ssh'
    case 'mysql':
      return 'mysql'
    case 'postgres':
    case 'postgresql':
      return 'postgres'
    default:
      return undefined
  }
}

export function isKnownUnsupportedWebTerminalPlatform(platformType?: string): boolean {
  return ['windows', 'rdp', 'vnc', 'telnet', 'redis'].includes(normalizeProtocol(platformType))
}

export function buildWebTerminalWsUrl(protocol: string, token: string): string {
  const normalized = normalizeProtocol(protocol)
  if (!isSupportedWebTerminalProtocol(normalized)) {
    throw new Error(`暂不支持 ${protocol} Web 终端`)
  }
  const path = isDatabaseProtocol(normalized) ? '/ws/db-terminal' : '/ws/terminal'
  const wsScheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const params = new URLSearchParams({ token })
  if (isDatabaseProtocol(normalized)) {
    params.set('protocol', normalized)
  }
  return `${wsScheme}://${window.location.host}${path}?${params.toString()}`
}
