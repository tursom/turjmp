import type { AccessMap, LoginResult, User } from '@/types'
import {
  getAccessToken,
  getRefreshToken,
  removeTokens,
  setAccessToken,
  setRefreshToken,
} from '@/utils/token'

const USER_KEY = 'auth_user'
const ROLES_KEY = 'auth_roles'
const ACCESS_KEY = 'auth_access'
const MFA_SETUP_REQUIRED_KEY = 'auth_mfa_setup_required'
const AUTH_CHANGED_EVENT = 'turjmp:auth-changed'

export interface AuthSnapshot {
  accessToken: string | null
  refreshToken: string | null
  user: User | null
  roles: string[]
  access: AccessMap
  mfaSetupRequired: boolean
}

export function readStoredUser(): User | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as User
  } catch {
    localStorage.removeItem(USER_KEY)
    return null
  }
}

export function readStoredRoles(): string[] {
  const raw = localStorage.getItem(ROLES_KEY)
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item === 'string') : []
  } catch {
    localStorage.removeItem(ROLES_KEY)
    return []
  }
}

export function readStoredAccess(): AccessMap {
  const raw = localStorage.getItem(ACCESS_KEY)
  if (!raw) return {}
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    return Object.fromEntries(
      Object.entries(parsed as Record<string, unknown>)
        .filter((entry): entry is [string, boolean] => typeof entry[1] === 'boolean'),
    )
  } catch {
    localStorage.removeItem(ACCESS_KEY)
    return {}
  }
}

export function readMFASetupRequired(): boolean {
  return localStorage.getItem(MFA_SETUP_REQUIRED_KEY) === 'true'
}

export function getAuthSnapshot(): AuthSnapshot {
  return {
    accessToken: getAccessToken(),
    refreshToken: getRefreshToken(),
    user: readStoredUser(),
    roles: readStoredRoles(),
    access: readStoredAccess(),
    mfaSetupRequired: readMFASetupRequired(),
  }
}

export function persistAuthResult(result: LoginResult): AuthSnapshot {
  if (!result.access_token || !result.refresh_token || !result.user) {
    throw new Error('Invalid login response')
  }
  setAccessToken(result.access_token)
  setRefreshToken(result.refresh_token)
  localStorage.setItem(USER_KEY, JSON.stringify(result.user))
  localStorage.setItem(ROLES_KEY, JSON.stringify(result.roles ?? []))
  if (result.require_mfa_setup) {
    localStorage.setItem(MFA_SETUP_REQUIRED_KEY, 'true')
  } else {
    localStorage.removeItem(MFA_SETUP_REQUIRED_KEY)
  }
  const snapshot = getAuthSnapshot()
  notifyAuthChanged(snapshot)
  return snapshot
}

export function persistAccess(access: AccessMap): AuthSnapshot {
  localStorage.setItem(ACCESS_KEY, JSON.stringify(access))
  const snapshot = getAuthSnapshot()
  notifyAuthChanged(snapshot)
  return snapshot
}

export function clearStoredAuth(): AuthSnapshot {
  removeTokens()
  localStorage.removeItem(USER_KEY)
  localStorage.removeItem(ROLES_KEY)
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(MFA_SETUP_REQUIRED_KEY)
  const snapshot = getAuthSnapshot()
  notifyAuthChanged(snapshot)
  return snapshot
}

export function subscribeAuthChanges(handler: (snapshot: AuthSnapshot) => void): () => void {
  const listener = (event: Event) => {
    handler((event as CustomEvent<AuthSnapshot>).detail ?? getAuthSnapshot())
  }
  window.addEventListener(AUTH_CHANGED_EVENT, listener)
  return () => window.removeEventListener(AUTH_CHANGED_EVENT, listener)
}

function notifyAuthChanged(snapshot: AuthSnapshot): void {
  window.dispatchEvent(new CustomEvent<AuthSnapshot>(AUTH_CHANGED_EVENT, { detail: snapshot }))
}
