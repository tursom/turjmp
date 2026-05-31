import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { AccessMap, User, LoginResult } from '@/types'
import * as authApi from '@/api/auth'
import {
  getAccessToken,
  getRefreshToken,
} from '@/utils/token'
import {
  clearStoredAuth,
  type AuthSnapshot,
  persistAuthResult,
  persistAccess,
  readMFASetupRequired,
  readStoredAccess,
  readStoredRoles,
  readStoredUser,
  subscribeAuthChanges,
} from '@/utils/authStorage'
import router, { defaultRouteForAccess } from '@/router'

export const useAuthStore = defineStore('auth', () => {
  const accessToken = ref<string | null>(getAccessToken())
  const refreshToken = ref<string | null>(getRefreshToken())
  const user = ref<User | null>(readStoredUser())
  const roles = ref<string[]>(readStoredRoles())
  const access = ref<AccessMap>(readStoredAccess())
  const mfaSetupRequired = ref(readMFASetupRequired())
  const loginLoading = ref(false)

  const isLoggedIn = computed(() => !!accessToken.value)

  function applySnapshot(snapshot: AuthSnapshot) {
    accessToken.value = snapshot.accessToken
    refreshToken.value = snapshot.refreshToken
    user.value = snapshot.user
    roles.value = snapshot.roles
    access.value = snapshot.access
    mfaSetupRequired.value = snapshot.mfaSetupRequired
  }

  subscribeAuthChanges(applySnapshot)

  function setAuth(result: LoginResult) {
    applySnapshot(persistAuthResult(result))
  }

  async function login(
    username: string,
    password: string,
    mfaCode?: string,
    redirectTo?: string,
  ): Promise<LoginResult> {
    loginLoading.value = true
    try {
      const result = await authApi.login({ username, password, mfa_code: mfaCode })
      if (result.require_mfa) {
        return result
      }
      setAuth(result)
      if (result.require_mfa_setup) {
        await router.push('/mfa-setup')
        return result
      }
      await loadAccess()
      const nextPath =
        redirectTo && redirectTo.startsWith('/') && !redirectTo.startsWith('//')
          ? redirectTo
          : defaultRouteForAccess(access.value)
      await router.push(nextPath)
      return result
    } finally {
      loginLoading.value = false
    }
  }

  async function doLogout() {
    try {
      await authApi.logout()
    } catch {
      // server may be unavailable
    }
    resetAuth()
    await router.push('/login')
  }

  function resetAuth() {
    applySnapshot(clearStoredAuth())
  }

  async function restoreSession() {
    const tok = getAccessToken()
    if (tok) {
      accessToken.value = tok
      refreshToken.value = getRefreshToken()
      user.value = readStoredUser()
      roles.value = readStoredRoles()
      access.value = readStoredAccess()
      mfaSetupRequired.value = readMFASetupRequired()
    }
  }

  async function loadAccess(): Promise<AccessMap> {
    const result = await authApi.access()
    access.value = persistAccess(result).access
    return access.value
  }

  function hasRole(role: string): boolean {
    return roles.value.includes(role)
  }

  function hasAnyRole(roleList: string[]): boolean {
    return roleList.some((r) => roles.value.includes(r))
  }

  function canAccess(key: string): boolean {
    return access.value[key] === true
  }

  return {
    accessToken,
    refreshToken,
    user,
    roles,
    access,
    mfaSetupRequired,
    isLoggedIn,
    loginLoading,
    login,
    doLogout,
    resetAuth,
    restoreSession,
    loadAccess,
    hasRole,
    hasAnyRole,
    canAccess,
  }
})
