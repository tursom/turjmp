import { createRouter, createWebHistory } from 'vue-router'
import axios from 'axios'
import AppLayout from '@/components/layout/AppLayout.vue'
import { getAccessToken } from '@/utils/token'
import {
  clearStoredAuth,
  persistAccess,
  readMFASetupRequired,
  readStoredAccess,
  readStoredRoles,
} from '@/utils/authStorage'
import { applyDocumentTitle } from '@/utils/branding'
import type { AccessMap } from '@/types'

const NO_ACCESS_PATH = '/403'

function hasAccess(required: string | undefined, access: AccessMap): boolean {
  if (!required) return true
  return access[required] === true
}

export function defaultRouteForAccess(access: AccessMap = readStoredAccess()): string {
  for (const route of ACCESSIBLE_ROUTE_FALLBACKS) {
    if (hasAccess(route.access, access)) return route.path
  }
  return NO_ACCESS_PATH
}

const ACCESSIBLE_ROUTE_FALLBACKS = [
  { path: '/dashboard', access: 'dashboard' },
  { path: '/sessions', access: 'sessions' },
  { path: '/audit-logs', access: 'audit_logs' },
  { path: '/assets', access: 'assets' },
  { path: '/users', access: 'users' },
  { path: '/roles', access: 'roles' },
  { path: '/permissions', access: 'permissions' },
  { path: '/settings', access: 'settings' },
]

async function ensureAccess(token: string): Promise<AccessMap> {
  const stored = readStoredAccess()
  if (Object.values(stored).some(Boolean)) return stored
  try {
    const { data } = await axios.get('/api/v1/auth/access', {
      headers: { Authorization: `Bearer ${token}` },
    })
    const payload = data?.data ?? data
    return persistAccess(payload.access ?? {}).access
  } catch {
    return stored
  }
}

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/login/LoginView.vue'),
  },
  {
    path: NO_ACCESS_PATH,
    name: 'NoAccess',
    component: () => import('@/views/error/NoAccessView.vue'),
    meta: { title: '无访问权限' },
  },
  {
    path: '/mfa-setup',
    name: 'MFASetup',
    component: () => import('@/views/login/MFASetupView.vue'),
  },
  {
    path: '/',
    component: AppLayout,
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/DashboardView.vue'),
        meta: { title: '仪表盘', access: 'dashboard' },
      },
      {
        path: 'assets',
        name: 'Assets',
        component: () => import('@/views/assets/AssetListView.vue'),
        meta: { title: '资产', access: 'assets' },
      },
      {
        path: 'assets/new',
        name: 'AssetCreate',
        component: () => import('@/views/assets/AssetFormView.vue'),
        meta: { title: '新建资产', access: 'asset_create' },
      },
      {
        path: 'assets/:id',
        name: 'AssetDetail',
        component: () => import('@/views/assets/AssetDetailView.vue'),
        meta: { title: '资产详情', access: 'assets' },
      },
      {
        path: 'assets/:id/edit',
        name: 'AssetEdit',
        component: () => import('@/views/assets/AssetFormView.vue'),
        meta: { title: '编辑资产', access: 'asset_update' },
      },
      {
        path: 'platforms',
        name: 'Platforms',
        component: () => import('@/views/assets/PlatformListView.vue'),
        meta: { title: '平台模板', access: 'platforms' },
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('@/views/users/UserListView.vue'),
        meta: { title: '用户', access: 'users' },
      },
      {
        path: 'users/new',
        name: 'UserCreate',
        component: () => import('@/views/users/UserFormView.vue'),
        meta: { title: '新建用户', access: 'user_create' },
      },
      {
        path: 'users/:id/edit',
        name: 'UserEdit',
        component: () => import('@/views/users/UserFormView.vue'),
        meta: { title: '编辑用户', access: 'user_update' },
      },
      {
        path: 'roles',
        name: 'Roles',
        component: () => import('@/views/roles/RoleListView.vue'),
        meta: { title: '角色', access: 'roles' },
      },
      {
        path: 'roles/:id',
        name: 'RoleEdit',
        component: () => import('@/views/roles/RoleEditView.vue'),
        meta: { title: '编辑角色', access: 'role_update' },
      },
      {
        path: 'permissions',
        name: 'Permissions',
        component: () => import('@/views/permissions/AssetPermissionListView.vue'),
        meta: { title: '资产授权', access: 'permissions' },
      },
      {
        path: 'permissions/new',
        name: 'PermissionCreate',
        component: () => import('@/views/permissions/AssetPermissionFormView.vue'),
        meta: { title: '新建授权', access: 'permission_create' },
      },
      {
        path: 'permissions/:id/edit',
        name: 'PermissionEdit',
        component: () => import('@/views/permissions/AssetPermissionFormView.vue'),
        meta: { title: '编辑授权', access: 'permission_update' },
      },
      {
        path: 'sessions',
        name: 'Sessions',
        component: () => import('@/views/sessions/SessionListView.vue'),
        meta: { title: '会话', access: 'sessions' },
      },
      {
        path: 'sessions/:id',
        name: 'SessionDetail',
        component: () => import('@/views/sessions/SessionDetailView.vue'),
        meta: { title: '会话详情', access: 'sessions' },
      },
      {
        path: 'audit-logs',
        name: 'AuditLogs',
        component: () => import('@/views/audit/AuditLogView.vue'),
        meta: { title: '审计日志', access: 'audit_logs' },
      },
      {
        path: 'settings/ssh-fingerprint',
        name: 'SSHFingerprint',
        component: () => import('@/views/settings/SSHFingerprintView.vue'),
        meta: { title: 'SSH 指纹', access: 'settings' },
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/settings/SettingsView.vue'),
        meta: { title: '系统设置', access: 'settings' },
      },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const token = getAccessToken()
  const roles = readStoredRoles()
  const mfaSetupRequired = readMFASetupRequired()

  const title = to.meta?.title as string | undefined
  applyDocumentTitle(title)

  if (to.path === '/login') {
    if (token) {
      if (mfaSetupRequired) {
        return { path: '/mfa-setup', replace: true }
      }
      if (roles.length === 0) {
        clearStoredAuth()
        return true
      }
      const access = await ensureAccess(token)
      return { path: defaultRouteForAccess(access), replace: true }
    }
    return true
  }

  if (to.path === '/mfa-setup') {
    if (token) {
      if (mfaSetupRequired) {
        return true
      }
      if (roles.length === 0) {
        clearStoredAuth()
        return {
          path: '/login',
          query: { redirect: to.fullPath },
          replace: true,
        }
      }
      const access = await ensureAccess(token)
      return { path: defaultRouteForAccess(access), replace: true }
    }
    return {
      path: '/login',
      query: { redirect: to.fullPath },
      replace: true,
    }
  }

  if (!token) {
    return {
      path: '/login',
      query: to.fullPath !== '/' ? { redirect: to.fullPath } : undefined,
      replace: true,
    }
  }

  if (roles.length === 0) {
    if (mfaSetupRequired) {
      return {
        path: '/mfa-setup',
        replace: true,
      }
    }
    clearStoredAuth()
    return {
      path: '/login',
      query: to.fullPath !== '/' ? { redirect: to.fullPath } : undefined,
      replace: true,
    }
  }

  if (to.path === NO_ACCESS_PATH) {
    return true
  }

  const access = await ensureAccess(token)
  const requiredAccess = to.meta?.access as string | undefined
  if (!hasAccess(requiredAccess, access)) {
    const fallback = defaultRouteForAccess(access)
    if (fallback !== to.path) {
      return { path: fallback, replace: true }
    }
    return { path: NO_ACCESS_PATH, replace: true }
  }

  return true
})

export default router
