import client from './client'
import type { AccessMap, LoginRequest, LoginResult, RefreshRequest } from '@/types'

export async function login(data: LoginRequest): Promise<LoginResult> {
  const res = await client.post<LoginResult>('/auth/login', data)
  return res.data
}

export async function refresh(data: RefreshRequest): Promise<LoginResult> {
  const res = await client.post<LoginResult>('/auth/refresh', data)
  return res.data
}

export async function logout(): Promise<void> {
  await client.post('/auth/logout')
}

export async function access(): Promise<AccessMap> {
  const res = await client.get<{ access: AccessMap }>('/auth/access')
  return res.data.access
}

export async function mfaSetup(): Promise<{ secret: string; url: string }> {
  const res = await client.post<{ secret: string; url: string }>('/auth/mfa/setup')
  return res.data
}

export async function mfaVerify(code: string): Promise<void> {
  await client.post('/auth/mfa/verify', { code })
}
