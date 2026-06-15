import client from './client'
import type {
  AccessMap,
  LoginRequest,
  LoginResult,
  RDPProxyCredentialPasswordInput,
  RDPProxyCredentialStatus,
  RefreshRequest,
} from '@/types'

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

export async function getRDPProxyCredential(): Promise<RDPProxyCredentialStatus> {
  const res = await client.get<RDPProxyCredentialStatus>('/auth/rdp-proxy-credential')
  return res.data
}

export async function setRDPProxyCredential(
  data: RDPProxyCredentialPasswordInput,
): Promise<RDPProxyCredentialStatus> {
  const res = await client.put<RDPProxyCredentialStatus>('/auth/rdp-proxy-credential', data)
  return res.data
}

export async function resetRDPProxyCredential(
  data: RDPProxyCredentialPasswordInput,
): Promise<RDPProxyCredentialStatus> {
  const res = await client.post<RDPProxyCredentialStatus>('/auth/rdp-proxy-credential/reset', data)
  return res.data
}

export async function disableRDPProxyCredential(): Promise<RDPProxyCredentialStatus> {
  const res = await client.delete<RDPProxyCredentialStatus>('/auth/rdp-proxy-credential')
  return res.data
}
