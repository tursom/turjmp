import client from './client'
import type { AssetPermission, PermissionInput, PermissionDetail } from '@/types'

export async function list(params?: Record<string, unknown>): Promise<AssetPermission[]> {
  const res = await client.get<AssetPermission[]>('/permissions', { params })
  return res.data
}

export async function create(data: PermissionInput): Promise<AssetPermission> {
  const res = await client.post<AssetPermission>('/permissions', data)
  return res.data
}

export async function get(id: number): Promise<PermissionDetail> {
  const res = await client.get<PermissionDetail>(`/permissions/${id}`)
  return res.data
}

export async function update(
  id: number,
  data: Partial<PermissionInput>,
): Promise<AssetPermission> {
  const res = await client.put<AssetPermission>(`/permissions/${id}`, data)
  return res.data
}

export async function remove(id: number): Promise<void> {
  await client.delete(`/permissions/${id}`)
}
