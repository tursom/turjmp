import client from './client'
import type { Role, CreateRoleInput, RoleDetail, SetPermissionsInput, PermissionRule } from '@/types'

export async function list(): Promise<Role[]> {
  const res = await client.get<Role[]>('/roles')
  return res.data
}

export async function create(data: CreateRoleInput): Promise<Role> {
  const res = await client.post<Role>('/roles', data)
  return res.data
}

export async function get(id: number): Promise<RoleDetail> {
  const res = await client.get<RoleDetail>(`/roles/${id}`)
  return res.data
}

export async function update(id: number, data: Partial<CreateRoleInput>): Promise<Role> {
  const res = await client.put<Role>(`/roles/${id}`, data)
  return res.data
}

export async function remove(id: number): Promise<void> {
  await client.delete(`/roles/${id}`)
}

export async function setPermissions(id: number, data: SetPermissionsInput): Promise<PermissionRule[]> {
  const res = await client.post<PermissionRule[]>(`/roles/${id}/permissions`, data)
  return res.data
}
