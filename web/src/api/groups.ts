import client from './client'
import type { UserGroup } from '@/types'

export async function list(): Promise<UserGroup[]> {
  const res = await client.get<UserGroup[]>('/user-groups')
  return res.data
}
