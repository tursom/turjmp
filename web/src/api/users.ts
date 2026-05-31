import client from './client'
import type { User, CreateUserInput, UpdateUserInput, UserDetail } from '@/types'

export async function list(params?: Record<string, unknown>): Promise<User[]> {
  const res = await client.get<User[]>('/users', { params })
  return res.data
}

export async function create(data: CreateUserInput): Promise<User> {
  const res = await client.post<User>('/users', data)
  return res.data
}

export async function get(id: number): Promise<UserDetail> {
  const res = await client.get<UserDetail>(`/users/${id}`)
  return res.data
}

export async function update(id: number, data: UpdateUserInput): Promise<User> {
  const res = await client.put<User>(`/users/${id}`, data)
  return res.data
}

export async function remove(id: number): Promise<void> {
  await client.delete(`/users/${id}`)
}
