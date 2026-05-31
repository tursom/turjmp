import client from './client'
import type { Setting, SettingsByCategory, SSHFingerprint } from '@/types'

export async function list(): Promise<SettingsByCategory> {
  const res = await client.get<SettingsByCategory>('/settings')
  return res.data
}

export async function get(key: string): Promise<Setting> {
  const res = await client.get<Setting>(`/settings/${key}`)
  return res.data
}

export async function update(key: string, value: string): Promise<Setting> {
  const res = await client.put<Setting>(`/settings/${key}`, { value })
  return res.data
}

export async function sshFingerprint(): Promise<SSHFingerprint[]> {
  const res = await client.get<SSHFingerprint[]>('/settings/ssh-fingerprint')
  return res.data
}
