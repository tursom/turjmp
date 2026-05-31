import client from './client'
import type { AuditLog, AuditLogListResponse } from '@/types'

export async function list(params?: Record<string, unknown>): Promise<AuditLog[]> {
  const res = await client.get<AuditLogListResponse>('/audit-logs', { params })
  return res.data.items
}

export async function listPaged(params?: Record<string, unknown>): Promise<AuditLogListResponse> {
  const res = await client.get<AuditLogListResponse>('/audit-logs', { params })
  return res.data
}
