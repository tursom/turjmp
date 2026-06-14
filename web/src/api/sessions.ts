import client from './client'
import type {
  AuditLog,
  DashboardSummary,
  Session,
  SessionRecording,
  StreamTokenResult,
} from '@/types'

export async function dashboardSummary(): Promise<DashboardSummary> {
  const res = await client.get<DashboardSummary>('/dashboard/summary')
  return res.data
}

export async function list(params?: Record<string, unknown>): Promise<Session[]> {
  const res = await client.get<Session[]>('/sessions', { params })
  return res.data
}

export async function createStreamToken(): Promise<StreamTokenResult> {
  const res = await client.post<StreamTokenResult>('/sessions/stream-token')
  return res.data
}

export async function get(id: number): Promise<Session> {
  const res = await client.get<Session>(`/sessions/${id}`)
  return res.data
}

export async function forceFinish(id: number): Promise<Session> {
  const res = await client.post<Session>(`/sessions/${id}/force-finish`)
  return res.data
}

export async function recording(id: number): Promise<SessionRecording> {
  const res = await client.get<SessionRecording>(`/sessions/${id}/recording`)
  return res.data
}

export async function downloadRecordingContent(id: number): Promise<string> {
  const res = await client.get<string>(`/sessions/${id}/recording`, {
    params: { download: 1 },
    responseType: 'text',
  })
  return res.data
}

export async function listCommands(id: number): Promise<AuditLog[]> {
  const res = await client.get<AuditLog[]>(`/sessions/${id}/commands`)
  return res.data
}
