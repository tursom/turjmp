import client from './client'
import type { ConnectionTokenResult, SDKURLResult, IssueTokenInput, SDKURLInput } from '@/types'

export async function createConnectionToken(data: IssueTokenInput): Promise<ConnectionTokenResult> {
  const res = await client.post<ConnectionTokenResult>('/authentication/connection-tokens/', data)
  return res.data
}

export async function getSDKUrl(data: SDKURLInput): Promise<SDKURLResult> {
  const res = await client.get<SDKURLResult>('/authentication/connection-tokens/sdk-url', {
    params: data,
  })
  return res.data
}

export async function createSDKUrl(data: SDKURLInput): Promise<SDKURLResult> {
  const res = await client.post<SDKURLResult>('/authentication/connection-tokens/sdk-url', data)
  return res.data
}
