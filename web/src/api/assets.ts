import client from './client'
import type {
  AssetTreeData,
  AssetWithPlatform,
  CreateAssetInput,
  Asset,
  Account,
  AccountInput,
  Platform,
  PlatformProtocol,
  AssetListResponse,
  CreatePlatformInput,
} from '@/types'

export async function getTree(): Promise<AssetTreeData> {
  const res = await client.get<AssetTreeData>('/assets/tree')
  return res.data
}

export async function list(params?: Record<string, unknown>): Promise<AssetWithPlatform[]> {
  const res = await client.get<AssetWithPlatform[]>('/assets', { params })
  return res.data
}

export async function listPaged(params: Record<string, unknown>): Promise<AssetListResponse> {
  const res = await client.get<AssetListResponse>('/assets', { params })
  return res.data
}

export async function create(data: CreateAssetInput): Promise<Asset> {
  const res = await client.post<Asset>('/assets', data)
  return res.data
}

export async function get(id: number): Promise<Asset> {
  const res = await client.get<Asset>(`/assets/${id}`)
  return res.data
}

export async function update(id: number, data: Partial<CreateAssetInput>): Promise<Asset> {
  const res = await client.put<Asset>(`/assets/${id}`, data)
  return res.data
}

export async function remove(id: number): Promise<void> {
  await client.delete(`/assets/${id}`)
}

export async function listAccounts(assetId: number): Promise<Account[]> {
  const res = await client.get<Account[]>(`/assets/${assetId}/accounts`)
  return res.data
}

export async function createAccount(assetId: number, data: AccountInput): Promise<Account> {
  const res = await client.post<Account>(`/assets/${assetId}/accounts`, data)
  return res.data
}

export async function getAccount(assetId: number, accountId: number): Promise<Account> {
  const res = await client.get<Account>(`/assets/${assetId}/accounts/${accountId}`)
  return res.data
}

export async function updateAccount(
  assetId: number,
  accountId: number,
  data: Partial<AccountInput>,
): Promise<Account> {
  const res = await client.put<Account>(`/assets/${assetId}/accounts/${accountId}`, data)
  return res.data
}

export async function deleteAccount(assetId: number, accountId: number): Promise<void> {
  await client.delete(`/assets/${assetId}/accounts/${accountId}`)
}

export async function listPlatforms(): Promise<Platform[]> {
  const res = await client.get<Platform[]>('/platforms')
  return res.data
}

export async function listPlatformProtocols(platformId: number): Promise<PlatformProtocol[]> {
  const res = await client.get<PlatformProtocol[]>(`/platforms/${platformId}/protocols`)
  return res.data
}

export async function createPlatform(data: CreatePlatformInput): Promise<Platform> {
  const res = await client.post<Platform>('/platforms', data)
  return res.data
}
