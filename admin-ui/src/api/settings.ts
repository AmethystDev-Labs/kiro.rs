import axios from 'axios'
import { storage } from '@/lib/storage'
import type { SettingsResponse, UpdateSettingsRequest } from '@/types/api'

const api = axios.create({
  baseURL: '/api/admin',
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const apiKey = storage.getApiKey()
  if (apiKey) {
    config.headers['x-api-key'] = apiKey
  }
  return config
})

export async function getSettings(): Promise<SettingsResponse> {
  const { data } = await api.get<SettingsResponse>('/settings')
  return data
}

export async function updateSettings(
  req: UpdateSettingsRequest
): Promise<SettingsResponse> {
  const { data } = await api.post<SettingsResponse>('/settings', req)
  return data
}
