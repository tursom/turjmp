import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig } from 'axios'
import { clearStoredAuth, persistAuthResult } from '@/utils/authStorage'

type RetriableRequestConfig = AxiosRequestConfig & { _retry?: boolean }

const client: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

// --- Refresh queue management ---
let isRefreshing = false
let failedQueue: Array<{
  resolve: (value?: unknown) => void
  reject: (reason?: unknown) => void
  config: RetriableRequestConfig
}> = []

function processQueue(error: unknown, token: string | null = null) {
  failedQueue.forEach(({ resolve, reject, config }) => {
    if (error) {
      reject(error)
    } else {
      config.headers = config.headers ?? {}
      if (token) {
        config.headers.Authorization = `Bearer ${token}`
      }
      resolve(client(config))
    }
  })
  failedQueue = []
}

function errorMessage(error: unknown): string {
  if (!axios.isAxiosError(error)) {
    return error instanceof Error ? error.message : 'Request failed'
  }
  if (error.response?.data?.error?.message) {
    return error.response.data.error.message
  }
  return error.response?.data?.message || error.message || 'Unknown error'
}

function isLoginRequest(config: RetriableRequestConfig): boolean {
  return (config.url ?? '').includes('/auth/login')
}

function clearAuthAndRedirect() {
  clearStoredAuth()
  // Avoid redirect loop on the login page itself
  if (window.location.pathname !== '/login') {
    window.location.href = '/login'
  }
}

// --- Request interceptor ---
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// --- Response interceptor ---
client.interceptors.response.use(
  // Success: unwrap {data: payload} envelope
  (response) => {
    if (response.data && typeof response.data === 'object' && 'data' in response.data) {
      response.data = response.data.data
    }
    return response
  },

  // Error: handle 401, refresh, and error formatting
  async (error) => {
    const originalRequest = error.config as RetriableRequestConfig

    if (!originalRequest) {
      return Promise.reject(new Error(error.message || 'Request failed'))
    }

    if (error.response?.status === 401) {
      if (isLoginRequest(originalRequest)) {
        return Promise.reject(new Error(errorMessage(error)))
      }

      if (originalRequest.url?.includes('/auth/refresh') || originalRequest._retry) {
        clearAuthAndRedirect()
        return Promise.reject(new Error('Session expired'))
      }

      const refreshTokenValue = localStorage.getItem('refresh_token')
      if (!refreshTokenValue) {
        clearAuthAndRedirect()
        return Promise.reject(new Error('No refresh token'))
      }

      originalRequest._retry = true

      // Queue concurrent requests while refreshing
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject, config: originalRequest })
        })
      }

      isRefreshing = true

      try {
        // Use raw axios — not client — to avoid interceptor recursion
        const { data: refreshResponse } = await axios.post('/api/v1/auth/refresh', {
          refresh_token: refreshTokenValue,
        })
        const payload = refreshResponse?.data ?? refreshResponse
        persistAuthResult(payload)
        processQueue(null, payload.access_token)

        originalRequest.headers = originalRequest.headers ?? {}
        originalRequest.headers.Authorization = `Bearer ${payload.access_token}`
        return client(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        clearAuthAndRedirect()
        return Promise.reject(
          refreshError instanceof Error ? refreshError : new Error('Token refresh failed'),
        )
      } finally {
        isRefreshing = false
      }
    }

    // Transform {error: {code, message}} into thrown Error
    return Promise.reject(new Error(errorMessage(error)))
  },
)

export default client
