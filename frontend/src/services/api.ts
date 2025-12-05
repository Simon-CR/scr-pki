import axios, { AxiosInstance, AxiosResponse, AxiosRequestConfig } from 'axios'
import { tokenStorage } from '../utils/tokenStorage'

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

// Create axios instance
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = tokenStorage.getAccessToken()
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle token refresh
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    return response
  },
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      // Don't attempt to refresh token if the failed request was a login attempt
      if (originalRequest.url?.includes('/auth/login')) {
        return Promise.reject(error)
      }

      originalRequest._retry = true

      try {
        const refreshToken = tokenStorage.getRefreshToken()
        if (!refreshToken) {
          throw new Error('No refresh token available')
        }

        // Try to refresh the token
        const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
          refresh_token: refreshToken
        })

        const { access_token, refresh_token: newRefreshToken } = response.data
        tokenStorage.setTokens(access_token, newRefreshToken)

        // Retry the original request with new token
        originalRequest.headers.Authorization = `Bearer ${access_token}`
        return apiClient(originalRequest)

      } catch (refreshError) {
        // Refresh failed, clear tokens and redirect to login
        tokenStorage.clearTokens()
        window.location.href = '/login'
        return Promise.reject(refreshError)
      }
    }

    return Promise.reject(error)
  }
)

export { apiClient }

// Generic API methods
export const api = {
  get: <T>(url: string, params?: any): Promise<T> =>
    apiClient.get(url, { params }).then(response => response.data),

  post: <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> =>
    apiClient.post(url, data, config).then(response => response.data),

  put: <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> =>
    apiClient.put(url, data, config).then(response => response.data),

  patch: <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> =>
    apiClient.patch(url, data, config).then(response => response.data),

  delete: <T>(url: string, config?: AxiosRequestConfig): Promise<T> =>
    apiClient.delete(url, config).then(response => response.data),

  // Helper for form data uploads
  postFormData: <T>(url: string, formData: FormData): Promise<T> =>
    apiClient.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    }).then(response => response.data),

  // Helper for URL-encoded form data
  postUrlEncoded: <T>(url: string, data: URLSearchParams): Promise<T> =>
    apiClient.post(url, data, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }).then(response => response.data),
}

export const getApiErrorMessage = (error: unknown, fallback: string): string => {
  if (error && typeof error === 'object' && 'response' in error) {
    const err = error as { response?: { data?: { detail?: string | any[]; message?: string }; status?: number }; message?: string }
    const detail = err.response?.data?.detail || err.response?.data?.message
    
    if (detail) {
      if (Array.isArray(detail)) {
        // Handle FastAPI validation errors
        return detail.map(e => e.msg || JSON.stringify(e)).join(', ')
      }
      return String(detail)
    }
    if (err.message) {
      return err.message
    }
  }
  if (error instanceof Error) {
    return error.message || fallback
  }
  return fallback
}