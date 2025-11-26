import { api } from './api'
import { AlertSettings, TestEmailRequest, TestWebhookRequest } from '../types'

export interface SystemCertRequest {
  common_name: string
  subject_alt_names?: string
}

export interface SystemCertResponse {
  message: string
  certificate_id: number
  common_name: string
}

export interface SystemHealthResponse {
  database_connected: boolean
  vault_connected: boolean
  vault_initialized: boolean
  vault_sealed: boolean
  total_certificates: number
  total_cas: number
  missing_keys: string[]
}

export interface SystemConfigResponse {
  vault_configured: boolean
  vault_configured_via_env: boolean
  docker_available: boolean
}

export interface VaultConfigRequest {
  vault_token: string
}

export interface VaultInitResponse {
  root_token: string
  keys: string[]
  message: string
}

export interface Backup {
  filename: string
  size: number
  created_at: string
}

export interface RestoreRequest {
  unseal_keys: string[]
  root_token?: string
  restore_app?: boolean
  restore_vault?: boolean
}

export interface VersionCheckResponse {
  current_version: string
  latest_version: string
  update_available: boolean
  release_url?: string
}

export const systemService = {
  updateSystemCertificate: async (data: SystemCertRequest): Promise<SystemCertResponse> => {
    return api.post<SystemCertResponse>('/system/certificate', data)
  },
  
  getAlertSettings: async (): Promise<AlertSettings> => {
    return api.get<AlertSettings>('/system/settings')
  },

  updateAlertSettings: async (data: AlertSettings): Promise<AlertSettings> => {
    return api.post<AlertSettings>('/system/settings', data)
  },

  sendTestEmail: async (data: TestEmailRequest): Promise<{ message: string }> => {
    return api.post<{ message: string }>('/system/settings/test-email', data)
  },

  sendTestSlack: async (data: TestWebhookRequest): Promise<{ message: string }> => {
    return api.post<{ message: string }>('/system/settings/test-slack', data)
  },

  sendTestDiscord: async (data: TestWebhookRequest): Promise<{ message: string }> => {
    return api.post<{ message: string }>('/system/settings/test-discord', data)
  },

  checkSystemHealth: async (): Promise<SystemHealthResponse> => {
    return api.get<SystemHealthResponse>('/system/health')
  },

  getSystemConfig: async (): Promise<SystemConfigResponse> => {
    return api.get<SystemConfigResponse>('/system/config')
  },

  configureVault: async (data: VaultConfigRequest): Promise<{ message: string }> => {
    return api.post<{ message: string }>('/system/config/vault', data)
  },

  initializeVault: async (): Promise<VaultInitResponse> => {
    return api.post<VaultInitResponse>('/system/config/vault/init', {})
  },

  unsealVault: async (keys: string[]): Promise<{ message: string }> => {
    return api.post<{ message: string }>('/system/config/vault/unseal', { keys })
  },

  resetSystem: async (includeConfig: boolean = false): Promise<{message: string}> => {
    return api.post<{message: string}>('/system/reset', null, { params: { include_config: includeConfig } })
  },

  listBackups: async (): Promise<Backup[]> => {
    return api.get<Backup[]>('/system/backups')
  },
  
  createBackup: async (): Promise<{filename: string, message: string}> => {
    return api.post('/system/backups')
  },
  
  restoreBackup: async (filename: string, data: RestoreRequest): Promise<{message: string}> => {
    return api.post(`/system/backups/${filename}/restore`, data)
  },
  
  deleteBackup: async (filename: string): Promise<{message: string}> => {
    return api.delete(`/system/backups/${filename}`)
  },
  
  uploadBackup: async (file: File): Promise<{message: string, filename: string}> => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/system/backups/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    })
  },

  checkVersion: async (): Promise<VersionCheckResponse> => {
    return api.get<VersionCheckResponse>('/system/version-check')
  }
}
