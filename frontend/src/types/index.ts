// Authentication types
export type UserRole = 'admin' | 'operator' | 'viewer'

export interface User {
  id: number
  username: string
  email: string
  full_name: string
  role: UserRole
  is_active: boolean
  is_superuser?: boolean
  created_at: string
  last_login?: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
  user: User
}

export interface TokenRefreshRequest {
  refresh_token: string
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
}

// Certificate types
export interface Certificate {
  id: number
  common_name: string
  subject_alt_names: string[]
  certificate_type: 'server' | 'wildcard' | 'ip'
  key_size: number
  signature_algorithm: string
  serial_number: string
  status: 'pending' | 'active' | 'expired' | 'revoked'
  issued_at: string
  not_valid_before: string
  not_valid_after: string
  days_until_expiry: number
  deployment_locations: string[]
  notes?: string
  created_by_user_id?: number
  revoked_at?: string
  revocation_reason?: string
  issuer_ca_id?: number
  issuer_common_name?: string
  pem_available?: boolean
  monitoring_enabled: boolean
  monitoring_target_url?: string | null
  monitoring_target_port?: number | null
  monitoring_channels?: string[]
}

export interface CertificateIssueRequest {
  common_name: string
  subject_alt_names?: string[]
  certificate_type?: 'server' | 'wildcard' | 'ip'
  key_size?: number
  validity_days?: number
  deployment_locations?: string[]
  notes?: string
  monitoring_enabled?: boolean
  monitoring_target_url?: string
  monitoring_target_port?: number
  monitoring_channels?: string[]
}

export interface CertificateRenewalRequest {
  validity_days?: number
}

export interface CertificateRevocationRequest {
  reason?: string
}

// Certificate Authority types
export interface CertificateAuthority {
  id: number
  common_name: string
  organization: string
  organizational_unit?: string | null
  country: string
  state?: string | null
  locality?: string | null
  email?: string | null
  status: 'initializing' | 'active' | 'suspended' | 'revoked'
  serial_number: string
  not_valid_before?: string | null
  not_valid_after?: string | null
  issued_certificates_count: number
  days_until_expiry: number
  is_root: boolean
  is_offline: boolean
  parent_ca_id?: number | null
  child_count: number
}

export interface CAHierarchyResponse {
  root_ca?: CertificateAuthority | null
  active_ca?: CertificateAuthority | null
  hierarchy: CertificateAuthority[]
}

export interface CAInitializeRequest {
  common_name: string
  organization: string
  organizational_unit?: string
  country: string
  state?: string
  locality?: string
  email?: string
  validity_days?: number
  key_size?: number
  create_intermediate?: boolean
  intermediate_common_name?: string
  parent_ca_id?: number
  offline_root?: boolean
  path_length?: number
}

// Monitoring types
export interface MonitoringService {
  id: number
  name: string
  description?: string
  service_type: string
  url: string
  port?: number | null
  check_interval: number
  timeout: number
  retry_count: number
  status: 'active' | 'paused' | 'disabled' | 'up' | 'down' | 'pending'
  certificate_id?: number
  last_check_at?: string
  last_check_result?: string
  last_check_duration?: number
  last_error_message?: string
  uptime_percentage: number
  consecutive_failures: number
  total_checks: number
  successful_checks: number
  failed_checks: number
  average_response_time: number
  certificate_status?: string
  expires_at?: string
  days_until_expiry?: number
  serial_number?: string
  certificate_match?: boolean | null
  observed_serial_number?: string | null
  last_verified_at?: string | null
  verification_error?: string | null
}

export interface MonitoringOverview {
  total_services: number
  services_up: number
  services_down: number
  average_uptime: number
}

export interface ServiceCreateRequest {
  name: string
  description?: string
  service_type: string
  url: string
  check_interval?: number
  timeout?: number
  retry_count?: number
  certificate_id?: number
}

export interface ServiceUpdateRequest {
  name?: string
  description?: string
  url?: string
  check_interval?: number
  timeout?: number
  retry_count?: number
  status?: 'active' | 'paused' | 'disabled'
}

// Alert types
export interface Alert {
  id: number
  title: string
  message: string
  alert_type: 'certificate_expiry' | 'service_down' | 'health_check_failure' | 'ca_expiry' | 'system_error'
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: 'active' | 'acknowledged' | 'resolved' | 'suppressed'
  certificate_id?: number
  service_id?: number
  user_id?: number
  acknowledged_by?: number
  acknowledged_at?: string
  resolved_at?: string
  created_at: string
  updated_at: string
  age_hours: number
}

export interface AlertRule {
  id: number
  name: string
  description?: string
  alert_type: 'certificate_expiry' | 'service_down' | 'health_check_failure' | 'ca_expiry' | 'system_error'
  is_enabled: boolean
  conditions: Record<string, any>
  notification_channels: string[]
  created_by?: number
  created_at: string
  updated_at: string
}

export interface AlertRuleCreateRequest {
  name: string
  description?: string
  alert_type: 'certificate_expiry' | 'service_down' | 'health_check_failure' | 'ca_expiry' | 'system_error'
  is_enabled?: boolean
  conditions: Record<string, any>
  notification_channels: string[]
}

export interface AlertSettings {
  smtp_enabled: boolean
  smtp_host?: string
  smtp_port: number
  smtp_username?: string
  smtp_password?: string
  smtp_use_tls: boolean
  alert_email_from?: string
  alert_email_to?: string

  webhook_slack_enabled: boolean
  webhook_slack_url?: string

  webhook_discord_enabled: boolean
  webhook_discord_url?: string

  alert_days_before_expiry?: number

  alert_recipient_owner?: boolean
  alert_recipient_admins?: boolean
  alert_recipient_global?: boolean
}

export interface TestEmailRequest {
  to_email: string
  smtp_settings?: AlertSettings
}

export interface TestWebhookRequest {
  webhook_url: string
}

// API Response types
export interface ApiResponse<T> {
  data: T
  message?: string
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  per_page: number
  pages: number
}

export interface ApiError {
  detail: string
  status_code: number
  timestamp: string
}

// Health check types
export interface HealthCheck {
  status: 'healthy' | 'unhealthy'
  timestamp: number
  version: string
  components: {
    database: 'healthy' | 'unhealthy'
    vault: 'healthy' | 'unhealthy'
  }
}

// Statistics types
export interface DashboardStats {
  total_certificates: number
  active_certificates: number
  expiring_certificates: number
  revoked_certificates: number
  monitored_services: number
  healthy_services: number
  unhealthy_services: number
  active_alerts: number
  ca_status: 'active' | 'inactive' | 'expired'
  ca_days_until_expiry: number
}

// Form validation types
export interface FormErrors {
  [key: string]: string | string[]
}

// Table and UI types
export interface TableColumn<T> {
  key: keyof T
  title: string
  sortable?: boolean
  render?: (value: any, record: T) => React.ReactNode
}

export interface SortConfig {
  key: string
  direction: 'asc' | 'desc'
}

export interface FilterConfig {
  [key: string]: any
}

// Application theme types
export interface ThemeConfig {
  mode: 'light' | 'dark'
  primaryColor: string
}

// Navigation types
export interface NavigationItem {
  id: string
  title: string
  path: string
  icon?: React.ComponentType<any>
  children?: NavigationItem[]
  roles?: ('admin' | 'operator' | 'viewer')[]
}