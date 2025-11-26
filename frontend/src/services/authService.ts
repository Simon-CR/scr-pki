import { api } from './api'
import { User, LoginRequest, LoginResponse, TokenRefreshRequest, TokenResponse } from '../types'

export const authService = {
  // Login with username and password
  async login(data: LoginRequest): Promise<LoginResponse> {
    const params = new URLSearchParams()
    params.append('username', data.username)
    params.append('password', data.password)
    params.append('grant_type', 'password')
    
    return api.postUrlEncoded<LoginResponse>('/auth/login', params)
  },

  // Refresh access token
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const data: TokenRefreshRequest = { refresh_token: refreshToken }
    return api.post<TokenResponse>('/auth/refresh', data)
  },

  // Get current user information
  async getCurrentUser(): Promise<User> {
    return api.get<User>('/auth/me')
  },

  // Logout (client-side token cleanup)
  async logout(): Promise<void> {
    return api.post<void>('/auth/logout')
  },
}