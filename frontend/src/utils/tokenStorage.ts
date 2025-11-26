import Cookies from 'js-cookie'

const ACCESS_TOKEN_KEY = 'pki_access_token'
const REFRESH_TOKEN_KEY = 'pki_refresh_token'

export const tokenStorage = {
  getAccessToken(): string | null {
    return Cookies.get(ACCESS_TOKEN_KEY) || null
  },

  getRefreshToken(): string | null {
    return Cookies.get(REFRESH_TOKEN_KEY) || null
  },

  setTokens(accessToken: string, refreshToken: string): void {
    // Set access token with shorter expiry (30 minutes)
    Cookies.set(ACCESS_TOKEN_KEY, accessToken, {
      expires: 1/48, // 30 minutes
      secure: true,
      sameSite: 'strict'
    })

    // Set refresh token with longer expiry (7 days)
    Cookies.set(REFRESH_TOKEN_KEY, refreshToken, {
      expires: 7,
      secure: true,
      sameSite: 'strict'
    })
  },

  clearTokens(): void {
    Cookies.remove(ACCESS_TOKEN_KEY)
    Cookies.remove(REFRESH_TOKEN_KEY)
  },

  hasValidAccessToken(): boolean {
    const token = this.getAccessToken()
    if (!token) return false

    try {
      // Basic JWT validation - check if it's not expired
      const payload = JSON.parse(atob(token.split('.')[1]))
      const currentTime = Math.floor(Date.now() / 1000)
      
      return payload.exp > currentTime
    } catch {
      return false
    }
  }
}