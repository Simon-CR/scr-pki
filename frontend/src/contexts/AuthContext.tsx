import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import toast from 'react-hot-toast'

import { User, LoginRequest, LoginResponse } from '../types'
import { authService } from '../services/authService'
import { tokenStorage } from '../utils/tokenStorage'
import { api } from '../services/api'

interface AuthContextType {
  user: User | null
  loading: boolean
  login: (data: LoginRequest) => Promise<void>
  logout: () => void
  refreshToken: () => Promise<boolean>
  hasRole: (role: string) => boolean
  hasAnyRole: (roles: string[]) => boolean
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()
  const location = useLocation()

  // Check authentication status on mount
  useEffect(() => {
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    // Safety timeout to prevent infinite spinner
    // Increased to 5s to handle load spikes/rapid refreshes without premature logout
    const timeoutId = setTimeout(() => {
      console.warn('Auth check timed out, forcing loading=false')
      setLoading(false)
    }, 5000)

    try {
      const token = tokenStorage.getAccessToken()
      let isValidSession = false
      
      // If we have a token, try to verify it first
      if (token) {
        try {
          // Verify token and get user info
          const userData = await authService.getCurrentUser()
          setUser(userData)
          isValidSession = true
        } catch (error: any) {
          // If token is invalid (401), we'll fall through to setup check
          // If it's another error (network), we might want to keep the user logged in or show error
          if (error.response?.status === 401) {
             // Try refresh
             const refreshed = await refreshToken()
             if (refreshed) {
               isValidSession = true
             } else {
               // If refresh failed, clear tokens and fall through to setup check
               tokenStorage.clearTokens()
             }
          } else {
            // Network error or other issue - don't redirect to setup, just stop loading
            // This keeps the user on the page (maybe with error state shown by components)
            console.error('Auth check failed (network/server):', error)
            isValidSession = true // Treat as "don't redirect"
          }
        }
      }

      // If no token or token invalid, check if setup is required
      if (!isValidSession) {
        try {
          // Use a shorter timeout for this specific check if possible, or rely on global timeout
          const setupStatus = await api.get<{ setup_required: boolean }>('/setup/status')
          if (setupStatus.setup_required && location.pathname !== '/setup') {
            navigate('/setup', { replace: true })
          }
        } catch (e) {
          // Ignore setup check errors (e.g. if backend is down)
          console.warn('Setup check failed', e)
        }
      }

    } catch (error: any) {
      console.error('Auth check failed:', error)
    } finally {
      clearTimeout(timeoutId)
      setLoading(false)
    }
  }

  const login = async (data: LoginRequest) => {
    try {
      setLoading(true)
      const response: LoginResponse = await authService.login(data)
      
      // Store tokens
      tokenStorage.setTokens(response.access_token, response.refresh_token)
      
      // Set user
      setUser(response.user)
      
      toast.success(`Welcome back, ${response.user.full_name || response.user.username}!`)
      
      // Redirect to intended page or dashboard
      const from = location.state?.from?.pathname || '/dashboard'
      navigate(from, { replace: true })
      
    } catch (error: any) {
      const message = error.response?.data?.detail || 'Login failed'
      toast.error(message)
      throw error
    } finally {
      setLoading(false)
    }
  }

  const logout = () => {
    tokenStorage.clearTokens()
    setUser(null)
    toast.success('Logged out successfully')
    navigate('/login', { replace: true })
  }

  const refreshToken = async (): Promise<boolean> => {
    try {
      const refreshToken = tokenStorage.getRefreshToken()
      
      if (!refreshToken) {
        return false
      }

      const response = await authService.refreshToken(refreshToken)
      
      // Store new tokens
      tokenStorage.setTokens(response.access_token, response.refresh_token)
      
      // Get updated user info
      const userData = await authService.getCurrentUser()
      setUser(userData)
      
      return true
    } catch (error) {
      console.error('Token refresh failed:', error)
      return false
    }
  }

  const hasRole = (role: string): boolean => {
    if (!user) return false
    
    // Role hierarchy: admin > operator > viewer
    const roleHierarchy = ['viewer', 'operator', 'admin']
    const userRoleIndex = roleHierarchy.indexOf(user.role)
    const requiredRoleIndex = roleHierarchy.indexOf(role)
    
    return userRoleIndex >= requiredRoleIndex
  }

  const hasAnyRole = (roles: string[]): boolean => {
    return roles.some(role => hasRole(role))
  }

  const isAuthenticated = !!user && !!tokenStorage.getAccessToken()

  const value: AuthContextType = {
    user,
    loading,
    login,
    logout,
    refreshToken,
    hasRole,
    hasAnyRole,
    isAuthenticated,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Hook for protected routes
export function useRequireAuth() {
  const auth = useAuth()
  const location = useLocation()
  const navigate = useNavigate()

  useEffect(() => {
    if (!auth.loading && !auth.isAuthenticated) {
      navigate('/login', {
        state: { from: location },
        replace: true
      })
    }
  }, [auth.loading, auth.isAuthenticated, navigate, location])

  return auth
}

// Hook for role-based access
export function useRequireRole(requiredRole: string) {
  const auth = useRequireAuth()

  if (!auth.loading && auth.isAuthenticated && !auth.hasRole(requiredRole)) {
    throw new Error(`Access denied. Required role: ${requiredRole}`)
  }

  return auth
}