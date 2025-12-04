import React, { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { systemService } from '../services/systemService'
import LoadingSpinner from './LoadingSpinner'

interface LayoutProps {
  children: React.ReactNode
}

const APP_VERSION = '0.2.5'

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const { user, logout, loading } = useAuth()
  const [updateAvailable, setUpdateAvailable] = useState(false)
  const [currentVersion, setCurrentVersion] = useState('')
  const [latestVersion, setLatestVersion] = useState('')
  const [releaseUrl, setReleaseUrl] = useState('')
  const [dockerAvailable, setDockerAvailable] = useState(false)

  useEffect(() => {
    const checkUpdate = async () => {
      try {
        const data = await systemService.checkVersion()
        setCurrentVersion(data.current_version)
        if (data.update_available) {
          setUpdateAvailable(true)
          setLatestVersion(data.latest_version)
          setReleaseUrl(data.release_url || '#')
          setDockerAvailable(data.docker_image_available || false)
        }
      } catch (error) {
        console.error('Failed to check version:', error)
      }
    }
    
    if (user?.role === 'admin') {
      checkUpdate()
    }
  }, [user])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  const handleLogout = async () => {
    try {
      await logout()
    } catch (error) {
      console.error('Logout error:', error)
    }
  }

  const getUserRoleBadge = () => {
    if (!user?.role) return null
    
    const roleColors = {
      admin: 'bg-red-100 text-red-800',
      operator: 'bg-blue-100 text-blue-800',
      viewer: 'bg-green-100 text-green-800'
    }
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${roleColors[user.role]}`}>
        {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
      </span>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex min-w-0">
              <div className="flex-shrink-0 flex items-center">
                <h1 className="text-xl font-semibold text-gray-900">
                  SCR-PKI
                </h1>
              </div>
              <div className="hidden sm:ml-6 sm:flex sm:space-x-4 lg:space-x-8 overflow-x-auto">
                {[
                  { to: '/dashboard', label: 'Dashboard' },
                  { to: '/certificates', label: 'Certificates' },
                  { to: '/authorities', label: 'Authorities' },
                  { to: '/monitoring', label: 'Monitoring' },
                  { to: '/alerts', label: 'Alerts' },
                  ...(user?.role === 'admin' ? [
                    { to: '/users', label: 'Users' },
                    { to: '/settings', label: 'Settings' }
                  ] : []),
                ].map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      `inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition ${
                        isActive
                          ? 'border-indigo-500 text-gray-900'
                          : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
                      }`
                    }
                  >
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>
            <div className="hidden sm:ml-6 sm:flex sm:items-center space-x-4 flex-shrink-0">
              <div className="flex items-center space-x-2 min-w-0">
                <span className="text-sm text-gray-700 truncate max-w-[120px] lg:max-w-[200px]">{user?.email}</span>
                {getUserRoleBadge()}
              </div>
              <button
                onClick={handleLogout}
                className="bg-white p-1 rounded-full text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                <span className="sr-only">Logout</span>
                <svg
                  className="h-6 w-6"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                  />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </nav>

      {updateAvailable && (
        <div className="bg-indigo-600">
          <div className="max-w-7xl mx-auto py-3 px-3 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between flex-wrap">
              <div className="w-0 flex-1 flex items-center">
                <span className="flex p-2 rounded-lg bg-indigo-800">
                  <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
                  </svg>
                </span>
                <p className="font-medium text-white truncate">
                  <span className="md:hidden">New version available!</span>
                  <span className="hidden md:inline">
                    New version {latestVersion} is available!
                    {dockerAvailable && (
                      <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                        Docker Image Ready
                      </span>
                    )}
                  </span>
                </p>
              </div>
              <div className="order-3 mt-2 flex-shrink-0 w-full sm:order-2 sm:mt-0 sm:w-auto">
                <a
                  href={releaseUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-indigo-600 bg-white hover:bg-indigo-50"
                >
                  View Release
                </a>
              </div>
              <div className="order-2 flex-shrink-0 sm:order-3 sm:ml-3">
                <button
                  type="button"
                  onClick={() => setUpdateAvailable(false)}
                  className="-mr-1 flex p-2 rounded-md hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-white sm:-mr-2"
                >
                  <span className="sr-only">Dismiss</span>
                  <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main content */}
      <main className="flex-1">
        <div className="py-6">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            {children}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200">
        <div className="max-w-7xl mx-auto py-4 px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center">
            <div className="text-sm text-gray-500">
              © {new Date().getFullYear()} SCR-PKI v{currentVersion || APP_VERSION}. All rights reserved.
            </div>
            <div className="flex space-x-6">
              <a href="#" className="text-sm text-gray-500 hover:text-gray-900">
                Documentation
              </a>
              <a href="#" className="text-sm text-gray-500 hover:text-gray-900">
                Support
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default Layout