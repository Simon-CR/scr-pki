import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './contexts/AuthContext'
import LoadingSpinner from './components/LoadingSpinner'

import Layout from './components/Layout'
import Login from './pages/Login'
import Setup from './pages/Setup'
import Dashboard from './pages/Dashboard'
import Certificates from './pages/Certificates'
import Authorities from './pages/Authorities'
import Monitoring from './pages/Monitoring'
import Alerts from './pages/Alerts'
import SystemSettings from './pages/SystemSettings'
import Users from './pages/Users'
import ErrorBoundary from './components/ErrorBoundary'

function App() {
  const { loading } = useAuth()

  if (loading) {
    return <LoadingSpinner />
  }

  return (
    <ErrorBoundary>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/setup" element={<Setup />} />
        
        {/* Protected Routes */}
        <Route
          path="/*"
          element={
            <Layout>
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                
                {/* Certificate Routes */}
                <Route path="/certificates" element={<Certificates />} />
                <Route path="/authorities" element={<Authorities />} />
                
                {/* Monitoring Routes */}
                <Route path="/monitoring" element={<Monitoring />} />
                <Route path="/alerts" element={<Alerts />} />
                
                {/* System Routes */}
                <Route path="/users" element={<Users />} />
                <Route path="/settings" element={<SystemSettings />} />

                {/* Catch all */}
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </Layout>
          }
        />
      </Routes>
    </ErrorBoundary>
  )
}

export default App