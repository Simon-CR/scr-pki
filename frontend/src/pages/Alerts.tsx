import React, { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../services/api'

interface Alert {
  id: number
  title: string
  message: string
  alert_type: string
  severity: string
  status: string
  created_at: string
  resource_id?: number
  resource_type?: string
}

const Alerts: React.FC = () => {
  const queryClient = useQueryClient()
  const [retestingId, setRetestingId] = useState<number | null>(null)

  // Fetch alerts
  const { data: alerts, isLoading, error } = useQuery({
    queryKey: ['alerts'],
    queryFn: async () => {
      const response = await api.get<Alert[]>('/alerts/')
      return response
    }
  })

  const handleRetest = async (alert: Alert) => {
    if (!alert.resource_id || alert.resource_type !== 'monitoring_service') return

    setRetestingId(alert.id)
    try {
      await api.post(`/monitoring/services/${alert.resource_id}/check`)
      // Invalidate alerts query to refresh list
      await queryClient.invalidateQueries({ queryKey: ['alerts'] })
    } catch (error) {
      console.error('Failed to retest', error)
    } finally {
      setRetestingId(null)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'text-red-600 bg-red-100 border-red-200'
      case 'warning':
        return 'text-yellow-600 bg-yellow-100 border-yellow-200'
      case 'info':
        return 'text-blue-600 bg-blue-100 border-blue-200'
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return 'text-red-600 bg-red-100'
      case 'acknowledged':
        return 'text-yellow-600 bg-yellow-100'
      case 'resolved':
        return 'text-green-600 bg-green-100'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString()
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <div className="text-red-600 mb-4">
          <svg className="mx-auto h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.99-.833-2.764 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">Error loading alerts</h3>
        <p className="text-gray-500">Unable to fetch alerts from the server.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
        <p className="mt-1 text-sm text-gray-500">
          System notifications and security alerts
        </p>
      </div>

      {/* Alert Summary */}
      {alerts && alerts.length > 0 && (
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-3">
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-6 h-6 bg-red-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-xs font-medium">
                      {alerts.filter(alert => alert.severity === 'critical').length}
                    </span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">
                      Critical Alerts
                    </dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {alerts.filter(alert => alert.severity === 'critical').length}
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-6 h-6 bg-yellow-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-xs font-medium">
                      {alerts.filter(alert => alert.severity === 'warning').length}
                    </span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">
                      Warning Alerts
                    </dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {alerts.filter(alert => alert.severity === 'warning').length}
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-6 h-6 bg-red-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-xs font-medium">
                      {alerts.filter(alert => alert.status === 'active').length}
                    </span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">
                      Active Alerts
                    </dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {alerts.filter(alert => alert.status === 'active').length}
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Alerts List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <div className="px-4 py-5 sm:px-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900">
            Recent Alerts
          </h3>
          <p className="mt-1 max-w-2xl text-sm text-gray-500">
            Latest system alerts and notifications
          </p>
        </div>
        {alerts && alerts.length > 0 ? (
          <ul className="divide-y divide-gray-200">
            {alerts.map((alert) => (
              <li key={alert.id} className={`border-l-4 ${getSeverityColor(alert.severity)}`}>
                <div className="px-4 py-4 sm:px-6">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      <div className="flex-shrink-0">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(alert.severity)}`}>
                          {alert.severity.toUpperCase()}
                        </span>
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-gray-900">
                          {alert.title}
                        </div>
                        <div className="text-sm text-gray-500 mt-1">
                          {alert.message}
                        </div>
                        <div className="text-xs text-gray-400 mt-2">
                          {formatDate(alert.created_at)} • Type: {alert.alert_type}
                        </div>
                      </div>
                    </div>
                    <div className="flex-shrink-0 flex items-center space-x-2">
                      {alert.resource_type === 'monitoring_service' && (
                        <button
                          onClick={() => handleRetest(alert)}
                          disabled={retestingId === alert.id}
                          className={`inline-flex items-center px-2.5 py-1.5 border border-transparent text-xs font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                            retestingId === alert.id ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                        >
                          {retestingId === alert.id ? (
                            <>
                              <svg className="animate-spin -ml-1 mr-2 h-3 w-3 text-blue-700" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                              </svg>
                              Testing...
                            </>
                          ) : (
                            'Re-test'
                          )}
                        </button>
                      )}
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(alert.status)}`}>
                        {alert.status.toUpperCase()}
                      </span>
                    </div>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="px-4 py-5 sm:px-6">
            <div className="text-center">
              <svg
                className="mx-auto h-8 w-8 text-gray-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <h3 className="mt-2 text-sm font-medium text-gray-900">No alerts</h3>
              <p className="mt-1 text-sm text-gray-500">
                All systems are running normally. No alerts to display.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default Alerts