import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'

import { api } from '../services/api'
import { MonitoringOverview, MonitoringService } from '../types'

const Monitoring: React.FC = () => {
  const navigate = useNavigate()
  // Fetch monitoring overview
  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['monitoring'],
    queryFn: async () => {
      const response = await api.get<MonitoringOverview>('/monitoring/')
      return response
    }
  })

  // Fetch services
  const { data: services, isLoading: servicesLoading } = useQuery({
    queryKey: ['monitoring-services'],
    queryFn: async () => {
      const response = await api.get<MonitoringService[]>('/monitoring/services')
      return response
    }
  })

  const getStatusColor = (status: string) => {
    const normalized = status.toLowerCase()
    if (normalized === 'up') return 'text-green-600 bg-green-100'
    if (normalized === 'down') return 'text-red-600 bg-red-100'
    return 'text-yellow-600 bg-yellow-100'
  }

  const formatExpiry = (value?: string) => {
    if (!value) return '—'
    return new Date(value).toLocaleDateString()
  }

  if (overviewLoading || servicesLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Monitoring</h1>
        <p className="mt-1 text-sm text-gray-500">
          Monitor your services and infrastructure health
        </p>
      </div>

      {/* Overview Stats */}
      {overview && (
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-6 h-6 bg-blue-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-xs font-medium">{overview.total_services}</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">
                      Total Services
                    </dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {overview.total_services}
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
                  <div className="w-6 h-6 bg-green-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-xs font-medium">{overview.services_up}</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">
                      Services Up
                    </dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {overview.services_up}
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
                    <span className="text-white text-xs font-medium">{overview.services_down}</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">
                      Services Down
                    </dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {overview.services_down}
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
                  <div className="w-6 h-6 bg-purple-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-xs font-medium">{overview.average_uptime.toFixed(0)}%</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">
                      Average Uptime
                    </dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {overview.average_uptime.toFixed(1)}%
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Services List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <div className="px-4 py-5 sm:px-6 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              Monitored Certificates
            </h3>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">
              Certificates opted into monitoring via the Certificates page.
            </p>
          </div>
          <button
            type="button"
            onClick={() => navigate('/certificates')}
            className="inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
          >
            Manage Certificates
          </button>
        </div>
        {services && services.length > 0 ? (
          <ul className="divide-y divide-gray-200">
            {services.map((service) => (
              <li key={service.id}>
                <div className="px-4 py-4 sm:px-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(service.status)}`}>
                          {service.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-gray-900">
                          {service.name}
                        </div>
                        <div className="text-sm text-gray-500">
                          {service.url}
                          {service.port ? `:${service.port}` : ''}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-sm text-gray-500 text-right">
                        <div>Cert Status: <span className="font-medium capitalize">{service.certificate_status}</span></div>
                        <div>Expires: {formatExpiry(service.expires_at)} ({service.days_until_expiry} days)</div>
                      </div>
                      <div className="text-sm text-gray-500">
                        {service.last_check_result}
                        {service.last_verified_at && (
                          <div className="text-xs text-gray-400">
                            Last verified {new Date(service.last_verified_at).toLocaleString()}
                          </div>
                        )}
                        {service.certificate_match === true && (
                          <div className="text-xs text-green-600 mt-1">Remote certificate matches.</div>
                        )}
                        {service.certificate_match === false && (
                          <div className="text-xs text-red-600 mt-1">
                            {service.verification_error
                              ? `Verification error: ${service.verification_error}`
                              : service.observed_serial_number
                                ? `Mismatch (remote serial ${service.observed_serial_number}).`
                                : 'Remote certificate does not match.'}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                    <div className="mt-3 flex flex-wrap items-center justify-between text-xs text-gray-500">
                      <div>Serial: {service.serial_number}</div>
                      <div>Observed uptime: {service.uptime_percentage.toFixed(1)}%</div>
                    <button
                      type="button"
                      onClick={() => navigate('/certificates')}
                      className="text-indigo-600 hover:text-indigo-800"
                    >
                      View in Certificates
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="px-4 py-5 sm:px-6">
            <p className="text-sm text-gray-500">
              No certificates are currently monitored. Opt-in from the Certificates page to populate this list.
            </p>
            <button
              type="button"
              onClick={() => navigate('/certificates')}
              className="mt-3 inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Go to Certificates
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export default Monitoring