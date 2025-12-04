import React, { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import { api } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import { Certificate, MonitoringService, Alert } from '../types'

interface DashboardStats {
  totalCertificates: number
  activeCertificates: number
  expiringSoon: number
  revokedCertificates: number
  activeServices: number
  criticalAlerts: number
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats>({
    totalCertificates: 0,
    activeCertificates: 0,
    expiringSoon: 0,
    revokedCertificates: 0,
    activeServices: 0,
    criticalAlerts: 0
  })

  // Fetch system health
  const { data: health } = useQuery({
    queryKey: ['system-health'],
    queryFn: async () => {
      return api.get<{
        database_connected: boolean
        vault_connected: boolean
        vault_initialized: boolean
        vault_sealed: boolean
      }>('/system/health')
    }
  })

  // Fetch certificates
  const { data: certificates, isLoading: certificatesLoading } = useQuery({
    queryKey: ['certificates'],
    queryFn: async () => {
      const response = await api.get<Certificate[]>('/certificates/')
      return response
    }
  })

  // Fetch monitoring services
  const { data: services, isLoading: servicesLoading } = useQuery({
    queryKey: ['monitoring-services'],
    queryFn: async () => {
      const response = await api.get<MonitoringService[]>('/monitoring/services')
      return response
    }
  })

  // Fetch alerts
  const { data: alerts, isLoading: alertsLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: async () => {
      const response = await api.get<Alert[]>('/alerts/')
      return response
    }
  })

  useEffect(() => {
    if (certificates && Array.isArray(certificates)) {
      const now = new Date()
      const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)
      
      const activeCerts = certificates.filter(cert => cert.status === 'active')
      const expiringSoonCerts = activeCerts.filter(cert => {
        const expiryDate = new Date(cert.not_valid_after)
        return expiryDate <= thirtyDaysFromNow
      })
      const revokedCerts = certificates.filter(cert => cert.status === 'revoked')

      setStats(prev => ({
        ...prev,
        totalCertificates: certificates.length,
        activeCertificates: activeCerts.length,
        expiringSoon: expiringSoonCerts.length,
        revokedCertificates: revokedCerts.length
      }))
    }

    if (services && Array.isArray(services)) {
      const activeServices = services.filter(service => 
        service.status === 'up' && service.last_check_result?.includes('presents the assigned certificate')
      )
      setStats(prev => ({
        ...prev,
        activeServices: activeServices.length
      }))
    }

    if (alerts && Array.isArray(alerts)) {
      const criticalAlerts = alerts.filter(alert => 
        alert.severity === 'critical' && alert.status === 'active'
      )
      setStats(prev => ({
        ...prev,
        criticalAlerts: criticalAlerts.length
      }))
    }
  }, [certificates, services, alerts])

  const expiringCertificates = (certificates ?? [])
    .filter(cert => {
      const now = new Date()
      const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)
      const expiryDate = new Date(cert.not_valid_after)
      return cert.status === 'active' && expiryDate <= thirtyDaysFromNow
    })
    .sort((a, b) => new Date(a.not_valid_after).getTime() - new Date(b.not_valid_after).getTime())

  const activeAlerts = (alerts ?? []).filter(alert => alert.status === 'active')
  const healthyServices = (services ?? []).filter(
    service => service.status === 'up' && service.last_check_result?.includes('presents the assigned certificate')
  )
  const totalServices = services?.length ?? 0
  const serviceUptime = totalServices ? Math.round((healthyServices.length / totalServices) * 100) : 100
  const certificateCoverage = stats.totalCertificates
    ? Math.round((stats.activeCertificates / stats.totalCertificates) * 100)
    : 0
  const revokedRate = stats.totalCertificates
    ? Math.round((stats.revokedCertificates / stats.totalCertificates) * 100)
    : 0
  const activityFeed = (certificates ?? [])
    .slice()
    .sort((a, b) => new Date(b.not_valid_before).getTime() - new Date(a.not_valid_before).getTime())
    .slice(0, 5)

  const isLoading = certificatesLoading || servicesLoading || alertsLoading

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
        
        {/* Vault Warning Banner */}
        {health && (!health.vault_initialized || !health.vault_connected) && (
          <div className="bg-yellow-900/30 border-l-4 border-yellow-500 p-4 rounded-r-md">
            <div className="flex">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-5 w-5 text-yellow-500" aria-hidden="true" />
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-300">
                  {!health.vault_initialized 
                    ? 'Vault Not Initialized' 
                    : 'Vault Not Connected'}
                </h3>
                <div className="mt-2 text-sm text-yellow-200/80">
                  <p>
                    {!health.vault_initialized 
                      ? 'The secure storage system (Vault) has not been initialized yet. You must initialize it to issue certificates.'
                      : 'The application cannot connect to the secure storage system (Vault). Please check your configuration.'}
                  </p>
                </div>
                <div className="mt-4">
                  <div className="-mx-2 -my-1.5 flex">
                    <Link
                      to="/settings?tab=vault"
                      className="bg-yellow-900/50 px-3 py-2 rounded-md text-sm font-medium text-yellow-200 hover:bg-yellow-900/70 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 focus:ring-yellow-500 transition-colors"
                    >
                      Go to Settings &rarr;
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Command center header */}
        <div className="grid gap-6 lg:grid-cols-[2fr,1fr]">
          <div className="bg-gradient-to-br from-indigo-600 via-purple-600 to-blue-600 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
            <div className="absolute inset-0 opacity-20 bg-[radial-gradient(circle_at_top,_#ffffff44,_transparent)]" />
            <div className="relative z-10">
              <p className="text-sm uppercase tracking-[0.3em] text-white/70 mb-3">Live overview</p>
              <h1 className="text-3xl sm:text-4xl font-black text-white mb-3">PKI Command Center</h1>
              <p className="text-white/80 max-w-2xl">
                Real-time visibility into certificate posture, issuance pipeline, and platform health across your estate.
              </p>
              <div className="mt-8 grid gap-4 sm:grid-cols-3">
                <div className="bg-white/10 rounded-2xl p-4 backdrop-blur">
                  <p className="text-xs uppercase tracking-wide text-white/60">Coverage</p>
                  <p className="text-2xl font-semibold text-white">{certificateCoverage}%</p>
                  <p className="text-xs text-white/60">Active certificates</p>
                </div>
                <div className="bg-white/10 rounded-2xl p-4 backdrop-blur">
                  <p className="text-xs uppercase tracking-wide text-white/60">Uptime</p>
                  <p className="text-2xl font-semibold text-white">{serviceUptime}%</p>
                  <p className="text-xs text-white/60">Service health</p>
                </div>
                <div className="bg-white/10 rounded-2xl p-4 backdrop-blur">
                  <p className="text-xs uppercase tracking-wide text-white/60">Open alerts</p>
                  <p className="text-2xl font-semibold text-white">{activeAlerts.length}</p>
                  <p className="text-xs text-white/60">Action required</p>
                </div>
              </div>
              <div className="mt-8 flex flex-wrap gap-3">
                <Link
                  to="/certificates"
                  className="inline-flex items-center px-4 py-2 text-sm font-semibold text-slate-900 bg-white rounded-full shadow-lg hover:-translate-y-0.5 transition-transform"
                >
                  Manage certificates
                </Link>
                <Link
                  to="/monitoring"
                  className="inline-flex items-center px-4 py-2 text-sm font-semibold text-white/80 border border-white/30 rounded-full hover:text-white"
                >
                  Monitoring console
                </Link>
              </div>
            </div>
          </div>
          <div className="grid gap-6">
            <div className="bg-slate-900 rounded-3xl border border-white/5 p-6 shadow-xl">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400 mb-3">Mission control</p>
              <h2 className="text-xl font-semibold text-white mb-4">Immediate actions</h2>
              <div className="space-y-3">
                <Link
                  to="/certificates"
                  className="flex items-center justify-between rounded-2xl border border-white/10 px-4 py-3 hover:bg-white/5 transition"
                >
                  <div>
                    <p className="text-sm font-medium">Issue certificate</p>
                    <p className="text-xs text-slate-400">Service onboarding or renewal</p>
                  </div>
                  <span className="text-xs text-indigo-300">Launch →</span>
                </Link>
                <Link
                  to="/alerts"
                  className="flex items-center justify-between rounded-2xl border border-white/10 px-4 py-3 hover:bg-white/5 transition"
                >
                  <div>
                    <p className="text-sm font-medium">Respond to alerts</p>
                    <p className="text-xs text-slate-400">{activeAlerts.length || 'No'} active incident{activeAlerts.length === 1 ? '' : 's'}</p>
                  </div>
                  <span className="text-xs text-indigo-300">Open →</span>
                </Link>
              </div>
            </div>
            <div className="bg-slate-900 rounded-3xl border border-white/5 p-6 shadow-xl">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400 mb-3">Platform pulse</p>
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between text-sm text-slate-400">
                    <span>Certificate hygiene</span>
                    <span>{certificateCoverage}%</span>
                  </div>
                  <div className="mt-1 h-2 rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-green-400 to-emerald-400"
                      style={{ width: `${certificateCoverage}%` }}
                    />
                  </div>
                </div>
                <div>
                  <div className="flex items-center justify-between text-sm text-slate-400">
                    <span>Revocation rate</span>
                    <span>{revokedRate}%</span>
                  </div>
                  <div className="mt-1 h-2 rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-red-400 to-orange-400"
                      style={{ width: `${revokedRate}%` }}
                    />
                  </div>
                </div>
                <div className="flex items-center justify-between text-sm text-slate-400">
                  <span>Healthy services</span>
                  <span>{healthyServices.length}/{totalServices || 1}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* KPI strip */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <div className="bg-slate-900 rounded-2xl border border-white/5 p-5">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Inventory</p>
            <p className="text-3xl font-semibold text-white mt-2">{stats.totalCertificates}</p>
            <p className="text-xs text-slate-500">Certificates discovered</p>
          </div>
          <div className="bg-slate-900 rounded-2xl border border-white/5 p-5">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Expiring soon</p>
            <p className="text-3xl font-semibold text-amber-300 mt-2">{stats.expiringSoon}</p>
            <p className="text-xs text-slate-500">Within 30 days</p>
          </div>
          <div className="bg-slate-900 rounded-2xl border border-white/5 p-5">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Active services</p>
            <p className="text-3xl font-semibold text-emerald-300 mt-2">{stats.activeServices}</p>
            <p className="text-xs text-slate-500">Monitoring coverage</p>
          </div>
          <div className="bg-slate-900 rounded-2xl border border-white/5 p-5">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Critical alerts</p>
            <p className="text-3xl font-semibold text-rose-300 mt-2">{stats.criticalAlerts}</p>
            <p className="text-xs text-slate-500">Requires action</p>
          </div>
        </div>

        {/* Deep dive grid */}
        <div className="grid gap-6 lg:grid-cols-[2fr,1fr]">
          <div className="space-y-6">
            <div className="bg-slate-900 rounded-3xl border border-white/5 p-6">
              <div className="flex items-center justify-between">
                <h3 className="text-xl font-semibold text-white">Certificate posture</h3>
                <Link to="/certificates" className="text-xs text-indigo-200 hover:text-white">View registry →</Link>
              </div>
              <div className="mt-6 grid gap-4 md:grid-cols-2">
                <div className="p-4 rounded-2xl bg-slate-800 border border-white/5">
                  <p className="text-sm text-slate-400 mb-2">Active coverage</p>
                  <p className="text-3xl font-semibold text-white">{stats.activeCertificates}</p>
                  <div className="mt-4 h-2 rounded-full bg-slate-900">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-indigo-400 to-blue-400"
                      style={{ width: `${certificateCoverage}%` }}
                    />
                  </div>
                </div>
                <div className="p-4 rounded-2xl bg-slate-800 border border-white/5">
                  <p className="text-sm text-slate-400 mb-2">Revoked certificates</p>
                  <p className="text-3xl font-semibold text-white">{stats.revokedCertificates}</p>
                  <div className="mt-4 h-2 rounded-full bg-slate-900">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-rose-400 to-orange-400"
                      style={{ width: `${revokedRate}%` }}
                    />
                  </div>
                </div>
              </div>
              <div className="mt-6">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-500 mb-3">Renewal pipeline</p>
                <div className="space-y-3">
                  {expiringCertificates.slice(0, 4).map(cert => (
                    <div key={cert.id} className="flex items-center justify-between p-4 rounded-2xl bg-slate-800 border border-white/5">
                      <div>
                        <p className="font-medium text-white">{cert.common_name}</p>
                        <p className="text-sm text-slate-400">
                          Expires {new Date(cert.not_valid_after).toLocaleDateString()}
                        </p>
                      </div>
                      <span className="text-xs px-3 py-1 rounded-full bg-amber-500/20 text-amber-200">
                        {Math.max(
                          0,
                          Math.ceil((new Date(cert.not_valid_after).getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24))
                        )}d
                      </span>
                    </div>
                  ))}
                  {expiringCertificates.length === 0 && (
                    <div className="p-6 text-center rounded-2xl bg-slate-800 border border-white/5 text-slate-400">
                      No certificates expiring in the next 30 days.
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="bg-slate-900 rounded-3xl border border-white/5 p-6">
              <div className="flex items-center justify-between">
                <h3 className="text-xl font-semibold text-white">Operational telemetry</h3>
                <Link to="/monitoring" className="text-xs text-indigo-200 hover:text-white">Open monitoring →</Link>
              </div>
              <div className="mt-6 grid gap-4 md:grid-cols-2">
                <div className="p-4 rounded-2xl bg-slate-800 border border-white/5">
                  <p className="text-sm text-slate-400">Healthy services</p>
                  <p className="text-3xl font-semibold text-emerald-300 mt-2">{healthyServices.length}</p>
                  <p className="text-xs text-slate-500">of {totalServices || '—'} monitored endpoints</p>
                </div>
                <div className="p-4 rounded-2xl bg-slate-800 border border-white/5">
                  <p className="text-sm text-slate-400">Degraded</p>
                  <p className="text-3xl font-semibold text-amber-300 mt-2">{totalServices - healthyServices.length}</p>
                  <p className="text-xs text-slate-500">requiring review</p>
                </div>
              </div>
              <div className="mt-6 grid gap-3">
                {(services ?? []).slice(0, 4).map(service => (
                  <div key={service.id} className="flex items-center justify-between rounded-2xl bg-slate-800 border border-white/5 px-4 py-3">
                    <div>
                      <p className="text-sm font-medium text-white">{service.name}</p>
                      <p className="text-xs text-slate-500">
                        Last check {service.last_verified_at ? new Date(service.last_verified_at).toLocaleString() : '—'}
                      </p>
                    </div>
                    <span
                      className={`text-xs px-3 py-1 rounded-full ${
                        service.status === 'up' && service.last_check_result?.includes('presents the assigned certificate')
                          ? 'bg-emerald-500/20 text-emerald-200'
                          : 'bg-rose-500/20 text-rose-200'
                      }`}
                    >
                      {service.status}
                    </span>
                  </div>
                ))}
                {(services ?? []).length === 0 && (
                  <div className="p-6 text-center rounded-2xl bg-slate-800 border border-white/5 text-slate-400">
                    No monitoring services registered.
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-slate-900 rounded-3xl border border-white/5 p-6">
              <div className="flex items-center justify-between">
                <h3 className="text-xl font-semibold text-white">Active alerts</h3>
                <span className="text-xs text-slate-400">{activeAlerts.length} open</span>
              </div>
              <div className="mt-6 space-y-4">
                {activeAlerts.slice(0, 4).map(alert => (
                  <div key={alert.id} className="rounded-2xl border border-white/5 bg-slate-800 px-4 py-3">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium text-white">{alert.message}</p>
                      <span
                        className={`text-xs px-3 py-1 rounded-full ${
                          alert.severity === 'critical'
                            ? 'bg-rose-500/20 text-rose-200'
                            : alert.severity === 'high'
                              ? 'bg-orange-500/20 text-orange-200'
                              : 'bg-amber-500/20 text-amber-200'
                        }`}
                      >
                        {alert.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-2">{new Date(alert.created_at).toLocaleString()}</p>
                  </div>
                ))}
                {activeAlerts.length === 0 && (
                  <div className="p-6 text-center rounded-2xl bg-slate-800 border border-white/5 text-slate-400">
                    No active alerts. All systems stable.
                  </div>
                )}
              </div>
            </div>

            <div className="bg-slate-900 rounded-3xl border border-white/5 p-6">
              <div className="flex items-center justify-between">
                <h3 className="text-xl font-semibold text-white">Recent activity</h3>
                <span className="text-xs text-slate-400">Latest 5 events</span>
              </div>
              <div className="mt-6 space-y-4">
                {activityFeed.length > 0 ? (
                  activityFeed.map(cert => (
                    <div key={cert.id} className="flex items-center justify-between border-b border-white/5 pb-3 last:border-b-0 last:pb-0">
                      <div>
                        <p className="text-sm font-medium text-white">{cert.common_name}</p>
                        <p className="text-xs text-slate-500">
                          Valid from {new Date(cert.not_valid_before).toLocaleDateString()} · Expires {new Date(cert.not_valid_after).toLocaleDateString()}
                        </p>
                      </div>
                      <span
                        className={`text-xs px-3 py-1 rounded-full ${
                          cert.status === 'active'
                            ? 'bg-emerald-500/20 text-emerald-200'
                            : cert.status === 'revoked'
                              ? 'bg-rose-500/20 text-rose-200'
                              : 'bg-slate-500/20 text-slate-200'
                        }`}
                      >
                        {cert.status}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="p-6 text-center rounded-2xl bg-slate-800 border border-white/5 text-slate-400">
                    No certificate activity captured yet.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard