import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, apiClient, getApiErrorMessage } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import { Certificate } from '../types'
import toast from 'react-hot-toast'
import { useConfirmDialog } from '../components/ConfirmDialog'

interface CertificateFilters {
  status: string
  search: string
}

const MAX_VALIDITY_YEARS = 20
const MAX_VALIDITY_DAYS = MAX_VALIDITY_YEARS * 365
const DEFAULT_VALIDITY_DAYS = 365
const CUSTOM_VALIDITY_VALUE = 'custom'
const YEAR_OPTIONS = Array.from({ length: MAX_VALIDITY_YEARS }, (_, index) => index + 1)
const DEFAULT_MONITORING_PORT = 443

type IssueFormState = {
  common_name: string
  certificate_type: 'server' | 'wildcard' | 'ip'
  organization: string
  organizational_unit: string
  country: string
  state: string
  locality: string
  email: string
  subject_alt_names: string
  validity_days: number
  monitoring_enabled: boolean
  monitoring_target_url: string
  monitoring_target_port: string
}

type MonitoringFormState = {
  monitoring_enabled: boolean
  monitoring_target_url: string
  monitoring_target_port: string
}


const createInitialIssueForm = (): IssueFormState => ({
  common_name: '',
  certificate_type: 'server',
  organization: '',
  organizational_unit: '',
  country: 'US',
  state: '',
  locality: '',
  email: '',
  subject_alt_names: '',
  validity_days: DEFAULT_VALIDITY_DAYS,
  monitoring_enabled: false,
  monitoring_target_url: '',
  monitoring_target_port: DEFAULT_MONITORING_PORT.toString()
})

const parseSubjectAltNamesInput = (value: string): string[] =>
  value
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)

const stripProtocolAndWildcard = (value: string): string => {
  if (!value) return ''
  const withoutProtocol = value.replace(/^https?:\/\//i, '')
  const withoutPath = withoutProtocol.split('/')[0]
  return withoutPath.replace(/^\*\./, '')
}

const buildDefaultMonitoringUrl = (commonName: string, sanInput: string): string => {
  const candidates = parseSubjectAltNamesInput(sanInput)
  const target = stripProtocolAndWildcard(candidates[0] || commonName)
  if (!target) {
    return ''
  }
  return `https://${target}`
}

const CERTIFICATE_TYPE_OPTIONS: Array<{ value: IssueFormState['certificate_type']; label: string }> = [
  { value: 'server', label: 'Server Certificate' },
  { value: 'wildcard', label: 'Wildcard/SAN Certificate' },
  { value: 'ip', label: 'IP Address Certificate' }
]

const getVaultUiUrl = () => {
  if (import.meta.env.VITE_VAULT_UI_URL) {
    return import.meta.env.VITE_VAULT_UI_URL
  }
  return `${window.location.origin}/ui/`
}

const getYearPresetFromDays = (days: number): string => {
  const match = YEAR_OPTIONS.find(year => year * 365 === days)
  return match ? String(match) : CUSTOM_VALIDITY_VALUE
}

const Certificates: React.FC = () => {
  const { confirm } = useConfirmDialog()
  const monitoringAutoUrlRef = useRef('')
  const [filters, setFilters] = useState<CertificateFilters>({
    status: 'all',
    search: ''
  })
  const [showIssueModal, setShowIssueModal] = useState(false)
  
  const [issueForm, setIssueForm] = useState<IssueFormState>(() => createInitialIssueForm())
  const [issueError, setIssueError] = useState<string | null>(null)
  const [validityPreset, setValidityPreset] = useState<string>(getYearPresetFromDays(DEFAULT_VALIDITY_DAYS))
  const [selectedCertificate, setSelectedCertificate] = useState<Certificate | null>(null)
  const [monitoringForm, setMonitoringForm] = useState<MonitoringFormState>({
    monitoring_enabled: false,
    monitoring_target_url: '',
    monitoring_target_port: DEFAULT_MONITORING_PORT.toString()
  })
  const [downloadTarget, setDownloadTarget] = useState<string | null>(null)
  const queryClient = useQueryClient()


  useEffect(() => {
    if (!issueForm.monitoring_enabled) {
      return
    }
    const suggested = buildDefaultMonitoringUrl(issueForm.common_name, issueForm.subject_alt_names)
    if (!suggested) {
      return
    }
    setIssueForm(prev => {
      if (!prev.monitoring_enabled) {
        return prev
      }
      if (prev.monitoring_target_url && prev.monitoring_target_url !== monitoringAutoUrlRef.current) {
        return prev
      }
      monitoringAutoUrlRef.current = suggested
      if (prev.monitoring_target_url === suggested) {
        return prev
      }
      return {
        ...prev,
        monitoring_target_url: suggested
      }
    })
  }, [issueForm.common_name, issueForm.subject_alt_names, issueForm.monitoring_enabled])

  useEffect(() => {
    if (!selectedCertificate) {
      setMonitoringForm({
        monitoring_enabled: false,
        monitoring_target_url: '',
        monitoring_target_port: DEFAULT_MONITORING_PORT.toString()
      })
      return
    }

    setMonitoringForm({
      monitoring_enabled: selectedCertificate.monitoring_enabled,
      monitoring_target_url: selectedCertificate.monitoring_target_url || '',
      monitoring_target_port: selectedCertificate.monitoring_target_port?.toString() || DEFAULT_MONITORING_PORT.toString()
    })
  }, [selectedCertificate])

  // Fetch certificates
  const { data: certificates, isLoading, error } = useQuery({
    queryKey: ['certificates', filters],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (filters.status !== 'all') params.append('status', filters.status)
      if (filters.search) params.append('search', filters.search)
      
      const response = await api.get<Certificate[]>(`/certificates/?${params.toString()}`)
      return response
    }
  })

  // Revoke certificate mutation
  const revokeMutation = useMutation({
    mutationFn: async (certificateId: string) => {
      await api.post(`/certificates/${certificateId}/revoke`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring-services'] })
    }
  })

  // Renew certificate mutation
  const renewMutation = useMutation({
    mutationFn: async (certificateId: string) => {
      await api.post(`/certificates/${certificateId}/renew`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring-services'] })
    }
  })

  const deleteMutation = useMutation({
    mutationFn: async (certificateId: string) => {
      await api.delete(`/certificates/${certificateId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring-services'] })
      toast.success('Certificate deleted')
    },
    onError: (error: unknown) => {
      toast.error(getApiErrorMessage(error, 'Failed to delete certificate'))
    }
  })

  const monitoringMutation = useMutation({
    mutationFn: async ({ certificateId, payload }: { certificateId: number; payload: { monitoring_enabled: boolean; monitoring_target_url?: string; monitoring_target_port?: number; monitoring_channels?: string[] } }) => {
      return await api.put<Certificate>(`/certificates/${certificateId}/monitoring`, payload)
    },
    onSuccess: (updatedCertificate) => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring-services'] })
      setSelectedCertificate(updatedCertificate)
      toast.success('Monitoring preferences updated')
    },
    onError: (error: unknown) => {
      toast.error(getApiErrorMessage(error, 'Failed to update monitoring preferences'))
    }
  })

  // Issue certificate mutation
  const issueMutation = useMutation({
    mutationFn: async (issueData: IssueFormState) => {
      const subjectAltNames = parseSubjectAltNamesInput(issueData.subject_alt_names)
      const monitoringPortValue = issueData.monitoring_target_port.trim()
      const shouldMonitor = issueData.monitoring_enabled
      const monitoringUrl = shouldMonitor
        ? (issueData.monitoring_target_url.trim() || buildDefaultMonitoringUrl(issueData.common_name, issueData.subject_alt_names))
        : undefined
      const requestData = {
        common_name: issueData.common_name,
        certificate_type: issueData.certificate_type,
        organization: issueData.organization || undefined,
        organizational_unit: issueData.organizational_unit || undefined,
        country: issueData.country || undefined,
        state: issueData.state || undefined,
        locality: issueData.locality || undefined,
        email: issueData.email || undefined,
        subject_alt_names: subjectAltNames,
        validity_days: issueData.validity_days,
        monitoring_enabled: shouldMonitor,
        monitoring_target_url: shouldMonitor ? monitoringUrl : undefined,
        monitoring_target_port: shouldMonitor
          ? (monitoringPortValue ? Number(monitoringPortValue) : DEFAULT_MONITORING_PORT)
          : undefined,
        monitoring_channels: [] as string[],
      }
      return await api.post('/certificates/issue', requestData)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring-services'] })
      toast.success('Certificate issued successfully')
      setShowIssueModal(false)
      setIssueForm(createInitialIssueForm())
      setValidityPreset(getYearPresetFromDays(DEFAULT_VALIDITY_DAYS))
      monitoringAutoUrlRef.current = ''
      setIssueError(null)
    },
    onError: (error: unknown) => {
      const message = getApiErrorMessage(error, 'Failed to issue certificate')
      setIssueError(message)
      toast.error(message)
    }
  })

  const handleIssueSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIssueError(null)
    issueMutation.mutate(issueForm)
  }

  const handleOpenIssueModal = () => {
    setIssueError(null)
    setShowIssueModal(true)
  }

  const handleCloseIssueModal = () => {
    setShowIssueModal(false)
    setIssueError(null)
    setIssueForm(createInitialIssueForm())
    setValidityPreset(getYearPresetFromDays(DEFAULT_VALIDITY_DAYS))
    monitoringAutoUrlRef.current = ''
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target
    if (name === 'validity_days') {
      const parsedValue = parseInt(value, 10)
      const safeValue = Number.isNaN(parsedValue) ? 0 : parsedValue
      setValidityPreset(getYearPresetFromDays(safeValue))
      setIssueForm(prev => ({
        ...prev,
        validity_days: safeValue
      }))
      return
    }

     if (name === 'monitoring_target_port') {
       setIssueForm(prev => ({
         ...prev,
         monitoring_target_port: value
       }))
       return
     }

    setIssueForm(prev => ({
      ...prev,
      [name]: value
    }))
  }

  const handleIssueCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, checked } = e.target
    if (name === 'monitoring_enabled') {
      setIssueForm(prev => {
        const nextUrl = checked ? (prev.monitoring_target_url || buildDefaultMonitoringUrl(prev.common_name, prev.subject_alt_names)) : ''
        if (checked) {
          monitoringAutoUrlRef.current = nextUrl
        } else {
          monitoringAutoUrlRef.current = ''
        }
        return {
          ...prev,
          monitoring_enabled: checked,
          monitoring_target_url: nextUrl,
          monitoring_target_port: checked ? (prev.monitoring_target_port || DEFAULT_MONITORING_PORT.toString()) : DEFAULT_MONITORING_PORT.toString()
        }
      })
    }
  }

  const handleUseIssueMonitorSuggestion = () => {
    setIssueForm(prev => {
      const suggestion = buildDefaultMonitoringUrl(prev.common_name, prev.subject_alt_names)
      if (!suggestion) {
        return prev
      }
      monitoringAutoUrlRef.current = suggestion
      return {
        ...prev,
        monitoring_target_url: suggestion,
        monitoring_enabled: true,
        monitoring_target_port: prev.monitoring_target_port || DEFAULT_MONITORING_PORT.toString()
      }
    })
  }

  const handleMonitoringInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setMonitoringForm(prev => ({
      ...prev,
      [name]: value
    }))
  }

  const handleMonitoringCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { checked } = e.target
    setMonitoringForm(prev => ({
      ...prev,
      monitoring_enabled: checked,
      monitoring_target_url: checked
        ? (prev.monitoring_target_url || (selectedCertificate ? buildDefaultMonitoringUrl(selectedCertificate.common_name, selectedCertificate.subject_alt_names.join(', ')) : ''))
        : '',
      monitoring_target_port: checked ? (prev.monitoring_target_port || DEFAULT_MONITORING_PORT.toString()) : DEFAULT_MONITORING_PORT.toString()
    }))
  }

  const monitoringFormChanged = useMemo(() => {
    if (!selectedCertificate) {
      return false
    }
    const currentPort = monitoringForm.monitoring_target_port || DEFAULT_MONITORING_PORT.toString()
    const originalPort = selectedCertificate.monitoring_target_port?.toString() || DEFAULT_MONITORING_PORT.toString()
    const currentUrl = monitoringForm.monitoring_target_url || ''
    const originalUrl = selectedCertificate.monitoring_target_url || ''
    return (
      monitoringForm.monitoring_enabled !== selectedCertificate.monitoring_enabled ||
      currentUrl !== originalUrl ||
      currentPort !== originalPort
    )
  }, [monitoringForm, selectedCertificate])

  const handleApplySuggestedMonitoringUrl = () => {
    if (!selectedCertificate) {
      return
    }
    const suggestion = buildDefaultMonitoringUrl(
      selectedCertificate.common_name,
      selectedCertificate.subject_alt_names.join(', ')
    )
    if (!suggestion) {
      return
    }
    setMonitoringForm(prev => ({
      ...prev,
      monitoring_target_url: suggestion
    }))
  }

  const handleSaveMonitoringPreferences = () => {
    if (!selectedCertificate) {
      return
    }
    if (monitoringForm.monitoring_enabled && !monitoringForm.monitoring_target_url.trim()) {
      toast.error('Provide a monitoring URL')
      return
    }

    const payload = {
      monitoring_enabled: monitoringForm.monitoring_enabled,
      monitoring_target_url: monitoringForm.monitoring_enabled
        ? monitoringForm.monitoring_target_url.trim()
        : undefined,
      monitoring_target_port: monitoringForm.monitoring_enabled
        ? (Number(monitoringForm.monitoring_target_port) || DEFAULT_MONITORING_PORT)
        : undefined,
      monitoring_channels: selectedCertificate.monitoring_channels || []
    }

    monitoringMutation.mutate({ certificateId: selectedCertificate.id, payload })
  }

  const handleValidityPresetChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const presetValue = e.target.value
    setValidityPreset(presetValue)

    if (presetValue === CUSTOM_VALIDITY_VALUE) {
      return
    }

    const years = parseInt(presetValue, 10)
    if (!Number.isNaN(years)) {
      const days = years * 365
      setIssueForm(prev => ({
        ...prev,
        validity_days: days
      }))
    }
  }

  const handleRevoke = async (certificateId: string) => {
    const confirmed = await confirm({
      title: 'Revoke Certificate',
      message: 'Are you sure you want to revoke this certificate? This action cannot be undone.',
      confirmLabel: 'Revoke',
      variant: 'danger'
    })
    if (confirmed) {
      try {
        await revokeMutation.mutateAsync(certificateId)
      } catch (error) {
        console.error('Failed to revoke certificate:', error)
      }
    }
  }

  const handleRenew = async (certificateId: string) => {
    try {
      await renewMutation.mutateAsync(certificateId)
    } catch (error) {
      console.error('Failed to renew certificate:', error)
    }
  }

  const handleDelete = async (certificateId: string, status: string) => {
    if (status === 'active') {
      toast.error('Revoke the certificate before deleting it permanently.')
      return
    }

    const confirmed = await confirm({
      title: 'Delete Certificate',
      message: 'This will permanently delete the certificate record. Continue?',
      confirmLabel: 'Delete',
      variant: 'danger'
    })
    if (confirmed) {
      try {
        await deleteMutation.mutateAsync(certificateId)
      } catch (error) {
        console.error('Failed to delete certificate:', error)
      }
    }
  }

  const handleViewCertificate = (cert: Certificate) => {
    setSelectedCertificate(cert)
  }

  const handleCloseCertificateDetails = () => {
    setSelectedCertificate(null)
  }

  const handleDownloadCertificate = async (cert: Certificate, mode: 'leaf' | 'chain' | 'key' | 'bundle') => {
    const targetKey = `${cert.id}-${mode}`
    setDownloadTarget(targetKey)
    try {
      const params: Record<string, boolean> = {}
      
      switch (mode) {
        case 'leaf':
          params.include_chain = false
          params.include_private_key = false
          params.include_leaf_certificate = true
          break
        case 'chain':
          params.include_chain = true
          params.include_private_key = false
          params.include_leaf_certificate = true
          break
        case 'key':
          params.include_chain = false
          params.include_private_key = true
          params.include_leaf_certificate = false
          break
        case 'bundle':
          params.include_chain = true
          params.include_private_key = true
          params.include_leaf_certificate = true
          break
      }

      const response = await apiClient.get(`/certificates/${cert.id}/download`, {
        params,
        responseType: 'blob'
      })

      const disposition = response.headers['content-disposition'] as string | undefined
      const match = disposition?.match(/filename="?([^";]+)"?/i)
      let filename = match?.[1]
      
      if (!filename) {
        const base = cert.common_name.replace(/\s+/g, '_')
        if (mode === 'key') filename = `${base}.key`
        else if (mode === 'leaf') filename = `${base}.crt`
        else filename = `${base}.pem`
      }

      const url = window.URL.createObjectURL(response.data)
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', filename)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      
      const messages = {
        leaf: 'Certificate downloaded',
        chain: 'Certificate chain downloaded',
        key: 'Private key downloaded',
        bundle: 'Full bundle downloaded'
      }
      toast.success(messages[mode])
    } catch (error) {
      toast.error(getApiErrorMessage(error, 'Unable to download certificate'))
    } finally {
      setDownloadTarget(null)
    }
  }

  const handleCopyToClipboard = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success(`${label} copied to clipboard`)
    } catch (error) {
      console.error('Clipboard copy failed', error)
      toast.error('Unable to copy to clipboard')
    }
  }

  const formatDateTime = (value?: string) => {
    if (!value) return '—'
    return new Date(value).toLocaleString()
  }

  const handleOpenVaultUi = () => {
    window.open(getVaultUiUrl(), '_blank', 'noopener,noreferrer')
  }

  const getStatusBadge = (status: string) => {
    const statusColors = {
      active: 'bg-green-100 text-green-800',
      expired: 'bg-red-100 text-red-800',
      revoked: 'bg-gray-100 text-gray-800',
      pending: 'bg-yellow-100 text-yellow-800'
    }
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusColors[status as keyof typeof statusColors] || 'bg-gray-100 text-gray-800'}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    )
  }

  const getDaysUntilExpiry = (expiresAt: string) => {
    const now = new Date()
    const expiry = new Date(expiresAt)
    const diffTime = expiry.getTime() - now.getTime()
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return diffDays
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <div className="text-red-600 mb-4">
          <svg className="mx-auto h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to load certificates</h3>
        <p className="text-gray-500">Please try again later.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
  <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Certificates</h1>
          <p className="mt-1 text-sm text-gray-500">
            Manage and monitor your SSL/TLS certificates
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleOpenVaultUi}
            className="inline-flex items-center justify-center rounded-md border border-gray-300 px-4 py-2 text-sm font-semibold text-gray-700 shadow-sm transition hover:bg-gray-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2"
          >
            Open Vault UI
          </button>
          <button
            onClick={handleOpenIssueModal}
            className="inline-flex items-center justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2"
          >
            Issue Certificate
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <label htmlFor="search" className="block text-sm font-medium text-gray-700 mb-1">
              Search
            </label>
            <input
              type="text"
              id="search"
              value={filters.search}
              onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
              placeholder="Search by common name, serial number..."
              className="flex h-10 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm placeholder:text-gray-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
            />
          </div>
          <div className="sm:w-48">
            <label htmlFor="status" className="block text-sm font-medium text-gray-700 mb-1">
              Status
            </label>
            <select
              id="status"
              value={filters.status}
              onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
              className="flex h-10 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
            >
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="expired">Expired</option>
              <option value="revoked">Revoked</option>
              <option value="pending">Pending</option>
            </select>
          </div>
        </div>
      </div>

      {/* Certificates Table */}
      <div className="bg-white shadow rounded-lg overflow-hidden">
        <div className="px-4 py-5 sm:p-6">
          {certificates && certificates.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Certificate
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Expires
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Serial Number
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {certificates.map((cert) => {
                    const daysUntilExpiry = getDaysUntilExpiry(cert.not_valid_after)
                    return (
                      <tr key={cert.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div className="text-sm font-medium text-gray-900">
                              {cert.common_name}
                            </div>
                            {cert.monitoring_enabled && (
                              <span className="mt-1 inline-flex items-center rounded-full bg-sky-100 px-2 py-0.5 text-[11px] font-medium text-sky-700">
                                Monitoring
                              </span>
                            )}
                            {cert.subject_alt_names && cert.subject_alt_names.length > 0 && (
                              <div className="mt-1 text-xs text-gray-500 truncate max-w-xs">
                                {cert.subject_alt_names.join(', ')}
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {getStatusBadge(cert.status)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {new Date(cert.not_valid_after).toLocaleDateString()}
                          </div>
                          {cert.status === 'active' && (
                            <div className={`text-sm ${daysUntilExpiry <= 30 ? 'text-red-600' : daysUntilExpiry <= 60 ? 'text-yellow-600' : 'text-gray-500'}`}>
                              {daysUntilExpiry > 0 ? `${daysUntilExpiry} days left` : `Expired ${Math.abs(daysUntilExpiry)} days ago`}
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                          {cert.serial_number}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                          <div className="flex flex-wrap justify-end gap-3">
                            {cert.status === 'active' && (
                              <>
                                <button
                                  onClick={() => handleRenew(cert.id.toString())}
                                  disabled={renewMutation.isPending}
                                  className="text-indigo-600 hover:text-indigo-900 disabled:opacity-50"
                                >
                                  Renew
                                </button>
                                <button
                                  onClick={() => handleRevoke(cert.id.toString())}
                                  disabled={revokeMutation.isPending}
                                  className="text-red-600 hover:text-red-900 disabled:opacity-50"
                                >
                                  Revoke
                                </button>
                              </>
                            )}
                            {cert.status !== 'active' && (
                              <button
                                onClick={() => handleDelete(cert.id.toString(), cert.status)}
                                disabled={deleteMutation.isPending}
                                className="text-red-600 hover:text-red-900 disabled:opacity-50"
                              >
                                Delete
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => handleViewCertificate(cert)}
                              className="text-gray-600 hover:text-gray-900"
                            >
                              View
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12">
              <svg className="mx-auto h-8 w-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
              </svg>
              <h3 className="mt-2 text-sm font-medium text-gray-900">No certificates found</h3>
              <p className="mt-1 text-sm text-gray-500">
                Get started by issuing your first certificate.
              </p>
              <div className="mt-6">
                <button
                  onClick={handleOpenIssueModal}
                  className="inline-flex items-center justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2"
                >
                  Issue Certificate
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Issue Certificate Modal */}
      {showIssueModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-6 border max-w-2xl shadow-lg rounded-md bg-white">
            <div className="mb-4">
              <h3 className="text-lg font-medium text-gray-900">Issue New Certificate</h3>
              <p className="text-sm text-gray-500">Fill out the form below to generate a new certificate</p>
            </div>

            <form onSubmit={handleIssueSubmit} className="space-y-4">
              {/* Common Name */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Common Name (CN) *
                </label>
                <input
                  type="text"
                  name="common_name"
                  value={issueForm.common_name}
                  onChange={handleInputChange}
                  placeholder="example.com"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>

              {/* Certificate Type */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Certificate Type *
                </label>
                <select
                  name="certificate_type"
                  value={issueForm.certificate_type}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {CERTIFICATE_TYPE_OPTIONS.map(option => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Organization Details */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Organization
                  </label>
                  <input
                    type="text"
                    name="organization"
                    value={issueForm.organization}
                    onChange={handleInputChange}
                    placeholder="Your Organization"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Organizational Unit
                  </label>
                  <input
                    type="text"
                    name="organizational_unit"
                    value={issueForm.organizational_unit}
                    onChange={handleInputChange}
                    placeholder="IT Department"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>

              {/* Location Details */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Country
                  </label>
                  <input
                    type="text"
                    name="country"
                    value={issueForm.country}
                    onChange={handleInputChange}
                    placeholder="US"
                    maxLength={2}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    State/Province
                  </label>
                  <input
                    type="text"
                    name="state"
                    value={issueForm.state}
                    onChange={handleInputChange}
                    placeholder="California"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    City/Locality
                  </label>
                  <input
                    type="text"
                    name="locality"
                    value={issueForm.locality}
                    onChange={handleInputChange}
                    placeholder="San Francisco"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>

              {/* Email */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email Address
                </label>
                <input
                  type="email"
                  name="email"
                  value={issueForm.email}
                  onChange={handleInputChange}
                  placeholder="admin@example.com"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              {/* Subject Alternative Names */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Subject Alternative Names (SAN)
                </label>
                <input
                  type="text"
                  name="subject_alt_names"
                  value={issueForm.subject_alt_names}
                  onChange={handleInputChange}
                  placeholder="www.example.com, api.example.com"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <p className="text-xs text-gray-500 mt-1">Comma-separated list of alternative domain names</p>
              </div>

              <div className="rounded-lg border border-gray-200 p-4">
                <label className="flex items-center gap-2 text-sm font-medium text-gray-900">
                  <input
                    type="checkbox"
                    name="monitoring_enabled"
                    checked={issueForm.monitoring_enabled}
                    onChange={handleIssueCheckboxChange}
                    className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  Monitor this endpoint after issuance
                </label>
                <p className="mt-1 text-xs text-gray-500">
                  Automatically create a monitoring entry that pings the certificate host over HTTPS.
                </p>
                {issueForm.monitoring_enabled && (
                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <div className="sm:col-span-2">
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Monitoring URL
                      </label>
                      <input
                        type="text"
                        name="monitoring_target_url"
                        value={issueForm.monitoring_target_url}
                        onChange={handleInputChange}
                        placeholder="https://service.example.com"
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        required
                      />
                      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-gray-500">
                        <span>Default: https://SAN (or common name)</span>
                        <button
                          type="button"
                          onClick={handleUseIssueMonitorSuggestion}
                          className="text-indigo-600 hover:text-indigo-800"
                        >
                          Use suggested URL
                        </button>
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Port
                      </label>
                      <input
                        type="number"
                        name="monitoring_target_port"
                        min={1}
                        max={65535}
                        value={issueForm.monitoring_target_port}
                        onChange={handleInputChange}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <p className="text-xs text-gray-500 mt-1">Defaults to {DEFAULT_MONITORING_PORT} for HTTPS checks.</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Validity Period */}
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Validity Period (days)
                  </label>
                  <input
                    type="number"
                    name="validity_days"
                    value={issueForm.validity_days}
                    onChange={handleInputChange}
                    min={1}
                    max={MAX_VALIDITY_DAYS}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <p className="text-xs text-gray-500 mt-1">Supports up to {MAX_VALIDITY_YEARS} years ({MAX_VALIDITY_DAYS.toLocaleString()} days). Adjust for leap years if needed.</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Quick Select (years)
                  </label>
                  <select
                    value={validityPreset}
                    onChange={handleValidityPresetChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value={CUSTOM_VALIDITY_VALUE}>Custom (enter days)</option>
                    {YEAR_OPTIONS.map(year => (
                      <option key={year} value={year.toString()}>
                        {year} {year === 1 ? 'Year' : 'Years'} ({year * 365} days)
                      </option>
                    ))}
                  </select>
                  <p className="text-xs text-gray-500 mt-1">Picking a year will auto-fill the days field.</p>
                </div>
              </div>

              {/* Form Actions */}
              {issueError && (
                <div className="text-sm text-red-600">
                  {issueError}
                </div>
              )}
              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={handleCloseIssueModal}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={issueMutation.isPending}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {issueMutation.isPending ? 'Issuing...' : 'Issue Certificate'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Certificate Details Modal */}
      {selectedCertificate && (
        <div className="fixed inset-0 bg-gray-900 bg-opacity-50 z-50 overflow-y-auto">
          <div className="mx-auto mt-10 w-full max-w-3xl rounded-lg bg-white shadow-xl">
            <div className="flex items-start justify-between border-b px-6 py-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Certificate Details</h3>
                <p className="text-sm text-gray-500">{selectedCertificate.common_name}</p>
              </div>
              <div className="flex items-center gap-3">
                {getStatusBadge(selectedCertificate.status)}
                <button
                  onClick={handleCloseCertificateDetails}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <span className="sr-only">Close</span>
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            <div className="px-6 py-5 space-y-5">
              <div className="flex flex-col gap-2">
                <div className="flex flex-wrap gap-3">
                <button
                  type="button"
                  onClick={() => handleDownloadCertificate(selectedCertificate, 'key')}
                  disabled={downloadTarget === `${selectedCertificate.id}-key` || !selectedCertificate.pem_available}
                  className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {downloadTarget === `${selectedCertificate.id}-key` ? 'Preparing…' : 'Download Key'}
                </button>
                <button
                  type="button"
                  onClick={() => handleDownloadCertificate(selectedCertificate, 'chain')}
                  disabled={downloadTarget === `${selectedCertificate.id}-chain` || !selectedCertificate.pem_available}
                  className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {downloadTarget === `${selectedCertificate.id}-chain` ? 'Preparing…' : 'Download Chain'}
                </button>
                <button
                  type="button"
                  onClick={() => handleDownloadCertificate(selectedCertificate, 'bundle')}
                  disabled={downloadTarget === `${selectedCertificate.id}-bundle` || !selectedCertificate.pem_available}
                  className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {downloadTarget === `${selectedCertificate.id}-bundle` ? 'Preparing…' : 'Full Bundle'}
                </button>
                <button
                  type="button"
                  onClick={() => handleCopyToClipboard(selectedCertificate.serial_number, 'Serial number')}
                  className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Copy Serial
                </button>
                {selectedCertificate.subject_alt_names.length > 0 && (
                  <button
                    type="button"
                    onClick={() => handleCopyToClipboard(selectedCertificate.subject_alt_names.join(', '), 'SAN list')}
                    className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Copy SANs
                  </button>
                )}
                </div>
                <p className="text-xs text-gray-500">
                  Download Bundle includes the private key and issuing CA chain.
                </p>
              </div>

              <dl className="grid gap-4 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-gray-500">Serial Number</dt>
                  <dd className="font-mono text-gray-900 break-all whitespace-pre-wrap leading-relaxed">
                    {selectedCertificate.serial_number}
                  </dd>
                </div>
                <div>
                  <dt className="text-gray-500">Certificate Type</dt>
                  <dd className="text-gray-900 capitalize">{selectedCertificate.certificate_type}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Key Size</dt>
                  <dd className="text-gray-900">{selectedCertificate.key_size} bit</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Signature Algorithm</dt>
                  <dd className="text-gray-900">{selectedCertificate.signature_algorithm}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Issuer</dt>
                  <dd className="text-gray-900">{selectedCertificate.issuer_common_name || '—'}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Issued At</dt>
                  <dd className="text-gray-900">{formatDateTime(selectedCertificate.issued_at)}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Valid From</dt>
                  <dd className="text-gray-900">{formatDateTime(selectedCertificate.not_valid_before)}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Valid Until</dt>
                  <dd className="text-gray-900">{formatDateTime(selectedCertificate.not_valid_after)}</dd>
                </div>
                {selectedCertificate.revoked_at && (
                  <div>
                    <dt className="text-gray-500">Revoked At</dt>
                    <dd className="text-gray-900">{formatDateTime(selectedCertificate.revoked_at)}</dd>
                  </div>
                )}
                {selectedCertificate.revocation_reason && (
                  <div>
                    <dt className="text-gray-500">Revocation Reason</dt>
                    <dd className="text-gray-900">{selectedCertificate.revocation_reason}</dd>
                  </div>
                )}
              </dl>

              <div>
                <h4 className="text-sm font-medium text-gray-900">Subject Alternative Names</h4>
                {selectedCertificate.subject_alt_names.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {selectedCertificate.subject_alt_names.map((san) => (
                      <span key={san} className="rounded-full bg-gray-100 px-3 py-1 text-xs text-gray-700">
                        {san}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="mt-1 text-sm text-gray-500">No SAN entries configured.</p>
                )}
              </div>

              <div>
                <h4 className="text-sm font-medium text-gray-900">Deployment Locations</h4>
                {selectedCertificate.deployment_locations.length > 0 ? (
                  <ul className="mt-2 list-disc pl-5 text-sm text-gray-700">
                    {selectedCertificate.deployment_locations.map((location) => (
                      <li key={location}>{location}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-1 text-sm text-gray-500">Deployment targets not recorded.</p>
                )}
              </div>

              <div className="rounded-lg border border-gray-200 p-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-gray-900">Monitoring</h4>
                    <p className="text-xs text-gray-500">Keep this certificate under continuous HTTPS checks.</p>
                  </div>
                  <label className="inline-flex items-center gap-2 text-sm font-medium text-gray-900">
                    <input
                      type="checkbox"
                      checked={monitoringForm.monitoring_enabled}
                      onChange={handleMonitoringCheckboxChange}
                      className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    Enabled
                  </label>
                </div>
                {monitoringForm.monitoring_enabled ? (
                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <div className="sm:col-span-2">
                      <label className="block text-sm font-medium text-gray-700 mb-1">Monitoring URL</label>
                      <input
                        type="text"
                        name="monitoring_target_url"
                        value={monitoringForm.monitoring_target_url}
                        onChange={handleMonitoringInputChange}
                        placeholder="https://service.example.com"
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
                      <input
                        type="number"
                        name="monitoring_target_port"
                        value={monitoringForm.monitoring_target_port}
                        min={1}
                        max={65535}
                        onChange={handleMonitoringInputChange}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <p className="text-xs text-gray-500 mt-1">Default is {DEFAULT_MONITORING_PORT}.</p>
                    </div>
                    <div className="flex items-center">
                      <button
                        type="button"
                        onClick={handleApplySuggestedMonitoringUrl}
                        className="text-sm font-medium text-indigo-600 hover:text-indigo-800"
                      >
                        Use suggested URL
                      </button>
                    </div>
                  </div>
                ) : (
                  <p className="mt-3 text-sm text-gray-500">
                    Monitoring is disabled. Enable it to populate the Monitoring tab for this certificate.
                  </p>
                )}
                <div className="mt-4 flex flex-wrap items-center justify-end gap-3">
                  <button
                    type="button"
                    onClick={handleSaveMonitoringPreferences}
                    disabled={!monitoringFormChanged || monitoringMutation.isPending}
                    className="inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:opacity-50"
                  >
                    {monitoringMutation.isPending ? 'Saving…' : 'Save Monitoring'}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 border-t px-6 py-4">
              <button
                type="button"
                onClick={handleCloseCertificateDetails}
                className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}

export default Certificates