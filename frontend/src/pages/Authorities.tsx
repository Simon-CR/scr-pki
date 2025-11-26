import React, { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'

import { api, apiClient } from '../services/api'
import LoadingSpinner from '../components/LoadingSpinner'
import { CAHierarchyResponse, CAInitializeRequest, CertificateAuthority } from '../types'

const KEY_SIZE_OPTIONS = [2048, 3072, 4096]
const ROOT_MAX_VALIDITY_YEARS = 30
const ROOT_DEFAULT_VALIDITY_YEARS = 10
const ROOT_MAX_VALIDITY_DAYS = ROOT_MAX_VALIDITY_YEARS * 365
const ROOT_DEFAULT_VALIDITY_DAYS = ROOT_DEFAULT_VALIDITY_YEARS * 365
const ROOT_CUSTOM_VALIDITY = 'custom'
const ROOT_YEAR_OPTIONS = Array.from({ length: ROOT_MAX_VALIDITY_YEARS }, (_, index) => index + 1)
const INTERMEDIATE_MAX_VALIDITY_YEARS = 20
const INTERMEDIATE_DEFAULT_VALIDITY_YEARS = 5
const INTERMEDIATE_MAX_VALIDITY_DAYS = INTERMEDIATE_MAX_VALIDITY_YEARS * 365
const INTERMEDIATE_DEFAULT_VALIDITY_DAYS = INTERMEDIATE_DEFAULT_VALIDITY_YEARS * 365
const INTERMEDIATE_CUSTOM_VALIDITY = 'custom'
const INTERMEDIATE_YEAR_OPTIONS = Array.from({ length: INTERMEDIATE_MAX_VALIDITY_YEARS }, (_, index) => index + 1)

const getApiErrorMessage = (error: unknown, fallback: string): string => {
  if (error && typeof error === 'object' && 'response' in error) {
    const err = error as { response?: { data?: { detail?: string; message?: string }; status?: number }; message?: string }
    const detail = err.response?.data?.detail || err.response?.data?.message
    if (detail) {
      return detail
    }
    if (err.message) {
      return err.message
    }
  }
  if (error instanceof Error) {
    return error.message || fallback
  }
  return fallback
}

type RootFormState = {
  common_name: string
  organization: string
  organizational_unit: string
  country: string
  state: string
  locality: string
  email: string
  validity_days: number
  key_size: number
  create_intermediate: boolean
  intermediate_common_name: string
  offline_root: boolean
  path_length: number
}

type IntermediateFormState = {
  intermediate_common_name: string
  organization: string
  organizational_unit: string
  country: string
  state: string
  locality: string
  email: string
  validity_days: number
  key_size: number
  parent_ca_id?: number
  path_length: number
}

type CAImportMode = 'root' | 'intermediate'

type ImportFormState = {
  pem_certificate: string
  pem_private_key: string
  private_key_password: string
  offline_root: boolean
  parent_ca_id?: number
  is_offline: boolean
  root_certificate_pem: string
}

const createDefaultRootForm = (): RootFormState => ({
  common_name: 'Internal Root CA',
  organization: '',
  organizational_unit: '',
  country: 'US',
  state: '',
  locality: '',
  email: '',
  validity_days: ROOT_DEFAULT_VALIDITY_DAYS,
  key_size: 4096,
  create_intermediate: true,
  intermediate_common_name: 'Internal Issuing CA',
  offline_root: true,
  path_length: 1,
})

const createDefaultIntermediateForm = (root?: CertificateAuthority | null): IntermediateFormState => ({
  intermediate_common_name: root ? `${root.common_name} Intermediate CA ${root.child_count + 1 || 1}` : 'Issuing CA',
  organization: root?.organization ?? '',
  organizational_unit: root?.organizational_unit ?? '',
  country: root?.country ?? 'US',
  state: root?.state ?? '',
  locality: root?.locality ?? '',
  email: root?.email ?? '',
  validity_days: INTERMEDIATE_DEFAULT_VALIDITY_DAYS,
  key_size: 4096,
  parent_ca_id: root?.id,
  path_length: 0,
})

const createDefaultImportForm = (mode: CAImportMode, root?: CertificateAuthority | null): ImportFormState => ({
  pem_certificate: '',
  pem_private_key: '',
  private_key_password: '',
  offline_root: mode === 'root',
  parent_ca_id: mode === 'intermediate' ? root?.id : undefined,
  is_offline: mode === 'intermediate' ? false : true,
  root_certificate_pem: '',
})

const formatDate = (value?: string | null) => {
  if (!value) return '—'
  return new Date(value).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

const getRootValidityPreset = (days: number): string => {
  const exactYear = ROOT_YEAR_OPTIONS.find((year) => year * 365 === days)
  return exactYear ? String(exactYear) : ROOT_CUSTOM_VALIDITY
}

const getIntermediateValidityPreset = (days: number): string => {
  const exactYear = INTERMEDIATE_YEAR_OPTIONS.find((year) => year * 365 === days)
  return exactYear ? String(exactYear) : INTERMEDIATE_CUSTOM_VALIDITY
}

const renderStatusBadge = (status: CertificateAuthority['status'], isOffline: boolean, highlight = false) => {
  const statusClasses: Record<string, string> = {
    active: 'bg-green-100 text-green-800',
    initializing: 'bg-blue-100 text-blue-800',
    suspended: 'bg-yellow-100 text-yellow-800',
    revoked: 'bg-red-100 text-red-800',
  }

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-medium ${
        statusClasses[status] || 'bg-gray-100 text-gray-800'
      } ${highlight ? 'ring-2 ring-offset-2 ring-indigo-200' : ''}`}
    >
      {status.charAt(0).toUpperCase() + status.slice(1)}
      {isOffline && <span className="text-[10px] font-semibold uppercase">Offline</span>}
    </span>
  )
}

const getDeleteRestriction = (ca: CertificateAuthority): string | null => {
  if (ca.is_root) {
    return 'Root Certificate Authorities cannot be deleted.'
  }
  if (ca.child_count > 0) {
    return 'Remove child intermediates before deleting this authority.'
  }
  if (ca.issued_certificates_count > 0) {
    return 'Revoke or migrate certificates issued by this authority before deleting it.'
  }
  return null
}

const Authorities: React.FC = () => {
  const queryClient = useQueryClient()
  const { data, isLoading, error } = useQuery({
    queryKey: ['ca-hierarchy'],
    queryFn: async () => api.get<CAHierarchyResponse>('/ca/info'),
  })
  const rootCa = data?.root_ca ?? null
  const activeCa = data?.active_ca ?? null
  const authorities = data?.hierarchy ?? []
  const authorityMap = useMemo(
    () => new Map(authorities.map((ca) => [ca.id, ca])),
    [authorities]
  )

  const [rootForm, setRootForm] = useState<RootFormState>(() => createDefaultRootForm())
  const [rootValidityPreset, setRootValidityPreset] = useState<string>(() =>
    getRootValidityPreset(ROOT_DEFAULT_VALIDITY_DAYS)
  )
  const [intermediateForm, setIntermediateForm] = useState<IntermediateFormState>(() => createDefaultIntermediateForm(rootCa))
  const [intermediateValidityPreset, setIntermediateValidityPreset] = useState<string>(() =>
    getIntermediateValidityPreset(INTERMEDIATE_DEFAULT_VALIDITY_DAYS)
  )
  const [showRootModal, setShowRootModal] = useState(false)
  const [showIntermediateModal, setShowIntermediateModal] = useState(false)
  const [downloadTarget, setDownloadTarget] = useState<string | null>(null)
  const [showImportModal, setShowImportModal] = useState(false)
  const [importMode, setImportMode] = useState<CAImportMode>('root')
  const [importForm, setImportForm] = useState<ImportFormState>(() => createDefaultImportForm('root', rootCa))

  useEffect(() => {
    const nextForm = createDefaultIntermediateForm(rootCa)
    setIntermediateForm(nextForm)
    setIntermediateValidityPreset(getIntermediateValidityPreset(nextForm.validity_days))
  }, [rootCa])

  useEffect(() => {
    setImportForm((prev) => ({
      ...prev,
      parent_ca_id: importMode === 'intermediate' ? rootCa?.id : undefined,
    }))
  }, [rootCa, importMode])

  const initializeMutation = useMutation({
    mutationFn: async (payload: CAInitializeRequest) => api.post<CAHierarchyResponse>('/ca/initialize', payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ca-hierarchy'] })
    },
  })

  const importMutation = useMutation({
    mutationFn: async ({ mode, payload }: { mode: CAImportMode; payload: any }) => {
      if (mode === 'root') {
        return api.post<CertificateAuthority>('/ca/import/root', payload)
      }
      return api.post<CertificateAuthority>('/ca/import/intermediate', payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ca-hierarchy'] })
    },
  })

  const setActiveMutation = useMutation({
    mutationFn: async (caId: number) => api.post<CertificateAuthority>(`/ca/${caId}/set-active`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ca-hierarchy'] })
    },
  })
  const deleteMutation = useMutation({
    mutationFn: async (caId: number) => api.delete(`/ca/${caId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ca-hierarchy'] })
      toast.success('Certificate Authority deleted')
    },
    onError: (deleteError: unknown) => {
      toast.error(getApiErrorMessage(deleteError, 'Unable to delete Certificate Authority'))
    },
  })
  const handleDeleteAuthority = (ca: CertificateAuthority) => {
    const restriction = getDeleteRestriction(ca)
    if (restriction) {
      toast.error(restriction)
      return
    }
    const messageParts = [
      `Delete ${ca.common_name}?`,
      'This permanently removes the CA metadata and its private key from Vault.',
      'Only delete unused intermediates without child CAs or issued certificates.',
    ]
    if (window.confirm(messageParts.join('\n\n'))) {
      deleteMutation.mutate(ca.id)
    }
  }

  const handleDownloadCertificate = async ({
    caId,
    root = false,
    includeChain = true,
    label,
  }: {
    caId?: number
    root?: boolean
    includeChain?: boolean
    label: string
  }) => {
    setDownloadTarget(label)
    try {
      const response = await apiClient.get<Blob>('/ca/certificate', {
        params: {
          ...(root ? { root: true } : {}),
          ...(caId ? { ca_id: caId } : {}),
          include_chain: includeChain,
        },
        responseType: 'blob',
      })

      const disposition = response.headers['content-disposition'] as string | undefined
      const match = disposition?.match(/filename="?([^";]+)"?/i)
      const filename = match?.[1] || `${label.replace(/\s+/g, '_')}.pem`

      const url = window.URL.createObjectURL(response.data)
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', filename)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      toast.success(`Downloaded ${label}`)
    } catch (downloadError) {
      toast.error(getApiErrorMessage(downloadError, 'Unable to download certificate'))
    } finally {
      setDownloadTarget(null)
    }
  }

  const updateRootValidityDays = (value: number) => {
    const clamped = Math.max(365, Math.min(value, ROOT_MAX_VALIDITY_DAYS))
    setRootForm((prev) => ({
      ...prev,
      validity_days: clamped,
    }))
    setRootValidityPreset(getRootValidityPreset(clamped))
  }

  const handleRootValidityDaysChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const parsed = Number(event.target.value)
    if (Number.isNaN(parsed)) {
      setRootValidityPreset(ROOT_CUSTOM_VALIDITY)
      return
    }
    updateRootValidityDays(parsed)
  }

  const handleRootValidityPresetChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    const preset = event.target.value
    setRootValidityPreset(preset)
    if (preset === ROOT_CUSTOM_VALIDITY) {
      return
    }
    const years = parseInt(preset, 10)
    if (!Number.isNaN(years)) {
      updateRootValidityDays(years * 365)
    }
  }

  const updateIntermediateValidityDays = (value: number) => {
    const clamped = Math.max(365, Math.min(value, INTERMEDIATE_MAX_VALIDITY_DAYS))
    setIntermediateForm((prev) => ({
      ...prev,
      validity_days: clamped,
    }))
    setIntermediateValidityPreset(getIntermediateValidityPreset(clamped))
  }

  const handleIntermediateValidityDaysChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const parsed = Number(event.target.value)
    if (Number.isNaN(parsed)) {
      setIntermediateValidityPreset(INTERMEDIATE_CUSTOM_VALIDITY)
      return
    }
    updateIntermediateValidityDays(parsed)
  }

  const handleIntermediateValidityPresetChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    const preset = event.target.value
    setIntermediateValidityPreset(preset)
    if (preset === INTERMEDIATE_CUSTOM_VALIDITY) {
      return
    }
    const years = parseInt(preset, 10)
    if (!Number.isNaN(years)) {
      updateIntermediateValidityDays(years * 365)
    }
  }

  const handleRootSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!rootForm.common_name.trim() || !rootForm.organization.trim()) {
      toast.error('Common name and organization are required')
      return
    }

    const payload: CAInitializeRequest = {
      common_name: rootForm.common_name.trim(),
      organization: rootForm.organization.trim(),
      organizational_unit: rootForm.organizational_unit.trim() || undefined,
      country: rootForm.country.trim().toUpperCase(),
      state: rootForm.state.trim() || undefined,
      locality: rootForm.locality.trim() || undefined,
      email: rootForm.email.trim() || undefined,
      validity_days: rootForm.validity_days,
      key_size: rootForm.key_size,
      create_intermediate: rootForm.create_intermediate,
      intermediate_common_name: rootForm.create_intermediate
        ? rootForm.intermediate_common_name.trim() || `${rootForm.common_name} Issuing CA`
        : undefined,
      offline_root: rootForm.offline_root,
      path_length: rootForm.create_intermediate ? rootForm.path_length : undefined,
    }

    try {
      await initializeMutation.mutateAsync(payload)
      toast.success('Root Certificate Authority initialized')
      setShowRootModal(false)
      setRootForm(createDefaultRootForm())
      setRootValidityPreset(getRootValidityPreset(ROOT_DEFAULT_VALIDITY_DAYS))
    } catch (submitError) {
      toast.error(getApiErrorMessage(submitError, 'Failed to initialize root CA'))
    }
  }

  const handleIntermediateSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!intermediateForm.intermediate_common_name.trim()) {
      toast.error('Intermediate common name is required')
      return
    }
    if (!intermediateForm.parent_ca_id) {
      toast.error('Choose the parent CA that will sign this intermediate')
      return
    }

    const payload: CAInitializeRequest = {
      common_name: rootCa?.common_name || `${intermediateForm.intermediate_common_name} Root`,
      organization: intermediateForm.organization.trim() || (rootCa?.organization ?? ''),
      organizational_unit: intermediateForm.organizational_unit.trim() || undefined,
      country: intermediateForm.country.trim().toUpperCase(),
      state: intermediateForm.state.trim() || undefined,
      locality: intermediateForm.locality.trim() || undefined,
      email: intermediateForm.email.trim() || undefined,
      validity_days: intermediateForm.validity_days,
      key_size: intermediateForm.key_size,
      create_intermediate: true,
      intermediate_common_name: intermediateForm.intermediate_common_name.trim(),
      parent_ca_id: intermediateForm.parent_ca_id,
      path_length: intermediateForm.path_length,
      offline_root: rootCa?.is_offline ?? true,
    }

    try {
      await initializeMutation.mutateAsync(payload)
      toast.success('Intermediate Certificate Authority created')
      setShowIntermediateModal(false)
      const resetForm = createDefaultIntermediateForm(rootCa)
      setIntermediateForm(resetForm)
      setIntermediateValidityPreset(getIntermediateValidityPreset(resetForm.validity_days))
    } catch (submitError) {
      toast.error(getApiErrorMessage(submitError, 'Failed to create intermediate CA'))
    }
  }

  const handleOpenImportModal = (mode: CAImportMode) => {
    setImportMode(mode)
    setImportForm(createDefaultImportForm(mode, rootCa))
    setShowImportModal(true)
  }

  const handleImportSubmit = async (event: React.FormEvent) => {
    event.preventDefault()

    if (!importForm.pem_certificate.trim()) {
      toast.error('Provide the PEM-encoded certificate')
      return
    }

    if (importMode === 'intermediate') {
      if (!importForm.pem_private_key.trim()) {
        toast.error('Intermediate imports require the private key PEM')
        return
      }
      if (!importForm.parent_ca_id) {
        toast.error('Select the parent CA that issued this intermediate')
        return
      }
    }

    const payload = importMode === 'root'
      ? {
          pem_certificate: importForm.pem_certificate.trim(),
          offline_root: importForm.offline_root,
          pem_private_key: importForm.pem_private_key.trim() || undefined,
          private_key_password: importForm.private_key_password.trim() || undefined,
        }
      : {
          pem_certificate: importForm.pem_certificate.trim(),
          pem_private_key: importForm.pem_private_key.trim(),
          private_key_password: importForm.private_key_password.trim() || undefined,
          parent_ca_id: importForm.parent_ca_id,
          root_certificate_pem: importForm.root_certificate_pem.trim() || undefined,
          is_offline: importForm.is_offline,
        }

    try {
      await importMutation.mutateAsync({ mode: importMode, payload })
      toast.success(importMode === 'root' ? 'Root CA imported' : 'Intermediate CA imported')
      setShowImportModal(false)
      setImportForm(createDefaultImportForm(importMode, rootCa))
    } catch (submitError) {
      toast.error(getApiErrorMessage(submitError, 'CA import failed'))
    }
  }

  const handleSetActive = async (caId: number) => {
    try {
      await setActiveMutation.mutateAsync(caId)
      toast.success('Issuing CA updated')
    } catch (updateError) {
      toast.error(getApiErrorMessage(updateError, 'Unable to set active CA'))
    }
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
        <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to load Certificate Authorities</h3>
        <p className="text-gray-500">{getApiErrorMessage(error, 'Please try again later.')}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Certificate Authorities</h1>
          <p className="mt-1 text-sm text-gray-500">
            View your trust hierarchy, download the root, and add issuing intermediates.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {rootCa && (
            <button
              type="button"
              onClick={() => handleDownloadCertificate({ root: true, includeChain: false, label: 'root-ca' })}
              disabled={downloadTarget === 'root-ca'}
              className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-semibold text-gray-700 shadow-sm transition hover:bg-gray-50 disabled:opacity-60"
            >
              {downloadTarget === 'root-ca' ? 'Preparing…' : 'Download Root CA'}
            </button>
          )}
          {activeCa && (
            <button
              type="button"
              onClick={() =>
                handleDownloadCertificate({ caId: activeCa.id, includeChain: true, label: 'issuing-chain' })
              }
              disabled={downloadTarget === 'issuing-chain'}
              className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-semibold text-gray-700 shadow-sm transition hover:bg-gray-50 disabled:opacity-60"
            >
              {downloadTarget === 'issuing-chain' ? 'Preparing…' : 'Download Issuing Chain'}
            </button>
          )}
          {rootCa && (
            <button
              type="button"
              onClick={() => setShowIntermediateModal(true)}
              className="inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700"
            >
              Add Intermediate CA
            </button>
          )}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-1">
        <div className="rounded-lg border border-dashed border-gray-300 p-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-gray-900">Bring your own CA material</h3>
              <p className="mt-1 text-sm text-gray-500">Import an existing root or intermediate certificate/key pair.</p>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() => handleOpenImportModal('root')}
              className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Import Root CA
            </button>
            <button
              type="button"
              onClick={() => handleOpenImportModal('intermediate')}
              className="inline-flex items-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Import Intermediate CA
            </button>
          </div>
          <p className="mt-3 text-xs text-gray-500">
            Paste PEM blocks directly from your HSM export or bundle. We keep encrypted copies in Vault immediately.
          </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="bg-white shadow rounded-lg p-6">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Root Authority</h2>
              <p className="text-sm text-gray-500">Your trust anchor for every issued certificate.</p>
            </div>
            {rootCa && renderStatusBadge(rootCa.status, rootCa.is_offline, rootCa.id === activeCa?.id)}
          </div>
          {rootCa ? (
            <dl className="mt-6 grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-gray-500">Common Name</dt>
                <dd className="font-medium text-gray-900">{rootCa.common_name}</dd>
              </div>
              <div>
                <dt className="text-gray-500">Organization</dt>
                <dd className="font-medium text-gray-900">{rootCa.organization}</dd>
              </div>
              <div>
                <dt className="text-gray-500">Serial</dt>
                <dd className="font-mono text-gray-900 break-all text-sm sm:text-base">{rootCa.serial_number}</dd>
              </div>
              <div>
                <dt className="text-gray-500">Valid Until</dt>
                <dd className="font-medium text-gray-900">
                  {formatDate(rootCa.not_valid_after)} ({rootCa.days_until_expiry} days)
                </dd>
              </div>
              <div>
                <dt className="text-gray-500">Offline Storage</dt>
                <dd className="font-medium text-gray-900">{rootCa.is_offline ? 'Yes' : 'No'}</dd>
              </div>
              <div>
                <dt className="text-gray-500">Children</dt>
                <dd className="font-medium text-gray-900">{rootCa.child_count}</dd>
              </div>
            </dl>
          ) : (
            <div className="mt-6 rounded-lg border border-dashed border-gray-300 p-6 text-center text-sm text-gray-600">
              <p>Create your first root CA to unlock certificate issuance.</p>
              <button
                type="button"
                onClick={() => setShowRootModal(true)}
                className="mt-4 inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
              >
                Launch Root CA Wizard
              </button>
            </div>
          )}
        </div>

        <div className="bg-white shadow rounded-lg p-6">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Active Issuing Authority</h2>
              <p className="text-sm text-gray-500">Certificates are currently minted by this CA.</p>
            </div>
            {activeCa && renderStatusBadge(activeCa.status, activeCa.is_offline, true)}
          </div>
          {activeCa ? (
            <dl className="mt-6 grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-gray-500">Common Name</dt>
                <dd className="font-medium text-gray-900">{activeCa.common_name}</dd>
              </div>
              <div>
                <dt className="text-gray-500">Issued Certificates</dt>
                <dd className="font-medium text-gray-900">{activeCa.issued_certificates_count}</dd>
              </div>
              <div>
                <dt className="text-gray-500">Parent</dt>
                <dd className="font-medium text-gray-900">
                  {activeCa.parent_ca_id ? authorityMap.get(activeCa.parent_ca_id)?.common_name || '—' : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500">Valid Until</dt>
                <dd className="font-medium text-gray-900">
                  {formatDate(activeCa.not_valid_after)} ({activeCa.days_until_expiry} days)
                </dd>
              </div>
            </dl>
          ) : (
            <div className="mt-6 rounded-lg border border-dashed border-gray-300 p-6 text-center text-sm text-gray-600">
              <p>No issuing CA is active yet. Add an intermediate to start issuing end-entity certificates.</p>
              <button
                type="button"
                onClick={() => (rootCa ? setShowIntermediateModal(true) : setShowRootModal(true))}
                className="mt-4 inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
              >
                {rootCa ? 'Add Intermediate CA' : 'Initialize Root First'}
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Hierarchy</h2>
              <p className="text-sm text-gray-500">Every CA in your chain of trust.</p>
            </div>
            <span className="text-sm text-gray-500">
              {authorities.length} {authorities.length === 1 ? 'authority' : 'authorities'}
            </span>
          </div>
        </div>
        {authorities.length > 0 ? (
          <div className="overflow-x-auto lg:overflow-visible">
            <table className="w-full table-auto divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Certificate Authority</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Valid Until</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Issued</th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {authorities.map((ca) => {
                  const deleteRestriction = getDeleteRestriction(ca)
                  const isDeletingThisCa = deleteMutation.isPending && deleteMutation.variables === ca.id
                  const deleteDisabled = Boolean(deleteRestriction) || deleteMutation.isPending

                  return (
                    <tr key={ca.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 align-top">
                        <div className="text-sm font-semibold text-gray-900 flex flex-wrap items-center gap-2">
                          {ca.common_name}
                          {ca.id === activeCa?.id && (
                            <span className="text-[11px] font-medium text-indigo-600">Issuing</span>
                          )}
                          {ca.is_root && (
                            <span className="text-[11px] font-medium text-amber-600">Root</span>
                          )}
                        </div>
                        <div className="text-xs text-gray-500 break-all">Serial: {ca.serial_number}</div>
                        <div className="text-xs text-gray-500">
                          Parent: {ca.parent_ca_id ? authorityMap.get(ca.parent_ca_id)?.common_name || 'Unknown' : '—'}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900">
                        {ca.is_root ? 'Root' : 'Intermediate'}
                        {ca.is_offline && <div className="text-xs text-gray-500">Offline</div>}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900">
                        {renderStatusBadge(ca.status, ca.is_offline, ca.id === activeCa?.id)}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900">
                        {formatDate(ca.not_valid_after)}
                        <div className={`text-xs ${ca.days_until_expiry <= 30 ? 'text-red-600' : 'text-gray-500'}`}>
                          {ca.days_until_expiry} days left
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900">
                        {ca.issued_certificates_count}
                      </td>
                      <td className="px-6 py-4 text-right text-sm font-medium align-top">
                        <div className="flex flex-wrap justify-end gap-x-3 gap-y-2 min-w-[18rem] md:min-w-[22rem]">
                          {!ca.is_root && ca.id !== activeCa?.id && (
                            <button
                              type="button"
                              onClick={() => handleSetActive(ca.id)}
                              disabled={setActiveMutation.isPending}
                              className="text-indigo-600 hover:text-indigo-900 disabled:opacity-50"
                            >
                              {setActiveMutation.isPending ? 'Updating…' : 'Make Active'}
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => handleDownloadCertificate({ caId: ca.id, includeChain: false, label: `ca-${ca.id}` })}
                            disabled={downloadTarget === `ca-${ca.id}`}
                            className="text-indigo-600 hover:text-indigo-900 disabled:opacity-50"
                          >
                            {downloadTarget === `ca-${ca.id}` ? 'Preparing…' : 'Download PEM'}
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              handleDownloadCertificate({ caId: ca.id, includeChain: true, label: `ca-${ca.id}-chain` })
                            }
                            disabled={downloadTarget === `ca-${ca.id}-chain`}
                            className="text-gray-600 hover:text-gray-900 disabled:opacity-50"
                          >
                            {downloadTarget === `ca-${ca.id}-chain` ? 'Preparing…' : 'Download Chain'}
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteAuthority(ca)}
                            disabled={deleteDisabled}
                            className="text-red-600 hover:text-red-900 disabled:opacity-50"
                            title={deleteRestriction ?? 'Delete unused intermediate'}
                          >
                            {isDeletingThisCa ? 'Removing…' : 'Delete'}
                          </button>
                        </div>
                        {deleteRestriction && (
                          <p className="mt-1 text-[11px] text-gray-500">
                            {deleteRestriction}
                          </p>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="px-6 py-12 text-center text-sm text-gray-600">
            <p>No Certificate Authorities yet. Initialize a root CA to get started.</p>
          </div>
        )}
      </div>

      {/* Root CA Modal */}
      {showRootModal && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-gray-900 bg-opacity-50 p-4 overflow-y-auto">
          <div className="w-full max-w-3xl rounded-lg bg-white shadow-xl">
            <div className="border-b px-6 py-4">
              <h3 className="text-lg font-semibold text-gray-900">Initialize Root Certificate Authority</h3>
              <p className="text-sm text-gray-500">Define your trust anchor and optionally create the first issuing CA.</p>
            </div>
            <form onSubmit={handleRootSubmit} className="px-6 py-6 space-y-6">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Root Common Name *</label>
                  <input
                    type="text"
                    value={rootForm.common_name}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, common_name: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Organization *</label>
                  <input
                    type="text"
                    value={rootForm.organization}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, organization: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Organizational Unit</label>
                  <input
                    type="text"
                    value={rootForm.organizational_unit}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, organizational_unit: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Country *</label>
                  <input
                    type="text"
                    value={rootForm.country}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, country: e.target.value.toUpperCase().slice(0, 2) }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm uppercase focus:ring-2 focus:ring-indigo-500"
                    maxLength={2}
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">State / Province</label>
                  <input
                    type="text"
                    value={rootForm.state}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, state: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">City / Locality</label>
                  <input
                    type="text"
                    value={rootForm.locality}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, locality: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Contact Email</label>
                  <input
                    type="email"
                    value={rootForm.email}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, email: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Validity (days)</label>
                    <input
                      type="number"
                      min={365}
                      max={ROOT_MAX_VALIDITY_DAYS}
                      value={rootForm.validity_days}
                      onChange={handleRootValidityDaysChange}
                      className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                    />
                    <p className="mt-1 text-xs text-gray-500">
                      Supports up to {ROOT_MAX_VALIDITY_YEARS} years ({ROOT_MAX_VALIDITY_DAYS.toLocaleString()} days).
                    </p>
                    <label className="mt-3 block text-sm font-medium text-gray-700">Quick select (years)</label>
                    <select
                      value={rootValidityPreset}
                      onChange={handleRootValidityPresetChange}
                      className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                    >
                      <option value={ROOT_CUSTOM_VALIDITY}>Custom (enter days)</option>
                      {ROOT_YEAR_OPTIONS.map((year) => (
                        <option key={year} value={year}>
                          {year} {year === 1 ? 'Year' : 'Years'} ({year * 365} days)
                        </option>
                      ))}
                    </select>
                    <p className="mt-1 text-xs text-gray-500">Preset selection will update the days field automatically.</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Key Size</label>
                    <select
                      value={rootForm.key_size}
                      onChange={(e) => setRootForm((prev) => ({ ...prev, key_size: Number(e.target.value) }))}
                      className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                    >
                      {KEY_SIZE_OPTIONS.map((size) => (
                        <option key={size} value={size}>
                          {size} bits
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-gray-200 p-4">
                <label className="flex items-center gap-2 text-sm font-medium text-gray-900">
                  <input
                    type="checkbox"
                    checked={rootForm.create_intermediate}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, create_intermediate: e.target.checked }))}
                    className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  Automatically create the first intermediate (recommended)
                </label>
                {rootForm.create_intermediate && (
                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Intermediate Common Name</label>
                      <input
                        type="text"
                        value={rootForm.intermediate_common_name}
                        onChange={(e) => setRootForm((prev) => ({ ...prev, intermediate_common_name: e.target.value }))}
                        className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Path Length Constraint</label>
                      <input
                        type="number"
                        min={0}
                        value={rootForm.path_length}
                        onChange={(e) =>
                          setRootForm((prev) => ({ ...prev, path_length: Number(e.target.value) || 0 }))
                        }
                        className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                      />
                      <p className="mt-1 text-xs text-gray-500">Controls how many child layers this intermediate can sign.</p>
                    </div>
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-gray-200 p-4">
                <label className="flex items-center gap-2 text-sm font-medium text-gray-900">
                  <input
                    type="checkbox"
                    checked={rootForm.offline_root}
                    onChange={(e) => setRootForm((prev) => ({ ...prev, offline_root: e.target.checked }))}
                    className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  Keep the root CA marked as offline
                </label>
                <p className="mt-1 text-xs text-gray-500">
                  Recommended for enhanced security—day-to-day issuance should occur through intermediates.
                </p>
              </div>

              <div className="flex justify-end gap-3 border-t border-gray-100 pt-4">
                <button
                  type="button"
                  onClick={() => setShowRootModal(false)}
                  className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={initializeMutation.isPending}
                  className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-60"
                >
                  {initializeMutation.isPending ? 'Saving…' : 'Create Root CA'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Intermediate CA Modal */}
      {showIntermediateModal && rootCa && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-gray-900 bg-opacity-50 p-4 overflow-y-auto">
          <div className="w-full max-w-2xl rounded-lg bg-white shadow-xl">
            <div className="border-b px-6 py-4">
              <h3 className="text-lg font-semibold text-gray-900">Add Intermediate Certificate Authority</h3>
              <p className="text-sm text-gray-500">Chain a new issuing CA beneath the selected parent.</p>
            </div>
            <form onSubmit={handleIntermediateSubmit} className="px-6 py-6 space-y-6">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Parent CA *</label>
                  <select
                    value={intermediateForm.parent_ca_id}
                    onChange={(e) =>
                      setIntermediateForm((prev) => ({ ...prev, parent_ca_id: Number(e.target.value) || undefined }))
                    }
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                    required
                  >
                    <option value="">Select parent</option>
                    {authorities.map((ca) => (
                      <option key={ca.id} value={ca.id}>
                        {ca.common_name}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Intermediate Common Name *</label>
                  <input
                    type="text"
                    value={intermediateForm.intermediate_common_name}
                    onChange={(e) =>
                      setIntermediateForm((prev) => ({ ...prev, intermediate_common_name: e.target.value }))
                    }
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Organization *</label>
                  <input
                    type="text"
                    value={intermediateForm.organization}
                    onChange={(e) =>
                      setIntermediateForm((prev) => ({ ...prev, organization: e.target.value }))
                    }
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Organizational Unit</label>
                  <input
                    type="text"
                    value={intermediateForm.organizational_unit}
                    onChange={(e) =>
                      setIntermediateForm((prev) => ({ ...prev, organizational_unit: e.target.value }))
                    }
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Country *</label>
                  <input
                    type="text"
                    value={intermediateForm.country}
                    onChange={(e) =>
                      setIntermediateForm((prev) => ({ ...prev, country: e.target.value.toUpperCase().slice(0, 2) }))
                    }
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm uppercase focus:ring-2 focus:ring-indigo-500"
                    maxLength={2}
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">State / Province</label>
                  <input
                    type="text"
                    value={intermediateForm.state}
                    onChange={(e) => setIntermediateForm((prev) => ({ ...prev, state: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">City / Locality</label>
                  <input
                    type="text"
                    value={intermediateForm.locality}
                    onChange={(e) => setIntermediateForm((prev) => ({ ...prev, locality: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Contact Email</label>
                  <input
                    type="email"
                    value={intermediateForm.email}
                    onChange={(e) => setIntermediateForm((prev) => ({ ...prev, email: e.target.value }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Validity (days)</label>
                  <input
                    type="number"
                    min={365}
                    max={INTERMEDIATE_MAX_VALIDITY_DAYS}
                    value={intermediateForm.validity_days}
                    onChange={handleIntermediateValidityDaysChange}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    Supports up to {INTERMEDIATE_MAX_VALIDITY_YEARS} years ({INTERMEDIATE_MAX_VALIDITY_DAYS.toLocaleString()} days).
                  </p>
                  <label className="mt-3 block text-sm font-medium text-gray-700">Quick select (years)</label>
                  <select
                    value={intermediateValidityPreset}
                    onChange={handleIntermediateValidityPresetChange}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value={INTERMEDIATE_CUSTOM_VALIDITY}>Custom (enter days)</option>
                    {INTERMEDIATE_YEAR_OPTIONS.map((year) => (
                      <option key={year} value={year}>
                        {year} {year === 1 ? 'Year' : 'Years'} ({year * 365} days)
                      </option>
                    ))}
                  </select>
                  <p className="mt-1 text-xs text-gray-500">Preset selection will update the days field automatically.</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Key Size</label>
                  <select
                    value={intermediateForm.key_size}
                    onChange={(e) => setIntermediateForm((prev) => ({ ...prev, key_size: Number(e.target.value) }))}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  >
                    {KEY_SIZE_OPTIONS.map((size) => (
                      <option key={size} value={size}>
                        {size} bits
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Path Length Constraint</label>
                  <input
                    type="number"
                    min={0}
                    value={intermediateForm.path_length}
                    onChange={(e) =>
                      setIntermediateForm((prev) => ({ ...prev, path_length: Number(e.target.value) || 0 }))
                    }
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                  />
                  <p className="mt-1 text-xs text-gray-500">Controls how many additional layers this intermediate can create.</p>
                </div>
              </div>

              <div className="flex justify-end gap-3 border-t border-gray-100 pt-4">
                <button
                  type="button"
                  onClick={() => setShowIntermediateModal(false)}
                  className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={initializeMutation.isPending}
                  className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-60"
                >
                  {initializeMutation.isPending ? 'Saving…' : 'Create Intermediate'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import Existing CA Modal */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-gray-900 bg-opacity-50 p-4 overflow-y-auto">
          <div className="w-full max-w-3xl rounded-lg bg-white shadow-xl">
            <div className="border-b px-6 py-4 flex items-start justify-between">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">
                  Import {importMode === 'root' ? 'Root' : 'Intermediate'} Certificate Authority
                </h3>
                <p className="text-sm text-gray-500">
                  Paste the PEM blocks exported from your existing CA. We encrypt and store them in Vault immediately.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowImportModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <span className="sr-only">Close</span>
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleImportSubmit} className="px-6 py-6 space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700">Certificate (PEM) *</label>
                <textarea
                  value={importForm.pem_certificate}
                  onChange={(e) => setImportForm((prev) => ({ ...prev, pem_certificate: e.target.value }))}
                  rows={8}
                  className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-indigo-500"
                  placeholder="-----BEGIN CERTIFICATE-----"
                  required
                />
              </div>

              {importMode === 'root' ? (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Private Key (optional)</label>
                    <textarea
                      value={importForm.pem_private_key}
                      onChange={(e) => setImportForm((prev) => ({ ...prev, pem_private_key: e.target.value }))}
                      rows={6}
                      className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-indigo-500"
                      placeholder="-----BEGIN PRIVATE KEY-----"
                    />
                    <p className="mt-1 text-xs text-gray-500">
                      Include the private key only if you intend to keep the root online inside this cluster.
                    </p>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Key Password</label>
                      <input
                        type="password"
                        value={importForm.private_key_password}
                        onChange={(e) => setImportForm((prev) => ({ ...prev, private_key_password: e.target.value }))}
                        className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                        placeholder="Optional"
                      />
                    </div>
                    <div className="flex items-center gap-2 pt-6">
                      <input
                        id="offline-root-toggle"
                        type="checkbox"
                        checked={importForm.offline_root}
                        onChange={(e) => setImportForm((prev) => ({ ...prev, offline_root: e.target.checked }))}
                        className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      <label htmlFor="offline-root-toggle" className="text-sm text-gray-700">
                        Treat this root as offline (recommended)
                      </label>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Parent CA *</label>
                      <select
                        value={importForm.parent_ca_id}
                        onChange={(e) =>
                          setImportForm((prev) => ({ ...prev, parent_ca_id: Number(e.target.value) || undefined }))
                        }
                        className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                        required
                      >
                        <option value="">Select parent</option>
                        {authorities.map((ca) => (
                          <option key={ca.id} value={ca.id}>
                            {ca.common_name}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="flex items-center gap-2 pt-6">
                      <input
                        id="intermediate-offline-toggle"
                        type="checkbox"
                        checked={importForm.is_offline}
                        onChange={(e) => setImportForm((prev) => ({ ...prev, is_offline: e.target.checked }))}
                        className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      <label htmlFor="intermediate-offline-toggle" className="text-sm text-gray-700">
                        Mark this intermediate as offline
                      </label>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Intermediate Private Key (PEM) *</label>
                    <textarea
                      value={importForm.pem_private_key}
                      onChange={(e) => setImportForm((prev) => ({ ...prev, pem_private_key: e.target.value }))}
                      rows={6}
                      className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-indigo-500"
                      required
                    />
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Key Password</label>
                      <input
                        type="password"
                        value={importForm.private_key_password}
                        onChange={(e) => setImportForm((prev) => ({ ...prev, private_key_password: e.target.value }))}
                        className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500"
                        placeholder="Optional"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Root Certificate (optional)</label>
                      <textarea
                        value={importForm.root_certificate_pem}
                        onChange={(e) => setImportForm((prev) => ({ ...prev, root_certificate_pem: e.target.value }))}
                        rows={4}
                        className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-indigo-500"
                        placeholder="Include the root PEM if it is not already in this cluster"
                      />
                    </div>
                  </div>
                </>
              )}

              <div className="flex justify-end gap-3 border-t border-gray-100 pt-4">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={importMutation.isPending}
                  className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-60"
                >
                  {importMutation.isPending ? 'Importing…' : 'Save CA'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default Authorities
