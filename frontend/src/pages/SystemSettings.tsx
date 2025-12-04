import React, { useState, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { systemService, SystemCertRequest, SystemHealthResponse, SystemConfigResponse, VaultInitResponse, Backup, AutoUnsealStatusResponse, SealConfigResponse, SealConfigRequest, SealProvider, KeysFileStatus, SealMigrationResponse, UnsealMethodStatus } from '../services/systemService'
import { AlertSettings } from '../types'
import LoadingSpinner from '../components/LoadingSpinner'
import { CheckCircle, XCircle, AlertTriangle, Lock, Server, Copy, Trash2, Download, Upload, RefreshCw, Save, Archive, Bell, Zap, Shield, ChevronDown, ChevronUp, TestTube, FileKey, Settings } from 'lucide-react'
import { tokenStorage } from '../utils/tokenStorage'
import { useConfirmDialog } from '../components/ConfirmDialog'

const SystemSettings: React.FC = () => {
  const { confirm } = useConfirmDialog()
  const [isLoading, setIsLoading] = useState(false)
  const queryClient = useQueryClient()
  const [healthLoading, setHealthLoading] = useState(false)
  const [healthData, setHealthData] = useState<SystemHealthResponse | null>(null)
  const [config, setConfig] = useState<SystemConfigResponse | null>(null)
  const [vaultToken, setVaultToken] = useState('')
  const [configLoading, setConfigLoading] = useState(false)
  const [initData, setInitData] = useState<VaultInitResponse | null>(null)
  const [resetLoading, setResetLoading] = useState(false)
  const [backups, setBackups] = useState<Backup[]>([])
  const [createBackupLoading, setCreateBackupLoading] = useState(false)
  const [restoreLoading, setRestoreLoading] = useState<string | null>(null) // Filename being restored
  const [showRestoreModal, setShowRestoreModal] = useState(false)
  const [restoreFilename, setRestoreFilename] = useState<string | null>(null)
  const [unsealKeys, setUnsealKeys] = useState<string[]>(['', '', ''])
  const [restoreRootToken, setRestoreRootToken] = useState('')
  const [restoreApp, setRestoreApp] = useState(true)
  const [restoreVault, setRestoreVault] = useState(true)
  const [activeTab, setActiveTab] = useState<'general' | 'vault' | 'backups' | 'alerts' | 'advanced'>('general')
  const [resetVaultConfig, setResetVaultConfig] = useState(false)
  const [configError, setConfigError] = useState<string | null>(null)
  const [alertSettings, setAlertSettings] = useState<AlertSettings | null>(null)
  const [alertSettingsLoading, setAlertSettingsLoading] = useState(false)
  const [showTestEmailModal, setShowTestEmailModal] = useState(false)
  const [testEmailRecipient, setTestEmailRecipient] = useState('')
  const [testEmailLoading, setTestEmailLoading] = useState(false)
  const [testSlackLoading, setTestSlackLoading] = useState(false)
  const [testDiscordLoading, setTestDiscordLoading] = useState(false)
  const [autoUnsealStatus, setAutoUnsealStatus] = useState<AutoUnsealStatusResponse | null>(null)
  const [autoUnsealLoading, setAutoUnsealLoading] = useState(false)
  
  // Seal Configuration State
  const [sealConfig, setSealConfig] = useState<SealConfigResponse | null>(null)
  const [sealConfigExpanded, setSealConfigExpanded] = useState(false)
  const [sealProvider, setSealProvider] = useState<SealProvider>('shamir')
  const [sealConfigLoading, setSealConfigLoading] = useState(false)
  const [sealTestLoading, setSealTestLoading] = useState(false)
  const [sealFormData, setSealFormData] = useState<Record<string, string | boolean | number>>({})
  const [migrationSteps, setMigrationSteps] = useState<string[] | null>(null)
  
  // Local Keys File State
  const [keysFileStatus, setKeysFileStatus] = useState<KeysFileStatus | null>(null)
  const [keysFileLoading, setKeysFileLoading] = useState(false)
  const [localUnsealKeys, setLocalUnsealKeys] = useState<string[]>(['', '', ''])
  
  // Seal Migration State
  const [migrationLoading, setMigrationLoading] = useState(false)
  const [migrationResult, setMigrationResult] = useState<SealMigrationResponse | null>(null)
  const [migrationUnsealKeys, setMigrationUnsealKeys] = useState<string[]>(['', '', ''])
  
  // Unseal Priority State
  const [unsealMethods, setUnsealMethods] = useState<UnsealMethodStatus[]>([])
  const [activeUnsealMethod, setActiveUnsealMethod] = useState<string | null>(null)
  const [editingProvider, setEditingProvider] = useState<string | null>(null)
  
  const { register, handleSubmit, setValue, formState: { errors } } = useForm<SystemCertRequest>({
    defaultValues: {
      common_name: window.location.hostname,
      subject_alt_names: '',
      auto_restart: false
    }
  })

  useEffect(() => {
    // Check for tab query parameter
    const params = new URLSearchParams(window.location.search)
    const tab = params.get('tab')
    if (tab && ['general', 'vault', 'backups', 'alerts', 'advanced'].includes(tab)) {
      setActiveTab(tab as any)
    }

    const init = async () => {
      await loadConfig()
      // Load other data after config to prioritize the main UI
      onCheckHealth(true)
      loadBackups()
      loadAlertSettings()
      loadSystemCertificate()
      loadSealConfig()
    }
    init()
  }, [])

  const loadSystemCertificate = async () => {
    try {
      const cert = await systemService.getSystemCertificate()
      if (cert.common_name) {
        setValue('common_name', cert.common_name)
        setValue('subject_alt_names', cert.subject_alt_names)
      }
    } catch (error) {
      console.error('Failed to load system certificate', error)
    }
  }

  const loadAlertSettings = async () => {
    try {
      const data = await systemService.getAlertSettings()
      setAlertSettings(data)
    } catch (error) {
      console.error('Failed to load alert settings', error)
    }
  }

  const handleSaveAlertSettings = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!alertSettings) return
    
    setAlertSettingsLoading(true)
    try {
      await systemService.updateAlertSettings(alertSettings)
      toast.success('Alert settings saved successfully')
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to save alert settings')
    } finally {
      setAlertSettingsLoading(false)
    }
  }

  const handleSendTestEmail = async () => {
    if (!testEmailRecipient) {
        toast.error('Please configure a To Address first')
        return
    }
    
    setTestEmailLoading(true)
    try {
        if (!alertSettings) return;

        await systemService.sendTestEmail({
          to_email: testEmailRecipient,
          smtp_settings: alertSettings
        })
        toast.success(`Test email sent to ${testEmailRecipient}`)
        setShowTestEmailModal(false)
    } catch (error: any) {
        toast.error(error.response?.data?.detail || 'Failed to send test email')
    } finally {
        setTestEmailLoading(false)
    }
  }

  const handleTestSlack = async () => {
    if (!alertSettings?.webhook_slack_url) {
        toast.error('Please enter a Slack Webhook URL')
        return
    }
    setTestSlackLoading(true)
    try {
        await systemService.sendTestSlack({ webhook_url: alertSettings.webhook_slack_url })
        toast.success('Test Slack notification sent')
    } catch (error: any) {
        toast.error(error.response?.data?.detail || 'Failed to send Slack test')
    } finally {
        setTestSlackLoading(false)
    }
  }

  const handleTestDiscord = async () => {
    if (!alertSettings?.webhook_discord_url) {
        toast.error('Please enter a Discord Webhook URL')
        return
    }
    setTestDiscordLoading(true)
    try {
        await systemService.sendTestDiscord({ webhook_url: alertSettings.webhook_discord_url })
        toast.success('Test Discord notification sent')
    } catch (error: any) {
        toast.error(error.response?.data?.detail || 'Failed to send Discord test')
    } finally {
        setTestDiscordLoading(false)
    }
  }

  const loadConfig = async (retryCount = 0) => {
    setConfigError(null)
    try {
      const data = await systemService.getSystemConfig()
      setConfig(data)
    } catch (error: any) {
      console.error('Failed to load system config', error)
      
      // If it's a network error or 5xx, retry
      if (retryCount < 2 && (!error.response || error.response.status >= 500)) {
        console.log(`Retrying config load (${retryCount + 1}/2)...`)
        setTimeout(() => loadConfig(retryCount + 1), 500 * (retryCount + 1))
        return
      }

      const msg = error.response?.data?.detail || error.message || 'Failed to load configuration'
      setConfigError(msg)
    }
  }

  const loadBackups = async () => {
    try {
      const data = await systemService.listBackups()
      setBackups(data)
    } catch (error) {
      console.error('Failed to load backups', error)
    }
  }

  const handleInitializeVault = async () => {
    const confirmed = await confirm({
      title: 'Initialize Vault',
      message: 'Are you sure you want to initialize Vault? This can only be done once on a fresh installation.',
      confirmLabel: 'Initialize',
      variant: 'warning'
    })
    if (!confirmed) {
      return
    }
    setConfigLoading(true)
    try {
      const data = await systemService.initializeVault()
      setInitData(data)
      setVaultToken(data.root_token)
      toast.success('Vault initialized successfully!')
      loadConfig()
      onCheckHealth(true)
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to initialize Vault')
    } finally {
      setConfigLoading(false)
    }
  }

  const handleUnsealVault = async () => {
    const validKeys = unsealKeys.filter(k => k.trim() !== '')
    if (validKeys.length === 0) {
        toast.error('At least one unseal key is required')
        return
    }
    
    setConfigLoading(true)
    try {
      await systemService.unsealVault(validKeys)
      toast.success('Vault unsealed successfully!')
      setUnsealKeys(['', '', ''])
      loadConfig()
      onCheckHealth(true)
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to unseal Vault')
    } finally {
      setConfigLoading(false)
    }
  }

  const loadAutoUnsealStatus = async () => {
    try {
      const status = await systemService.getAutoUnsealStatus()
      setAutoUnsealStatus(status)
    } catch (error) {
      console.error('Failed to load auto-unseal status', error)
    }
  }

  const handleAutoUnseal = async () => {
    const confirmed = await confirm({
      title: 'Auto-Unseal Vault',
      message: 'This will attempt to unseal the Vault using the stored keys. For production environments, consider using proper KMS-based auto-unseal instead. Continue?',
      confirmLabel: 'Auto-Unseal',
      variant: 'warning'
    })
    if (!confirmed) return

    setAutoUnsealLoading(true)
    try {
      const result = await systemService.autoUnsealVault()
      toast.success(result.message || 'Vault unsealed successfully!')
      loadConfig()
      onCheckHealth(true)
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Auto-unseal failed')
    } finally {
      setAutoUnsealLoading(false)
    }
  }

  // Unseal Priority Functions
  const loadUnsealPriority = async () => {
    try {
      const response = await systemService.getUnsealPriority()
      setUnsealMethods(response.methods)
      setActiveUnsealMethod(response.active_method || null)
    } catch (error) {
      console.error('Failed to load unseal priority', error)
    }
  }

  const moveMethodUp = async (index: number) => {
    if (index === 0) return
    const newMethods = [...unsealMethods]
    const temp = newMethods[index]
    newMethods[index] = newMethods[index - 1]
    newMethods[index - 1] = temp
    
    // Update priorities
    const priority = newMethods.map(m => m.method)
    try {
      await systemService.updateUnsealPriority(priority)
      setUnsealMethods(newMethods.map((m, i) => ({ ...m, priority: i })))
      toast.success('Priority updated')
    } catch (error: any) {
      toast.error('Failed to update priority')
    }
  }

  const moveMethodDown = async (index: number) => {
    if (index === unsealMethods.length - 1) return
    const newMethods = [...unsealMethods]
    const temp = newMethods[index]
    newMethods[index] = newMethods[index + 1]
    newMethods[index + 1] = temp
    
    // Update priorities
    const priority = newMethods.map(m => m.method)
    try {
      await systemService.updateUnsealPriority(priority)
      setUnsealMethods(newMethods.map((m, i) => ({ ...m, priority: i })))
      toast.success('Priority updated')
    } catch (error: any) {
      toast.error('Failed to update priority')
    }
  }

  // Seal Configuration Functions
  const loadSealConfig = async () => {
    try {
      const config = await systemService.getSealConfig()
      setSealConfig(config)
      if (config.configured && config.provider) {
        setSealProvider(config.provider as SealProvider)
        setSealFormData(config.details)
      }
      // Also load keys file status and priority when loading seal config
      loadKeysFileStatus()
      loadUnsealPriority()
    } catch (error) {
      console.error('Failed to load seal config', error)
    }
  }

  const handleSaveSealConfig = async () => {
    const confirmed = await confirm({
      title: 'Save Auto-Unseal Configuration',
      message: sealProvider === 'shamir' 
        ? 'This will disable auto-unseal. Vault will require manual unsealing after restarts.'
        : 'After saving, you must restart Vault and perform seal migration with your current unseal keys. Continue?',
      confirmLabel: 'Save Configuration',
      variant: 'warning'
    })
    if (!confirmed) return

    setSealConfigLoading(true)
    try {
      const request: SealConfigRequest = {
        provider: sealProvider,
        enabled: sealProvider !== 'shamir',
        config: sealFormData as Record<string, string | boolean | number>
      }
      const result = await systemService.saveSealConfig(request)
      toast.success(result.message)
      if (result.next_steps && result.next_steps.length > 0) {
        setMigrationSteps(result.next_steps)
      }
      loadSealConfig()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to save seal configuration')
    } finally {
      setSealConfigLoading(false)
    }
  }

  const handleTestSealConfig = async () => {
    setSealTestLoading(true)
    try {
      const request: SealConfigRequest = {
        provider: sealProvider,
        enabled: true,
        config: sealFormData as Record<string, string | boolean | number>
      }
      const result = await systemService.testSealConfig(request)
      if (result.success === true) {
        toast.success(result.message)
      } else if (result.success === false) {
        toast.error(result.message)
      } else {
        toast(result.message, { icon: 'ℹ️' })
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Test failed')
    } finally {
      setSealTestLoading(false)
    }
  }

  const handleDeleteSealConfig = async () => {
    const confirmed = await confirm({
      title: 'Remove Auto-Unseal Configuration',
      message: 'This will remove the auto-unseal configuration and revert to manual (Shamir) unsealing. Continue?',
      confirmLabel: 'Remove Configuration',
      variant: 'danger'
    })
    if (!confirmed) return

    setSealConfigLoading(true)
    try {
      const result = await systemService.deleteSealConfig()
      toast.success(result.message)
      setSealProvider('shamir')
      setSealFormData({})
      loadSealConfig()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to remove configuration')
    } finally {
      setSealConfigLoading(false)
    }
  }

  const handleStartMigration = async () => {
    // Get unseal keys from migrationUnsealKeys if provided, or try without (will use vault_keys.json)
    const validKeys = migrationUnsealKeys.filter(k => k.trim().length > 0)
    
    const confirmed = await confirm({
      title: 'Start Seal Migration',
      message: validKeys.length > 0 
        ? `This will restart Vault and migrate to the new seal configuration using ${validKeys.length} unseal keys. The system may be briefly unavailable.`
        : 'This will restart Vault and attempt migration using keys from vault_keys.json. The system may be briefly unavailable.',
      confirmLabel: 'Start Migration',
      variant: 'warning'
    })
    if (!confirmed) return

    setMigrationLoading(true)
    setMigrationResult(null)
    try {
      const result = await systemService.performSealMigration({
        action: 'start',
        unseal_keys: validKeys.length > 0 ? validKeys : undefined
      })
      setMigrationResult(result)
      if (result.success) {
        toast.success(result.message)
        // Clear migration steps since migration is complete
        setMigrationSteps(null)
        // Reload health and seal config
        onCheckHealth(false)
        loadSealConfig()
      } else {
        toast.error(result.message)
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Migration failed')
    } finally {
      setMigrationLoading(false)
    }
  }

  const updateSealFormField = (field: string, value: string | boolean) => {
    setSealFormData(prev => ({ ...prev, [field]: value }))
  }

  // Local Keys File Functions
  const loadKeysFileStatus = async () => {
    try {
      const status = await systemService.getKeysFileStatus()
      setKeysFileStatus(status)
      // If keys file exists, switch to local_file provider display
      if (status.exists && status.key_count > 0) {
        setSealProvider('local_file')
      }
    } catch (error) {
      console.error('Failed to load keys file status', error)
    }
  }

  const handleCreateKeysFile = async () => {
    const validKeys = localUnsealKeys.filter(k => k.trim().length > 0)
    if (validKeys.length < 3) {
      toast.error('At least 3 unseal keys are required')
      return
    }

    const confirmed = await confirm({
      title: 'Enable Local Auto-Unseal',
      message: 'This will store your unseal keys in a file for automatic unsealing. This is convenient but less secure than manual unsealing or KMS. Only use in dev/test environments or isolated home labs.',
      confirmLabel: 'Create Keys File',
      variant: 'warning'
    })
    if (!confirmed) return

    setKeysFileLoading(true)
    try {
      const result = await systemService.createKeysFile(validKeys)
      toast.success(result.message)
      setLocalUnsealKeys(['', '', ''])
      loadKeysFileStatus()
      loadAutoUnsealStatus()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to create keys file')
    } finally {
      setKeysFileLoading(false)
    }
  }

  const handleDeleteKeysFile = async () => {
    const confirmed = await confirm({
      title: 'Disable Local Auto-Unseal',
      message: 'This will delete vault_keys.json and disable local auto-unseal. You will need to manually unseal Vault after restarts.',
      confirmLabel: 'Delete Keys File',
      variant: 'danger'
    })
    if (!confirmed) return

    setKeysFileLoading(true)
    try {
      const result = await systemService.deleteKeysFile()
      toast.success(result.message)
      setKeysFileStatus(null)
      setSealProvider('shamir')
      loadAutoUnsealStatus()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to delete keys file')
    } finally {
      setKeysFileLoading(false)
    }
  }

  const handleCopyKeys = () => {
    if (!initData) return
    
    const text = `Root Token: ${initData.root_token}\n\nUnseal Keys:\n${initData.keys.map((k, i) => `Key ${i+1}: ${k}`).join('\n')}`
    navigator.clipboard.writeText(text)
    toast.success('Keys copied to clipboard')
  }

  const handleResetSystem = async () => {
    const confirmed = await confirm({
      title: 'Reset System',
      message: 'DANGER: This will delete ALL certificates, CAs, and monitoring data. This action cannot be undone. Are you sure?',
      confirmLabel: 'Reset System',
      variant: 'danger'
    })
    if (!confirmed) {
      return
    }
    
    const includeConfig = resetVaultConfig
    
    setResetLoading(true)
    try {
      await systemService.resetSystem(includeConfig)
      
      // Invalidate all queries to ensure fresh data across the application
      // This fixes the issue where Certificates/CAs pages show stale data after reset
      await queryClient.invalidateQueries()
      
      if (includeConfig) {
        toast.success('System reset successfully. Vault has been restarted.')
      } else {
        toast.success('System reset successfully')
      }
      
      // Clear local state
      setHealthData(null)
      if (includeConfig) {
        setInitData(null)
        setVaultToken('')
      }
      
      // Reload config to update UI state
      await loadConfig()
      // Reload health to show initialization status
      await onCheckHealth(true)
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to reset system')
    } finally {
      setResetLoading(false)
    }
  }

  const handleSaveVaultToken = async () => {
    if (!vaultToken) return
    setConfigLoading(true)
    try {
      await systemService.configureVault({ vault_token: vaultToken })
      toast.success('Vault configuration saved successfully')
      setVaultToken('')
      loadConfig()
      // Also refresh health check if we have data
      if (healthData) onCheckHealth()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to save Vault configuration')
    } finally {
      setConfigLoading(false)
    }
  }

  const onSubmit = async (data: SystemCertRequest) => {
    const confirmed = await confirm({
      title: 'Update System Certificate',
      message: 'This will overwrite the current system certificate and may require a restart of the application. Continue?',
      confirmLabel: 'Update Certificate',
      variant: 'warning'
    })
    if (!confirmed) {
      return
    }

    setIsLoading(true)
    try {
      const response = await systemService.updateSystemCertificate(data)
      toast.success(response.message, { duration: 10000 })
    } catch (error: any) {
      console.error('Failed to update system certificate:', error)
      toast.error(error.response?.data?.detail || 'Failed to update system certificate')
    } finally {
      setIsLoading(false)
    }
  }

  const onCheckHealth = async (silent = false, retryCount = 0) => {
    setHealthLoading(true)
    try {
      const data = await systemService.checkSystemHealth()
      setHealthData(data)
      
      // Load auto-unseal status if vault is sealed
      if (data.vault_sealed && data.vault_initialized) {
        loadAutoUnsealStatus()
        loadKeysFileStatus()
      }
      
      if (silent) return

      if (!data.vault_initialized) {
        toast('Vault is not initialized', { icon: '⚠️' })
      } else if (data.vault_sealed) {
        toast.error('Vault is sealed')
      } else if (!data.vault_connected) {
        toast.error('Vault is not connected')
      } else if (data.missing_keys.length > 0) {
        toast.error(`Found ${data.missing_keys.length} integrity issues!`)
      } else {
        toast.success('System health check passed!')
      }
    } catch (error: any) {
      console.error('Failed to check system health:', error)
      
      // Retry logic for health check
      if (retryCount < 2 && (!error.response || error.response.status >= 500)) {
        console.log(`Retrying health check (${retryCount + 1}/2)...`)
        setTimeout(() => onCheckHealth(silent, retryCount + 1), 500 * (retryCount + 1))
        return
      }

      if (!silent) toast.error('Failed to check system health')
    } finally {
      // Only turn off loading if we're not about to retry (approximate check)
      // Actually, simpler to just let it toggle, it's barely noticeable
      setHealthLoading(false)
    }
  }

  const handleCreateBackup = async () => {
    setCreateBackupLoading(true)
    try {
      await systemService.createBackup()
      toast.success('Backup created successfully')
      loadBackups()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to create backup')
    } finally {
      setCreateBackupLoading(false)
    }
  }

  const handleRestoreBackup = (filename: string) => {
    setRestoreFilename(filename)
    setUnsealKeys(['', '', ''])
    setRestoreRootToken('')
    setRestoreApp(true)
    setRestoreVault(true)
    setShowRestoreModal(true)
  }

  const confirmRestore = async () => {
    if (!restoreFilename) return
    
    // Filter empty keys
    const validKeys = unsealKeys.filter(k => k.trim() !== '')
    if (validKeys.length === 0) {
        toast.error('At least one unseal key is required')
        return
    }

    setRestoreLoading(restoreFilename)
    setShowRestoreModal(false)
    
    try {
      await systemService.restoreBackup(restoreFilename, {
        unseal_keys: validKeys,
        root_token: restoreRootToken || undefined,
        restore_app: restoreApp,
        restore_vault: restoreVault
      })
      
      // Invalidate all queries to ensure fresh data
      await queryClient.invalidateQueries()
      
      toast.success('System restored successfully.')
      onCheckHealth(true)
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to restore backup')
    } finally {
      setRestoreLoading(null)
      setRestoreFilename(null)
    }
  }

  const handleDeleteBackup = async (filename: string) => {
    const confirmed = await confirm({
      title: 'Delete Backup',
      message: `Are you sure you want to delete backup ${filename}?`,
      confirmLabel: 'Delete',
      variant: 'danger'
    })
    if (!confirmed) {
      return
    }
    try {
      await systemService.deleteBackup(filename)
      toast.success('Backup deleted')
      loadBackups()
    } catch (error: any) {
      toast.error('Failed to delete backup')
    }
  }

  const handleDownloadBackup = (filename: string) => {
    // Use token from cookie storage for authenticated download
    const token = tokenStorage.getAccessToken()
    if (!token) {
        toast.error('You must be logged in to download backups')
        return
    }
    
    fetch(`${import.meta.env.VITE_API_URL || '/api/v1'}/system/backups/${filename}`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => response.blob())
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
    })
    .catch(() => toast.error('Download failed'));
  }

  const handleUploadBackup = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    setCreateBackupLoading(true)
    try {
      await systemService.uploadBackup(file)
      toast.success('Backup uploaded successfully')
      loadBackups()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to upload backup')
    } finally {
      setCreateBackupLoading(false)
      // Reset input
      event.target.value = ''
    }
  }

  const handleTabChange = (tab: 'general' | 'vault' | 'backups' | 'alerts' | 'advanced') => {
    setActiveTab(tab)
    const url = new URL(window.location.href)
    url.searchParams.set('tab', tab)
    window.history.pushState({}, '', url.toString())
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-2xl font-semibold text-gray-900 mb-6">System Settings</h1>
        
        {/* Tabs */}
        <div className="border-b border-gray-200 mb-6">
          <nav className="-mb-px flex space-x-8" aria-label="Tabs">
            <button
              onClick={() => handleTabChange('general')}
              className={`${
                activeTab === 'general'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center`}
            >
              <Server className="h-4 w-4 mr-2" />
              General
            </button>
            <button
              onClick={() => handleTabChange('vault')}
              className={`${
                activeTab === 'vault'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center`}
            >
              <Lock className="h-4 w-4 mr-2" />
              Vault
            </button>
            <button
              onClick={() => handleTabChange('backups')}
              className={`${
                activeTab === 'backups'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center`}
            >
              <Archive className="h-4 w-4 mr-2" />
              Backups
            </button>
            <button
              onClick={() => handleTabChange('alerts')}
              className={`${
                activeTab === 'alerts'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center`}
            >
              <Bell className="h-4 w-4 mr-2" />
              Alerts
            </button>
            <button
              onClick={() => handleTabChange('advanced')}
              className={`${
                activeTab === 'advanced'
                  ? 'border-red-500 text-red-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center`}
            >
              <AlertTriangle className="h-4 w-4 mr-2" />
              Advanced
            </button>
          </nav>
        </div>
        
        {/* Vault Configuration Section */}
        {activeTab === 'vault' && (
        <div className="bg-white shadow overflow-hidden sm:rounded-lg mb-8">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 flex items-center">
              <Lock className="h-5 w-5 mr-2 text-gray-500" />
              Vault Configuration
            </h3>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">
              Configure connection to HashiCorp Vault.
            </p>
          </div>
          <div className="border-t border-gray-200 px-4 py-5 sm:p-6">
            {configError ? (
              <div className="rounded-md bg-red-50 p-4">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <XCircle className="h-5 w-5 text-red-400" aria-hidden="true" />
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-red-800">Error loading configuration</h3>
                    <div className="mt-2 text-sm text-red-700">
                      <p>{configError}</p>
                    </div>
                    <div className="mt-4">
                      <button
                        type="button"
                        onClick={() => loadConfig()}
                        className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-red-700 bg-red-100 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                      >
                        <RefreshCw className="h-4 w-4 mr-2" />
                        Retry
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ) : config ? (
              <div>
                <div className="flex items-center mb-4">
                  <div className={`flex-shrink-0 h-4 w-4 rounded-full ${config.vault_configured ? 'bg-green-400' : 'bg-red-400'} mr-2`}></div>
                  <span className="text-sm font-medium text-gray-900">
                    Status: {config.vault_configured ? 'Configured' : 'Not Configured'}
                  </span>
                </div>
                
                {config.vault_configured_via_env ? (
                  <div className="rounded-md bg-blue-50 p-4">
                    <div className="flex">
                      <div className="flex-shrink-0">
                        <Server className="h-5 w-5 text-blue-400" aria-hidden="true" />
                      </div>
                      <div className="ml-3">
                        <h3 className="text-sm font-medium text-blue-800">Configured via Environment</h3>
                        <div className="mt-2 text-sm text-blue-700">
                          <p>
                            Vault settings are managed via environment variables (VAULT_TOKEN). 
                            To change settings, update your deployment configuration.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="max-w-xl">
                    {/* Unseal Vault Section */}
                    {healthData && healthData.vault_initialized && healthData.vault_sealed && (
                      <div className="mb-6 bg-yellow-50 border-l-4 border-yellow-400 p-4">
                        <div className="flex">
                          <div className="flex-shrink-0">
                            <Lock className="h-5 w-5 text-yellow-400" aria-hidden="true" />
                          </div>
                          <div className="ml-3 w-full">
                            <h3 className="text-sm font-medium text-yellow-800">Vault is Sealed</h3>
                            <div className="mt-2 text-sm text-yellow-700">
                              <p>
                                The Vault is currently sealed. You must provide the unseal keys to unlock it.
                              </p>
                            </div>
                            
                            {/* Auto-Unseal Option */}
                            {autoUnsealStatus?.available && (
                              <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-md">
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center">
                                    <Zap className="h-5 w-5 text-blue-500 mr-2" />
                                    <div>
                                      <p className="text-sm font-medium text-blue-800">Auto-Unseal Available</p>
                                      <p className="text-xs text-blue-600">{autoUnsealStatus.message}</p>
                                    </div>
                                  </div>
                                  <button
                                    type="button"
                                    onClick={handleAutoUnseal}
                                    disabled={autoUnsealLoading}
                                    className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                                  >
                                    {autoUnsealLoading ? (
                                      <>
                                        <LoadingSpinner size="sm" className="mr-2" />
                                        Unsealing...
                                      </>
                                    ) : (
                                      <>
                                        <Zap className="h-4 w-4 mr-1" />
                                        Auto-Unseal
                                      </>
                                    )}
                                  </button>
                                </div>
                                <p className="mt-2 text-xs text-blue-600">
                                  ⚠️ For production, consider using KMS-based auto-unseal for better security.
                                </p>
                              </div>
                            )}

                            <div className="mt-4">
                              <label className="block text-sm font-medium text-yellow-800 mb-1">
                                {autoUnsealStatus?.available ? 'Or enter keys manually:' : 'Unseal Keys'}
                              </label>
                                {unsealKeys.map((key, idx) => (
                                  <input
                                    key={idx}
                                    type="password"
                                    className="mt-1 shadow-sm focus:ring-yellow-500 focus:border-yellow-500 block w-full sm:text-sm border-yellow-300 rounded-md mb-2"
                                    placeholder={`Unseal Key ${idx + 1}`}
                                    value={key}
                                    onChange={(e) => {
                                      const newKeys = [...unsealKeys]
                                      newKeys[idx] = e.target.value
                                      setUnsealKeys(newKeys)
                                    }}
                                  />
                                ))}
                                <button
                                    type="button"
                                    onClick={handleUnsealVault}
                                    disabled={configLoading}
                                    className="mt-2 inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-yellow-700 bg-yellow-100 hover:bg-yellow-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500"
                                >
                                    {configLoading ? 'Unsealing...' : 'Unseal Vault'}
                                </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Initialization Warning/Action */}
                    {healthData && (!healthData.vault_initialized || (!config.vault_configured && !healthData.vault_sealed)) && (
                       <div className="mb-6 bg-yellow-50 border-l-4 border-yellow-400 p-4">
                        <div className="flex">
                          <div className="flex-shrink-0">
                            <AlertTriangle className="h-5 w-5 text-yellow-400" aria-hidden="true" />
                          </div>
                          <div className="ml-3">
                            <h3 className="text-sm font-medium text-yellow-800">Vault Not Configured</h3>
                            <div className="mt-2 text-sm text-yellow-700">
                              <p>
                                {healthData.vault_initialized 
                                  ? "Vault is initialized but not configured in the system. If you have the keys, you can configure it below. If you want to start fresh, you may need to reset the system again."
                                  : "It appears this is a fresh Vault installation. You can initialize it automatically here."
                                }
                              </p>
                            </div>
                            {!healthData.vault_initialized && (
                            <div className="mt-4">
                              <button
                                type="button"
                                onClick={handleInitializeVault}
                                disabled={configLoading}
                                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-yellow-700 bg-yellow-100 hover:bg-yellow-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500"
                              >
                                {configLoading ? 'Initializing...' : 'Initialize Vault'}
                              </button>
                            </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Initialization Result Modal/Area */}
                    {initData && (
                      <div className="mb-6 bg-green-50 border border-green-200 rounded-md p-4">
                        <div className="flex justify-between items-start">
                          <h3 className="text-lg font-medium text-green-900 flex items-center">
                            <CheckCircle className="h-5 w-5 mr-2" />
                            Vault Initialized Successfully
                          </h3>
                          <button
                            type="button"
                            onClick={handleCopyKeys}
                            className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                          >
                            <Copy className="h-4 w-4 mr-1" />
                            Copy All Keys
                          </button>
                        </div>
                        <div className="mt-4">
                          <p className="text-sm text-red-600 font-bold mb-2">
                            WARNING: Save these keys immediately! They will NOT be shown again.
                            If you lose these keys, you will lose access to all your data if Vault seals.
                          </p>
                          <div className="bg-gray-800 rounded-md p-4 overflow-x-auto">
                            <div className="mb-4">
                              <span className="text-gray-400 text-xs uppercase tracking-wider">Root Token (Saved automatically)</span>
                              <div className="text-green-400 font-mono text-sm select-all">{initData.root_token}</div>
                            </div>
                            <div>
                              <span className="text-gray-400 text-xs uppercase tracking-wider">Unseal Keys (Save these!)</span>
                              {initData.keys.map((key, idx) => (
                                <div key={idx} className="text-white font-mono text-sm select-all py-1">
                                  Key {idx + 1}: {key}
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Manual Token Entry - Hide if just initialized */ }
                    {!initData && (
                      <div>
                        <label htmlFor="vault_token" className="block text-sm font-medium text-gray-700">
                          Vault Token
                        </label>
                        <div className="mt-1 flex rounded-md shadow-sm">
                          <input
                            type="password"
                            name="vault_token"
                            id="vault_token"
                            className="focus:ring-indigo-500 focus:border-indigo-500 flex-1 block w-full rounded-none rounded-l-md sm:text-sm border-gray-300"
                            placeholder="hvs.xxxxxxxxxxxxxxxxxxx"
                            value={vaultToken}
                            onChange={(e) => setVaultToken(e.target.value)}
                          />
                          <button
                            type="button"
                            onClick={handleSaveVaultToken}
                            disabled={configLoading || !vaultToken}
                            className={`inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-r-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 ${
                              (configLoading || !vaultToken) ? 'opacity-50 cursor-not-allowed' : ''
                            }`}
                          >
                            {configLoading ? 'Saving...' : 'Save Token'}
                          </button>
                        </div>
                        <p className="mt-2 text-sm text-gray-500">
                          Enter the Vault Root Token or an Access Token with appropriate permissions. 
                          This will be encrypted and stored in the database.
                        </p>
                      </div>
                    )}

                    {/* Auto-Unseal Configuration Section */}
                    <div className="mt-8 border-t border-gray-200 pt-6">
                      <button
                        type="button"
                        onClick={() => setSealConfigExpanded(!sealConfigExpanded)}
                        className="flex items-center justify-between w-full text-left"
                      >
                        <div className="flex items-center">
                          <Shield className="h-5 w-5 text-indigo-500 mr-2" />
                          <span className="text-lg font-medium text-gray-900">Auto-Unseal Configuration</span>
                          {/* Show badge based on actual active method - prioritize local keys file */}
                          {keysFileStatus?.exists && keysFileStatus.key_count > 0 ? (
                            <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                              LOCAL FILE
                            </span>
                          ) : sealConfig?.configured && sealConfig.enabled ? (
                            <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                              {sealConfig.provider.toUpperCase()}
                            </span>
                          ) : null}
                        </div>
                        {sealConfigExpanded ? (
                          <ChevronUp className="h-5 w-5 text-gray-400" />
                        ) : (
                          <ChevronDown className="h-5 w-5 text-gray-400" />
                        )}
                      </button>
                      <p className="mt-1 text-sm text-gray-500">
                        Configure automatic unsealing using KMS or Transit to avoid manual unseal on restarts.
                      </p>

                      {sealConfigExpanded && (
                        <div className="mt-4 space-y-6">
                          {/* Priority-Based Method List */}
                          <div>
                            <div className="flex items-center justify-between mb-3">
                              <h4 className="text-sm font-medium text-gray-900">Unseal Methods (Priority Order)</h4>
                              <p className="text-xs text-gray-500">First available method will be used</p>
                            </div>
                            
                            <div className="space-y-2">
                              {unsealMethods.map((method, index) => {
                                const isActive = method.method === activeUnsealMethod
                                const providerNames: Record<string, string> = {
                                  'local_file': 'Local Keys File',
                                  'transit': 'Self-Hosted Transit',
                                  'awskms': 'AWS KMS',
                                  'gcpckms': 'Google Cloud KMS',
                                  'azurekeyvault': 'Azure Key Vault',
                                  'ocikms': 'Oracle OCI KMS',
                                  'alicloudkms': 'AliCloud KMS'
                                }
                                
                                return (
                                  <div
                                    key={method.method}
                                    className={`flex items-center justify-between p-3 rounded-md border ${
                                      isActive 
                                        ? 'bg-green-50 border-green-300' 
                                        : method.configured 
                                          ? 'bg-blue-50 border-blue-200' 
                                          : 'bg-gray-50 border-gray-200'
                                    }`}
                                  >
                                    <div className="flex items-center flex-1">
                                      {/* Priority Controls */}
                                      <div className="flex flex-col mr-3">
                                        <button
                                          type="button"
                                          onClick={() => moveMethodUp(index)}
                                          disabled={index === 0}
                                          className="text-gray-400 hover:text-gray-600 disabled:opacity-30"
                                        >
                                          <ChevronUp className="h-4 w-4" />
                                        </button>
                                        <button
                                          type="button"
                                          onClick={() => moveMethodDown(index)}
                                          disabled={index === unsealMethods.length - 1}
                                          className="text-gray-400 hover:text-gray-600 disabled:opacity-30"
                                        >
                                          <ChevronDown className="h-4 w-4" />
                                        </button>
                                      </div>
                                      
                                      {/* Priority Number */}
                                      <span className="w-6 h-6 flex items-center justify-center rounded-full bg-gray-200 text-xs font-medium text-gray-600 mr-3">
                                        {index + 1}
                                      </span>
                                      
                                      {/* Method Info */}
                                      <div className="flex-1">
                                        <div className="flex items-center">
                                          <span className="text-sm font-medium text-gray-900">
                                            {providerNames[method.method] || method.method}
                                          </span>
                                          {isActive && (
                                            <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                                              ACTIVE
                                            </span>
                                          )}
                                          {method.configured && !isActive && (
                                            <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                                              READY
                                            </span>
                                          )}
                                        </div>
                                        <p className="text-xs text-gray-500">{method.details}</p>
                                      </div>
                                    </div>
                                    
                                    {/* Configure Button */}
                                    <button
                                      type="button"
                                      onClick={() => {
                                        if (method.method === 'local_file') {
                                          setSealProvider('local_file')
                                          setEditingProvider('local_file')
                                        } else {
                                          setSealProvider(method.method as SealProvider)
                                          setEditingProvider(method.method)
                                          // Load existing config for this provider
                                          systemService.getProviderConfig(method.method).then(config => {
                                            if (config.configured && config.config) {
                                              setSealFormData(config.config)
                                            } else {
                                              setSealFormData({})
                                            }
                                          })
                                        }
                                      }}
                                      className="ml-3 inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                                    >
                                      <Settings className="h-4 w-4 mr-1" />
                                      {method.configured ? 'Edit' : 'Configure'}
                                    </button>
                                  </div>
                                )
                              })}
                            </div>
                            
                            {unsealMethods.length === 0 && (
                              <p className="text-sm text-gray-500 text-center py-4">Loading unseal methods...</p>
                            )}
                          </div>

                          {/* Configuration Panel - Shows when editing a provider */}
                          {editingProvider && (
                            <div className="border-t pt-4">
                              <div className="flex items-center justify-between mb-4">
                                <h4 className="text-sm font-medium text-gray-900">
                                  Configure: {editingProvider === 'local_file' ? 'Local Keys File' : editingProvider.toUpperCase()}
                                </h4>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setEditingProvider(null)
                                    setSealFormData({})
                                  }}
                                  className="text-gray-400 hover:text-gray-600"
                                >
                                  <XCircle className="h-5 w-5" />
                                </button>
                              </div>

                          {/* Local Keys File Configuration */}
                          {editingProvider === 'local_file' && (
                            <div className="space-y-4 p-4 bg-yellow-50 border border-yellow-200 rounded-md">
                              <div className="flex items-start">
                                <FileKey className="h-5 w-5 text-yellow-600 mt-0.5 mr-2 flex-shrink-0" />
                                <div>
                                  <h4 className="text-sm font-medium text-yellow-800">Local Keys File Auto-Unseal</h4>
                                  <p className="mt-1 text-xs text-yellow-700">
                                    ⚠️ This stores unseal keys on disk. Only use in dev/test or isolated home labs with physical security.
                                  </p>
                                </div>
                              </div>
                              
                              {keysFileStatus?.exists ? (
                                <div className="space-y-3">
                                  <div className="flex items-center justify-between p-3 bg-white rounded-md border border-yellow-300">
                                    <div className="flex items-center">
                                      <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
                                      <div>
                                        <p className="text-sm font-medium text-gray-900">vault_keys.json active</p>
                                        <p className="text-xs text-gray-500">{keysFileStatus.key_count} unseal keys stored</p>
                                      </div>
                                    </div>
                                    <button
                                      type="button"
                                      onClick={handleDeleteKeysFile}
                                      disabled={keysFileLoading}
                                      className="inline-flex items-center px-3 py-1.5 border border-red-300 shadow-sm text-sm font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50"
                                    >
                                      {keysFileLoading ? <LoadingSpinner size="sm" /> : <Trash2 className="h-4 w-4 mr-1" />}
                                      Delete
                                    </button>
                                  </div>
                                  <p className="text-xs text-yellow-700">
                                    Vault will automatically unseal on restart using these stored keys.
                                  </p>
                                </div>
                              ) : (
                                <div className="space-y-3">
                                  <p className="text-sm text-gray-700">
                                    Enter your unseal keys below to create the local keys file:
                                  </p>
                                  {localUnsealKeys.map((key, idx) => (
                                    <input
                                      key={idx}
                                      type="password"
                                      placeholder={`Unseal Key ${idx + 1}`}
                                      value={key}
                                      onChange={(e) => {
                                        const newKeys = [...localUnsealKeys]
                                        newKeys[idx] = e.target.value
                                        setLocalUnsealKeys(newKeys)
                                      }}
                                      className="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                    />
                                  ))}
                                  <button
                                    type="button"
                                    onClick={() => setLocalUnsealKeys([...localUnsealKeys, ''])}
                                    className="text-sm text-indigo-600 hover:text-indigo-500"
                                  >
                                    + Add another key
                                  </button>
                                  <div className="pt-2">
                                    <button
                                      type="button"
                                      onClick={handleCreateKeysFile}
                                      disabled={keysFileLoading || localUnsealKeys.filter(k => k.trim()).length < 3}
                                      className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-yellow-600 hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 disabled:opacity-50"
                                    >
                                      {keysFileLoading ? (
                                        <LoadingSpinner size="sm" className="mr-2" />
                                      ) : (
                                        <FileKey className="h-4 w-4 mr-2" />
                                      )}
                                      Enable Local Auto-Unseal
                                    </button>
                                  </div>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Transit Configuration */}
                          {editingProvider === 'transit' && (
                            <div className="space-y-3 p-4 bg-gray-50 rounded-md">
                              <h4 className="text-sm font-medium text-gray-700">Transit Vault Settings</h4>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Vault Address</label>
                                <input
                                  type="text"
                                  placeholder="http://kms-vault:8200"
                                  value={(sealFormData.address as string) || ''}
                                  onChange={(e) => updateSealFormField('address', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Transit Token</label>
                                <input
                                  type="password"
                                  placeholder="hvs.xxxxxxxx"
                                  value={(sealFormData.token as string) || ''}
                                  onChange={(e) => updateSealFormField('token', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Key Name</label>
                                  <input
                                    type="text"
                                    placeholder="autounseal"
                                    value={(sealFormData.key_name as string) || 'autounseal'}
                                    onChange={(e) => updateSealFormField('key_name', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Mount Path</label>
                                  <input
                                    type="text"
                                    placeholder="transit"
                                    value={(sealFormData.mount_path as string) || 'transit'}
                                    onChange={(e) => updateSealFormField('mount_path', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                              </div>
                              <div className="flex items-center">
                                <input
                                  type="checkbox"
                                  id="tls_skip_verify"
                                  checked={(sealFormData.tls_skip_verify as boolean) || false}
                                  onChange={(e) => updateSealFormField('tls_skip_verify', e.target.checked)}
                                  className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                                />
                                <label htmlFor="tls_skip_verify" className="ml-2 block text-xs text-gray-600">
                                  Skip TLS Verification (not recommended for production)
                                </label>
                              </div>
                            </div>
                          )}

                          {/* AWS KMS Configuration */}
                          {editingProvider === 'awskms' && (
                            <div className="space-y-3 p-4 bg-gray-50 rounded-md">
                              <h4 className="text-sm font-medium text-gray-700">AWS KMS Settings</h4>
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Region</label>
                                  <input
                                    type="text"
                                    placeholder="us-east-1"
                                    value={(sealFormData.region as string) || ''}
                                    onChange={(e) => updateSealFormField('region', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">KMS Key ID / ARN</label>
                                  <input
                                    type="text"
                                    placeholder="arn:aws:kms:..."
                                    value={(sealFormData.kms_key_id as string) || ''}
                                    onChange={(e) => updateSealFormField('kms_key_id', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Access Key ID (optional if using IAM role)</label>
                                <input
                                  type="text"
                                  placeholder="AKIAIOSFODNN7EXAMPLE"
                                  value={(sealFormData.access_key as string) || ''}
                                  onChange={(e) => updateSealFormField('access_key', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Secret Access Key</label>
                                <input
                                  type="password"
                                  placeholder="Secret key..."
                                  value={(sealFormData.secret_key as string) || ''}
                                  onChange={(e) => updateSealFormField('secret_key', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                            </div>
                          )}

                          {/* GCP KMS Configuration */}
                          {editingProvider === 'gcpckms' && (
                            <div className="space-y-3 p-4 bg-gray-50 rounded-md">
                              <h4 className="text-sm font-medium text-gray-700">Google Cloud KMS Settings</h4>
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Project ID</label>
                                  <input
                                    type="text"
                                    placeholder="my-project"
                                    value={(sealFormData.project as string) || ''}
                                    onChange={(e) => updateSealFormField('project', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Region</label>
                                  <input
                                    type="text"
                                    placeholder="global"
                                    value={(sealFormData.region as string) || ''}
                                    onChange={(e) => updateSealFormField('region', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                              </div>
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Key Ring</label>
                                  <input
                                    type="text"
                                    placeholder="vault-keyring"
                                    value={(sealFormData.key_ring as string) || ''}
                                    onChange={(e) => updateSealFormField('key_ring', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Crypto Key</label>
                                  <input
                                    type="text"
                                    placeholder="vault-unseal-key"
                                    value={(sealFormData.crypto_key as string) || ''}
                                    onChange={(e) => updateSealFormField('crypto_key', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Service Account JSON (paste content)</label>
                                <textarea
                                  rows={3}
                                  placeholder='{"type": "service_account", ...}'
                                  value={(sealFormData.credentials_json as string) || ''}
                                  onChange={(e) => updateSealFormField('credentials_json', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm font-mono text-xs"
                                />
                              </div>
                            </div>
                          )}

                          {/* Azure Key Vault Configuration */}
                          {editingProvider === 'azurekeyvault' && (
                            <div className="space-y-3 p-4 bg-gray-50 rounded-md">
                              <h4 className="text-sm font-medium text-gray-700">Azure Key Vault Settings</h4>
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Vault Name</label>
                                  <input
                                    type="text"
                                    placeholder="my-keyvault"
                                    value={(sealFormData.vault_name as string) || ''}
                                    onChange={(e) => updateSealFormField('vault_name', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Key Name</label>
                                  <input
                                    type="text"
                                    placeholder="vault-unseal-key"
                                    value={(sealFormData.key_name as string) || ''}
                                    onChange={(e) => updateSealFormField('key_name', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Tenant ID</label>
                                <input
                                  type="text"
                                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                                  value={(sealFormData.tenant_id as string) || ''}
                                  onChange={(e) => updateSealFormField('tenant_id', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Client ID</label>
                                <input
                                  type="text"
                                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                                  value={(sealFormData.client_id as string) || ''}
                                  onChange={(e) => updateSealFormField('client_id', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Client Secret</label>
                                <input
                                  type="password"
                                  placeholder="Client secret..."
                                  value={(sealFormData.client_secret as string) || ''}
                                  onChange={(e) => updateSealFormField('client_secret', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                            </div>
                          )}

                          {/* OCI KMS Configuration */}
                          {/* OCI KMS Configuration */}
                          {editingProvider === 'ocikms' && (
                            <div className="space-y-3 p-4 bg-gray-50 rounded-md">
                              <h4 className="text-sm font-medium text-gray-700">Oracle OCI KMS Settings</h4>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Key OCID</label>
                                <input
                                  type="text"
                                  placeholder="ocid1.key.oc1.iad.xxxxx"
                                  value={(sealFormData.key_id as string) || ''}
                                  onChange={(e) => updateSealFormField('key_id', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Crypto Endpoint</label>
                                <input
                                  type="text"
                                  placeholder="https://xxxxx-crypto.kms.us-ashburn-1.oraclecloud.com"
                                  value={(sealFormData.crypto_endpoint as string) || ''}
                                  onChange={(e) => updateSealFormField('crypto_endpoint', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Management Endpoint</label>
                                <input
                                  type="text"
                                  placeholder="https://xxxxx-management.kms.us-ashburn-1.oraclecloud.com"
                                  value={(sealFormData.management_endpoint as string) || ''}
                                  onChange={(e) => updateSealFormField('management_endpoint', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div className="flex items-center">
                                <input
                                  type="checkbox"
                                  id="auth_type_api_key"
                                  checked={(sealFormData.auth_type_api_key as boolean) || false}
                                  onChange={(e) => updateSealFormField('auth_type_api_key', e.target.checked)}
                                  className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                                />
                                <label htmlFor="auth_type_api_key" className="ml-2 block text-xs text-gray-600">
                                  Use API Key Auth (instead of Instance Principal)
                                </label>
                              </div>
                            </div>
                          )}

                          {/* AliCloud KMS Configuration */}
                          {editingProvider === 'alicloudkms' && (
                            <div className="space-y-3 p-4 bg-gray-50 rounded-md">
                              <h4 className="text-sm font-medium text-gray-700">AliCloud KMS Settings</h4>
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">Region</label>
                                  <input
                                    type="text"
                                    placeholder="cn-hangzhou"
                                    value={(sealFormData.region as string) || ''}
                                    onChange={(e) => updateSealFormField('region', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs font-medium text-gray-600">KMS Key ID</label>
                                  <input
                                    type="text"
                                    placeholder="key-xxxxx"
                                    value={(sealFormData.kms_key_id as string) || ''}
                                    onChange={(e) => updateSealFormField('kms_key_id', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                  />
                                </div>
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Access Key</label>
                                <input
                                  type="text"
                                  placeholder="LTAI..."
                                  value={(sealFormData.access_key as string) || ''}
                                  onChange={(e) => updateSealFormField('access_key', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                              <div>
                                <label className="block text-xs font-medium text-gray-600">Secret Key</label>
                                <input
                                  type="password"
                                  placeholder="Secret key..."
                                  value={(sealFormData.secret_key as string) || ''}
                                  onChange={(e) => updateSealFormField('secret_key', e.target.value)}
                                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                                />
                              </div>
                            </div>
                          )}

                          {/* Shamir (Manual) Info */}
                          {editingProvider === 'shamir' && (
                            <div className="p-4 bg-gray-50 rounded-md">
                              <p className="text-sm text-gray-600">
                                With manual (Shamir) unsealing, you'll need to provide 3 of 5 unseal keys 
                                each time Vault restarts. This is the default and most secure option if 
                                you have reliable access to your unseal keys.
                              </p>
                            </div>
                          )}

                          {/* Action Buttons - Hide for local_file since it has its own buttons */}
                          {editingProvider !== 'local_file' && editingProvider !== null && (
                          <div className="flex items-center space-x-3 pt-4">
                            {editingProvider !== 'shamir' && (
                              <button
                                type="button"
                                onClick={handleTestSealConfig}
                                disabled={sealTestLoading}
                                className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                              >
                                {sealTestLoading ? (
                                  <LoadingSpinner size="sm" className="mr-2" />
                                ) : (
                                  <TestTube className="h-4 w-4 mr-2" />
                                )}
                                Test Connection
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={handleSaveSealConfig}
                              disabled={sealConfigLoading}
                              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                            >
                              {sealConfigLoading ? (
                                <LoadingSpinner size="sm" className="mr-2" />
                              ) : (
                                <Save className="h-4 w-4 mr-2" />
                              )}
                              Save Configuration
                            </button>
                            {sealConfig?.configured && sealConfig.enabled && (
                              <button
                                type="button"
                                onClick={handleDeleteSealConfig}
                                disabled={sealConfigLoading}
                                className="inline-flex items-center px-3 py-2 border border-red-300 shadow-sm text-sm font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50"
                              >
                                <Trash2 className="h-4 w-4 mr-2" />
                                Remove
                              </button>
                            )}
                          </div>
                          )}

                          {/* Migration Notice */}
                          {sealConfig?.requires_migration && (
                            <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
                              <p className="text-sm text-yellow-800">
                                ⚠️ <strong>Migration Required:</strong> {sealConfig.migration_instructions || 
                                  'Restart Vault and unseal with your current keys using the -migrate flag.'}
                              </p>
                            </div>
                          )}

                          {/* Migration Steps (after save) */}
                          {migrationSteps && migrationSteps.length > 0 && (
                            <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-md">
                              <div className="flex items-start justify-between mb-2">
                                <h4 className="text-sm font-medium text-blue-800 flex items-center">
                                  📋 Seal Migration Instructions
                                </h4>
                                <button
                                  type="button"
                                  onClick={() => setMigrationSteps(null)}
                                  className="text-blue-400 hover:text-blue-600"
                                >
                                  <XCircle className="h-4 w-4" />
                                </button>
                              </div>
                              
                              {/* Docker Automation Available */}
                              {config?.docker_available && (
                                <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded-md">
                                  <p className="text-sm text-green-800 mb-3">
                                    ✅ <strong>Docker Available:</strong> You can perform automated migration.
                                  </p>
                                  
                                  {/* Optional: provide unseal keys for migration */}
                                  <div className="mb-3">
                                    <p className="text-xs text-green-700 mb-2">
                                      Enter your Shamir unseal keys (or leave blank to use vault_keys.json):
                                    </p>
                                    <div className="space-y-2">
                                      {migrationUnsealKeys.map((key, idx) => (
                                        <input
                                          key={idx}
                                          type="password"
                                          value={key}
                                          onChange={(e) => {
                                            const newKeys = [...migrationUnsealKeys]
                                            newKeys[idx] = e.target.value
                                            setMigrationUnsealKeys(newKeys)
                                          }}
                                          placeholder={`Unseal Key ${idx + 1}`}
                                          className="w-full px-2 py-1 text-xs border rounded font-mono"
                                        />
                                      ))}
                                      <button
                                        type="button"
                                        onClick={() => setMigrationUnsealKeys([...migrationUnsealKeys, ''])}
                                        className="text-xs text-green-600 hover:text-green-800"
                                      >
                                        + Add another key
                                      </button>
                                    </div>
                                  </div>
                                  
                                  <button
                                    type="button"
                                    onClick={handleStartMigration}
                                    disabled={migrationLoading}
                                    className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 disabled:opacity-50"
                                  >
                                    {migrationLoading ? (
                                      <>
                                        <RefreshCw className="animate-spin h-4 w-4 mr-2" />
                                        Migrating...
                                      </>
                                    ) : (
                                      <>
                                        <Zap className="h-4 w-4 mr-2" />
                                        Start Automated Migration
                                      </>
                                    )}
                                  </button>
                                </div>
                              )}
                              
                              {/* Migration Result */}
                              {migrationResult && (
                                <div className={`mb-3 p-2 rounded text-sm ${migrationResult.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                  <p><strong>{migrationResult.success ? '✅' : '❌'} {migrationResult.message}</strong></p>
                                  {migrationResult.steps_completed && migrationResult.steps_completed.length > 0 && (
                                    <ul className="mt-2 text-xs list-disc list-inside">
                                      {migrationResult.steps_completed.map((step, idx) => (
                                        <li key={idx}>{step}</li>
                                      ))}
                                    </ul>
                                  )}
                                  {migrationResult.next_step && (
                                    <p className="mt-2 text-xs">Next: {migrationResult.next_step}</p>
                                  )}
                                </div>
                              )}
                              
                              {/* Manual instructions fallback */}
                              {!config?.docker_available && (
                                <p className="mb-2 text-xs text-blue-700">
                                  Docker socket not available. Follow manual steps below:
                                </p>
                              )}
                              
                              <div className="bg-gray-900 text-gray-100 rounded-md p-3 text-xs font-mono overflow-x-auto">
                                {migrationSteps.map((step, idx) => (
                                  <div key={idx} className={step === '' ? 'h-2' : 'leading-relaxed'}>
                                    {step}
                                  </div>
                                ))}
                              </div>
                              <button
                                type="button"
                                onClick={() => {
                                  navigator.clipboard.writeText(migrationSteps.join('\n'))
                                  toast.success('Instructions copied to clipboard')
                                }}
                                className="mt-2 inline-flex items-center text-xs text-blue-600 hover:text-blue-800"
                              >
                                <Copy className="h-3 w-3 mr-1" />
                                Copy to clipboard
                              </button>
                            </div>
                          )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex justify-center">
                <LoadingSpinner />
              </div>
            )}
          </div>
        </div>
        )}

        {/* System Health Section */}
        {activeTab === 'general' && (
        <>
        <div className="bg-white shadow overflow-hidden sm:rounded-lg mb-8">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              System Health & Integrity
            </h3>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">
              Verify the connection to Vault and ensure all database records have corresponding private keys.
            </p>
          </div>
          <div className="border-t border-gray-200 px-4 py-5 sm:p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="text-sm text-gray-500">
                Run this check if you suspect data synchronization issues between the Database and Vault.
              </div>
              <button
                type="button"
                onClick={() => onCheckHealth(false)}
                disabled={healthLoading}
                className={`inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 ${
                  healthLoading ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                {healthLoading ? (
                  <>
                    <LoadingSpinner size="sm" className="mr-2" />
                    Checking...
                  </>
                ) : (
                  'Run Health Check'
                )}
              </button>
            </div>

            {healthData && (
              <div className="mt-4 border rounded-md p-4 bg-gray-50">
                <dl className="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
                  <div className="sm:col-span-1">
                    <dt className="text-sm font-medium text-gray-500">Database Connection</dt>
                    <dd className="mt-1 text-sm text-gray-900 flex items-center">
                      {healthData.database_connected ? (
                        <><CheckCircle className="h-5 w-5 text-green-500 mr-2" /> Connected</>
                      ) : (
                        <><XCircle className="h-5 w-5 text-red-500 mr-2" /> Disconnected</>
                      )}
                    </dd>
                  </div>
                  <div className="sm:col-span-1">
                    <dt className="text-sm font-medium text-gray-500">Vault Connection</dt>
                    <dd className="mt-1 text-sm text-gray-900 flex items-center">
                      {healthData.vault_connected ? (
                        <><CheckCircle className="h-5 w-5 text-green-500 mr-2" /> Connected</>
                      ) : (
                        <><XCircle className="h-5 w-5 text-red-500 mr-2" /> Disconnected</>
                      )}
                    </dd>
                  </div>
                  <div className="sm:col-span-1">
                    <dt className="text-sm font-medium text-gray-500">Vault Status</dt>
                    <dd className="mt-1 text-sm text-gray-900 flex items-center">
                      {!healthData.vault_initialized ? (
                        <><AlertTriangle className="h-5 w-5 text-yellow-500 mr-2" /> Not Initialized</>
                      ) : healthData.vault_sealed ? (
                        <><AlertTriangle className="h-5 w-5 text-yellow-500 mr-2" /> Sealed</>
                      ) : (
                        <><CheckCircle className="h-5 w-5 text-green-500 mr-2" /> Unsealed</>
                      )}
                    </dd>
                  </div>
                  <div className="sm:col-span-1">
                    <dt className="text-sm font-medium text-gray-500">Total Records</dt>
                    <dd className="mt-1 text-sm text-gray-900">
                      {healthData.total_cas} CAs, {healthData.total_certificates} Certificates
                    </dd>
                  </div>
                  
                  <div className="sm:col-span-2">
                    <dt className="text-sm font-medium text-gray-500">Key Integrity (Database &rarr; Vault)</dt>
                    <dd className="mt-1 text-sm text-gray-900">
                      {!healthData.vault_connected || !healthData.vault_initialized || healthData.vault_sealed ? (
                        <div className="flex items-center text-yellow-700">
                          <AlertTriangle className="h-5 w-5 mr-2" />
                          Cannot verify: Vault unavailable.
                        </div>
                      ) : healthData.missing_keys.length === 0 ? (
                        <div className="flex items-center text-green-700">
                          <CheckCircle className="h-5 w-5 mr-2" />
                          All database records have corresponding keys in Vault.
                        </div>
                      ) : (
                        <div className="bg-red-50 p-3 rounded-md">
                          <div className="flex items-center text-red-700 mb-2">
                            <XCircle className="h-5 w-5 mr-2" />
                            Found {healthData.missing_keys.length} missing keys:
                          </div>
                          <ul className="list-disc list-inside text-sm text-red-600 max-h-40 overflow-y-auto">
                            {healthData.missing_keys.map((key, idx) => (
                              <li key={idx}>{key}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </dd>
                  </div>

                  <div className="sm:col-span-2">
                    <dt className="text-sm font-medium text-gray-500">Orphaned Keys (Vault &rarr; Database)</dt>
                    <dd className="mt-1 text-sm text-gray-900">
                      {!healthData.vault_connected || !healthData.vault_initialized || healthData.vault_sealed ? (
                        <div className="flex items-center text-yellow-700">
                          <AlertTriangle className="h-5 w-5 mr-2" />
                          Cannot verify: Vault unavailable.
                        </div>
                      ) : !healthData.orphaned_keys || healthData.orphaned_keys.length === 0 ? (
                        <div className="flex items-center text-green-700">
                          <CheckCircle className="h-5 w-5 mr-2" />
                          No orphaned keys found in Vault.
                        </div>
                      ) : (
                        <div className="bg-yellow-50 p-3 rounded-md">
                          <div className="flex items-center text-yellow-700 mb-2">
                            <AlertTriangle className="h-5 w-5 mr-2" />
                            Found {healthData.orphaned_keys.length} orphaned keys:
                          </div>
                          <ul className="list-disc list-inside text-sm text-yellow-600 max-h-40 overflow-y-auto">
                            {healthData.orphaned_keys.map((key, idx) => (
                              <li key={idx}>{key}</li>
                            ))}
                          </ul>
                          <p className="mt-2 text-xs text-yellow-600">
                            These keys exist in Vault but are not linked to any record in the database.
                          </p>
                        </div>
                      )}
                    </dd>
                  </div>
                </dl>
              </div>
            )}
          </div>
        </div>

        <div className="bg-white shadow overflow-hidden sm:rounded-lg">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              System Certificate
            </h3>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">
              Update the SSL certificate used by the PKI Management Interface.
              This will issue a new certificate from your internal CA.
            </p>
          </div>
          <div className="border-t border-gray-200 px-4 py-5 sm:p-6">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6 max-w-lg">
              <div>
                <label htmlFor="common_name" className="block text-sm font-medium text-gray-700">
                  Common Name (FQDN)
                </label>
                <div className="mt-1">
                  <input
                    type="text"
                    id="common_name"
                    className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                    placeholder="pki.example.com"
                    {...register('common_name', { required: 'Common Name is required' })}
                  />
                  {errors.common_name && (
                    <p className="mt-1 text-sm text-red-600">{errors.common_name.message}</p>
                  )}
                </div>
                <p className="mt-2 text-sm text-gray-500">
                  The domain name you use to access this interface.
                </p>
              </div>

              <div>
                <label htmlFor="subject_alt_names" className="block text-sm font-medium text-gray-700">
                  Subject Alternative Names (SANs)
                </label>
                <div className="mt-1">
                  <input
                    type="text"
                    id="subject_alt_names"
                    className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                    placeholder="192.168.1.100, pki.local, localhost"
                    {...register('subject_alt_names')}
                  />
                  {errors.subject_alt_names && (
                    <p className="mt-1 text-sm text-red-600">{errors.subject_alt_names.message}</p>
                  )}
                </div>
                <p className="mt-2 text-sm text-gray-500">
                  Comma-separated list of additional hostnames or IP addresses (e.g., static IP, localhost, shortname).
                </p>
              </div>

              <div className="flex items-start">
                <div className="flex items-center h-5">
                  <input
                    id="auto_restart"
                    type="checkbox"
                    className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                    {...register('auto_restart')}
                  />
                </div>
                <div className="ml-3 text-sm">
                  <label htmlFor="auto_restart" className="font-medium text-gray-700">Auto-restart Nginx</label>
                  <p className="text-gray-500">Automatically restart the Nginx container to apply the new certificate immediately.</p>
                </div>
              </div>

              <div className="flex items-center justify-end">
                <button
                  type="submit"
                  disabled={isLoading}
                  className={`inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 ${
                    isLoading ? 'opacity-50 cursor-not-allowed' : ''
                  }`}
                >
                  {isLoading ? (
                    <>
                      <LoadingSpinner size="sm" className="mr-2" />
                      Updating...
                    </>
                  ) : (
                    'Update Certificate'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
        </>
        )}

        {/* Backup & Restore Section */}
      {activeTab === 'backups' && (
      <div className="bg-white shadow sm:rounded-lg mb-8">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 flex items-center">
            <Archive className="h-5 w-5 mr-2 text-blue-500" />
            Backup & Restore
          </h3>
          <div className="mt-2 max-w-xl text-sm text-gray-500">
            <p>Manage system backups. Backups include the database (Users, Certificates, Vault Data) and configuration.</p>
            <p className="mt-1 font-medium text-yellow-600">
              <AlertTriangle className="inline h-4 w-4 mr-1" />
              Note: Backups contain encrypted Vault data. To restore, you MUST have the Unseal Keys that were valid at the time of backup.
            </p>
          </div>
          
          <div className="mt-5 flex items-center space-x-4">
            <button
              type="button"
              onClick={handleCreateBackup}
              disabled={createBackupLoading}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
            >
              {createBackupLoading ? <LoadingSpinner size="sm" /> : <Save className="h-4 w-4 mr-2" />}
              Create New Backup
            </button>
            
            <div className="relative">
                <input
                    type="file"
                    accept=".tar.gz"
                    onChange={handleUploadBackup}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    disabled={createBackupLoading}
                />
                <button
                    type="button"
                    className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                    <Upload className="h-4 w-4 mr-2" />
                    Upload Backup
                </button>
            </div>
          </div>

          {/* Backup List */}
          <div className="mt-6 flex flex-col">
            <div className="-my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
              <div className="py-2 align-middle inline-block min-w-full sm:px-6 lg:px-8">
                <div className="shadow overflow-hidden border-b border-gray-200 sm:rounded-lg">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Filename
                        </th>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Date
                        </th>
                        <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Size
                        </th>
                        <th scope="col" className="relative px-6 py-3">
                          <span className="sr-only">Actions</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {backups.length === 0 ? (
                        <tr>
                            <td colSpan={4} className="px-6 py-4 text-center text-sm text-gray-500">
                                No backups found.
                            </td>
                        </tr>
                      ) : (
                        backups.map((backup) => (
                        <tr key={backup.filename}>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                            {backup.filename}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(backup.created_at).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {(backup.size / 1024 / 1024).toFixed(2)} MB
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-3">
                            <button
                              onClick={() => handleDownloadBackup(backup.filename)}
                              className="text-blue-600 hover:text-blue-900"
                              title="Download"
                            >
                              <Download className="h-4 w-4" />
                            </button>
                            <button
                              onClick={() => handleRestoreBackup(backup.filename)}
                              className="text-green-600 hover:text-green-900"
                              title="Restore"
                              disabled={!!restoreLoading}
                            >
                              {restoreLoading === backup.filename ? (
                                <LoadingSpinner size="sm" />
                              ) : (
                                <RefreshCw className="h-4 w-4" />
                              )}
                            </button>
                            <button
                              onClick={() => handleDeleteBackup(backup.filename)}
                              className="text-red-600 hover:text-red-900"
                              title="Delete"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </td>
                        </tr>
                      )))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      )}

      {/* Alerts Settings Section */}
      {activeTab === 'alerts' && (
        <div className="bg-white shadow overflow-hidden sm:rounded-lg mb-8">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              Alert Settings
            </h3>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">
              Configure system alert settings. Alerts can be sent via Email, Slack, or Discord.
            </p>
          </div>
          <div className="border-t border-gray-200 px-4 py-5 sm:p-6">
            <form onSubmit={handleSaveAlertSettings} className="space-y-6">
              
              {/* SMTP Settings */}
              <div className="border-b border-gray-200 pb-6">
                <h4 className="text-md font-medium text-gray-900 mb-4">Email (SMTP)</h4>
                <div className="flex items-start mb-4">
                  <div className="flex items-center h-5">
                    <input
                      id="smtp_enabled"
                      name="smtp_enabled"
                      type="checkbox"
                      checked={alertSettings?.smtp_enabled || false}
                      onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, smtp_enabled: e.target.checked }) : null)}
                      className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                    />
                  </div>
                  <div className="ml-3 text-sm">
                    <label htmlFor="smtp_enabled" className="font-medium text-gray-700">Enable Email Alerts</label>
                    <p className="text-gray-500">Send notifications via SMTP server.</p>
                  </div>
                </div>

                {alertSettings?.smtp_enabled && (
                  <div className="grid grid-cols-1 gap-y-6 gap-x-4 sm:grid-cols-6">
                    <div className="sm:col-span-4">
                      <label htmlFor="smtp_host" className="block text-sm font-medium text-gray-700">SMTP Host</label>
                      <div className="mt-1">
                        <input
                          type="text"
                          id="smtp_host"
                          value={alertSettings.smtp_host || ''}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, smtp_host: e.target.value }) : null)}
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                        />
                      </div>
                    </div>

                    <div className="sm:col-span-2">
                      <label htmlFor="smtp_port" className="block text-sm font-medium text-gray-700">Port</label>
                      <div className="mt-1">
                        <input
                          type="number"
                          id="smtp_port"
                          value={alertSettings.smtp_port || 587}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, smtp_port: parseInt(e.target.value) }) : null)}
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                        />
                      </div>
                    </div>

                    <div className="sm:col-span-3">
                      <label htmlFor="smtp_username" className="block text-sm font-medium text-gray-700">Username</label>
                      <div className="mt-1">
                        <input
                          type="text"
                          id="smtp_username"
                          value={alertSettings.smtp_username || ''}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, smtp_username: e.target.value }) : null)}
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                        />
                      </div>
                    </div>

                    <div className="sm:col-span-3">
                      <label htmlFor="smtp_password" className="block text-sm font-medium text-gray-700">Password</label>
                      <div className="mt-1">
                        <input
                          type="password"
                          id="smtp_password"
                          value={alertSettings.smtp_password || ''}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, smtp_password: e.target.value }) : null)}
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                        />
                      </div>
                    </div>

                    <div className="sm:col-span-3">
                      <label htmlFor="alert_email_from" className="block text-sm font-medium text-gray-700">From Address</label>
                      <div className="mt-1">
                        <input
                          type="email"
                          id="alert_email_from"
                          value={alertSettings.alert_email_from || ''}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, alert_email_from: e.target.value }) : null)}
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                        />
                      </div>
                    </div>

                    <div className="sm:col-span-3">
                      <label htmlFor="alert_email_to" className="block text-sm font-medium text-gray-700">To Address</label>
                      <div className="mt-1">
                        <input
                          type="email"
                          id="alert_email_to"
                          value={alertSettings.alert_email_to || ''}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, alert_email_to: e.target.value }) : null)}
                          className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                        />
                      </div>
                    </div>

                    <div className="sm:col-span-6 flex justify-between items-center">
                      <div className="flex items-start">
                        <div className="flex items-center h-5">
                          <input
                            id="smtp_use_tls"
                            name="smtp_use_tls"
                            type="checkbox"
                            checked={alertSettings.smtp_use_tls !== false}
                            onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, smtp_use_tls: e.target.checked }) : null)}
                            className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                          />
                        </div>
                        <div className="ml-3 text-sm">
                          <label htmlFor="smtp_use_tls" className="font-medium text-gray-700">Use TLS</label>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => {
                            setTestEmailRecipient(alertSettings.alert_email_to || '')
                            setShowTestEmailModal(true)
                        }}
                        className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                      >
                        <span className="mr-2">📧</span> Test Email
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Slack Settings */}
              <div className="border-b border-gray-200 pb-6">
                <h4 className="text-md font-medium text-gray-900 mb-4">Slack</h4>
                <div className="flex items-start mb-4">
                  <div className="flex items-center h-5">
                    <input
                      id="webhook_slack_enabled"
                      name="webhook_slack_enabled"
                      type="checkbox"
                      checked={alertSettings?.webhook_slack_enabled || false}
                      onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, webhook_slack_enabled: e.target.checked }) : null)}
                      className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                    />
                  </div>
                  <div className="ml-3 text-sm">
                    <label htmlFor="webhook_slack_enabled" className="font-medium text-gray-700">Enable Slack Alerts</label>
                  </div>
                </div>

                {alertSettings?.webhook_slack_enabled && (
                  <div>
                    <label htmlFor="webhook_slack_url" className="block text-sm font-medium text-gray-700">Webhook URL</label>
                    <div className="mt-1 flex rounded-md shadow-sm">
                      <input
                        type="text"
                        id="webhook_slack_url"
                        value={alertSettings.webhook_slack_url || ''}
                        onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, webhook_slack_url: e.target.value }) : null)}
                        placeholder="https://hooks.slack.com/services/..."
                        className="focus:ring-indigo-500 focus:border-indigo-500 flex-1 block w-full rounded-none rounded-l-md sm:text-sm border-gray-300"
                      />
                      <button
                        type="button"
                        onClick={handleTestSlack}
                        disabled={testSlackLoading || !alertSettings.webhook_slack_url}
                        className="inline-flex items-center px-3 py-2 border border-l-0 border-gray-300 rounded-r-md bg-gray-50 text-gray-500 text-sm hover:bg-gray-100 focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
                      >
                        {testSlackLoading ? 'Testing...' : 'Test'}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Discord Settings */}
              <div className="pb-6">
                <h4 className="text-md font-medium text-gray-900 mb-4">Discord</h4>
                <div className="flex items-start mb-4">
                  <div className="flex items-center h-5">
                    <input
                      id="webhook_discord_enabled"
                      name="webhook_discord_enabled"
                      type="checkbox"
                      checked={alertSettings?.webhook_discord_enabled || false}
                      onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, webhook_discord_enabled: e.target.checked }) : null)}
                      className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                    />
                  </div>
                  <div className="ml-3 text-sm">
                    <label htmlFor="webhook_discord_enabled" className="font-medium text-gray-700">Enable Discord Alerts</label>
                  </div>
                </div>

                {alertSettings?.webhook_discord_enabled && (
                  <div>
                    <label htmlFor="webhook_discord_url" className="block text-sm font-medium text-gray-700">Webhook URL</label>
                    <div className="mt-1 flex rounded-md shadow-sm">
                      <input
                        type="text"
                        id="webhook_discord_url"
                        value={alertSettings.webhook_discord_url || ''}
                        onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, webhook_discord_url: e.target.value }) : null)}
                        placeholder="https://discord.com/api/webhooks/..."
                        className="focus:ring-indigo-500 focus:border-indigo-500 flex-1 block w-full rounded-none rounded-l-md sm:text-sm border-gray-300"
                      />
                      <button
                        type="button"
                        onClick={handleTestDiscord}
                        disabled={testDiscordLoading || !alertSettings.webhook_discord_url}
                        className="inline-flex items-center px-3 py-2 border border-l-0 border-gray-300 rounded-r-md bg-gray-50 text-gray-500 text-sm hover:bg-gray-100 focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
                      >
                        {testDiscordLoading ? 'Testing...' : 'Test'}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* General Alert Settings */}
              <div className="border-b border-gray-200 pb-6">
                <h4 className="text-md font-medium text-gray-900 mb-4">General</h4>
                <div>
                  <label htmlFor="alert_days_before_expiry" className="block text-sm font-medium text-gray-700">
                    Alert Threshold (Days)
                  </label>
                  <div className="mt-1">
                    <input
                      type="number"
                      id="alert_days_before_expiry"
                      className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                      placeholder="30"
                      value={alertSettings?.alert_days_before_expiry || 30}
                      onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, alert_days_before_expiry: parseInt(e.target.value) }) : null)}
                    />
                  </div>
                  <p className="mt-2 text-sm text-gray-500">
                    Certificates expiring within this many days will trigger a "Yellow" warning.
                  </p>
                </div>

                <div className="mt-6">
                  <h5 className="text-sm font-medium text-gray-900 mb-2">Alert Recipients</h5>
                  <div className="space-y-2">
                    <div className="flex items-start">
                      <div className="flex items-center h-5">
                        <input
                          id="alert_recipient_owner"
                          name="alert_recipient_owner"
                          type="checkbox"
                          checked={alertSettings?.alert_recipient_owner !== false}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, alert_recipient_owner: e.target.checked }) : null)}
                          className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                        />
                      </div>
                      <div className="ml-3 text-sm">
                        <label htmlFor="alert_recipient_owner" className="font-medium text-gray-700">Certificate Owners</label>
                        <p className="text-gray-500">Send alerts to the user who owns the certificate.</p>
                      </div>
                    </div>

                    <div className="flex items-start">
                      <div className="flex items-center h-5">
                        <input
                          id="alert_recipient_admins"
                          name="alert_recipient_admins"
                          type="checkbox"
                          checked={alertSettings?.alert_recipient_admins !== false}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, alert_recipient_admins: e.target.checked }) : null)}
                          className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                        />
                      </div>
                      <div className="ml-3 text-sm">
                        <label htmlFor="alert_recipient_admins" className="font-medium text-gray-700">System Administrators</label>
                        <p className="text-gray-500">Send alerts to all users with Admin role.</p>
                      </div>
                    </div>

                    <div className="flex items-start">
                      <div className="flex items-center h-5">
                        <input
                          id="alert_recipient_global"
                          name="alert_recipient_global"
                          type="checkbox"
                          checked={alertSettings?.alert_recipient_global || false}
                          onChange={(e) => setAlertSettings(prev => prev ? ({ ...prev, alert_recipient_global: e.target.checked }) : null)}
                          className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                        />
                      </div>
                      <div className="ml-3 text-sm">
                        <label htmlFor="alert_recipient_global" className="font-medium text-gray-700">Global Alert Email</label>
                        <p className="text-gray-500">Send alerts to the "To Address" configured in SMTP settings.</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-end">
                <button
                  type="submit"
                  disabled={alertSettingsLoading}
                  className={`inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 ${
                    alertSettingsLoading ? 'opacity-50 cursor-not-allowed' : ''
                  }`}
                >
                  {alertSettingsLoading ? (
                    <>
                      <LoadingSpinner size="sm" className="mr-2" />
                      Saving...
                    </>
                  ) : (
                    'Save Settings'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Danger Zone */}
        {activeTab === 'advanced' && (
        <div className="mt-8 bg-white shadow overflow-hidden sm:rounded-lg border border-red-200">
          <div className="px-4 py-5 sm:px-6 bg-red-50">
            <h3 className="text-lg leading-6 font-medium text-red-800 flex items-center">
              <AlertTriangle className="h-5 w-5 mr-2" />
              Danger Zone
            </h3>
            <p className="mt-1 max-w-2xl text-sm text-red-600">
              Destructive actions that cannot be undone.
            </p>
          </div>
          <div className="border-t border-red-200 px-4 py-5 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-gray-900">Reset System Data</h3>
                <p className="mt-1 text-sm text-gray-500">
                  Permanently delete all Certificates, Certificate Authorities, and Monitoring data.
                  <br />
                  This will also remove all keys from Vault. Only the Superuser account will be preserved.
                </p>
                <div className="mt-4 flex items-center">
                  <input
                    id="reset-vault-config"
                    name="reset-vault-config"
                    type="checkbox"
                    checked={resetVaultConfig}
                    onChange={(e) => setResetVaultConfig(e.target.checked)}
                    disabled={!config?.docker_available}
                    className={`h-4 w-4 text-red-600 focus:ring-red-500 border-gray-300 rounded ${!config?.docker_available ? 'opacity-50 cursor-not-allowed' : ''}`}
                  />
                  <label htmlFor="reset-vault-config" className={`ml-2 block text-sm ${!config?.docker_available ? 'text-gray-400' : 'text-gray-900'}`}>
                    Reset Vault Configuration (Disconnect & Restart Vault)
                  </label>
                </div>
                <p className="mt-1 text-xs text-gray-500 ml-6">
                  Check this if you want to re-initialize Vault from scratch.
                  {!config?.docker_available && (
                    <span className="block text-yellow-600 mt-1">
                      <AlertTriangle className="inline h-3 w-3 mr-1" />
                      Disabled: Docker socket not available. The backend cannot restart the Vault container.
                    </span>
                  )}
                </p>
              </div>
              <button
                type="button"
                onClick={handleResetSystem}
                disabled={resetLoading}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50"
              >
                {resetLoading ? (
                  <LoadingSpinner size="sm" className="mr-2" />
                ) : (
                  <Trash2 className="h-4 w-4 mr-2" />
                )}
                {resetLoading ? 'Resetting...' : 'Reset System'}
              </button>
            </div>
          </div>
        </div>
        )}
      </div>

      {/* Restore Modal */}
      {showRestoreModal && (
        <div className="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
          <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true" onClick={() => setShowRestoreModal(false)}></div>

            <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>

            <div className="inline-block align-bottom bg-white rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div>
                <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100">
                  <RefreshCw className="h-6 w-6 text-blue-600" aria-hidden="true" />
                </div>
                <div className="mt-3 text-center sm:mt-5">
                  <h3 className="text-lg leading-6 font-medium text-gray-900" id="modal-title">
                    Restore System Backup
                  </h3>
                  <div className="mt-2">
                    <p className="text-sm text-gray-500">
                      You are about to restore <strong>{restoreFilename}</strong>.
                      This will overwrite all current data.
                    </p>
                    <p className="mt-2 text-sm text-yellow-600 bg-yellow-50 p-2 rounded border border-yellow-200">
                      <AlertTriangle className="inline h-4 w-4 mr-1" />
                      <strong>Required:</strong> You must provide the Unseal Keys that were valid when this backup was created.
                    </p>
                  </div>
                  
                  <div className="mt-4 text-left">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Unseal Keys</label>
                    {unsealKeys.map((key, idx) => (
                      <input
                        key={idx}
                        type="password"
                        className="mt-1 shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                        placeholder={`Unseal Key ${idx + 1}`}
                        value={key}
                        onChange={(e) => {
                          const newKeys = [...unsealKeys]
                          newKeys[idx] = e.target.value
                          setUnsealKeys(newKeys)
                        }}
                      />
                    ))}
                    <p className="text-xs text-gray-500 mt-1">Enter at least one valid key (usually 3 are required).</p>
                  </div>

                  <div className="mt-4 text-left">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Root Token (Optional)</label>
                    <input
                      type="password"
                      className="mt-1 shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md"
                      placeholder="hvs.xxxxxxxx (Optional)"
                      value={restoreRootToken}
                      onChange={(e) => setRestoreRootToken(e.target.value)}
                    />
                    <p className="text-xs text-gray-500 mt-1">If provided, this will be saved as the system Vault token.</p>
                  </div>

                  <div className="mt-4 text-left border-t pt-4">
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Restore Options</h4>
                    <div className="flex items-start mb-2">
                      <div className="flex items-center h-5">
                        <input
                          id="restore_app"
                          name="restore_app"
                          type="checkbox"
                          checked={restoreApp}
                          onChange={(e) => setRestoreApp(e.target.checked)}
                          className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                        />
                      </div>
                      <div className="ml-3 text-sm">
                        <label htmlFor="restore_app" className="font-medium text-gray-700">Restore Application Data</label>
                        <p className="text-gray-500">Restores Users, Certificate Metadata, and Monitoring settings.</p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="flex items-center h-5">
                        <input
                          id="restore_vault"
                          name="restore_vault"
                          type="checkbox"
                          checked={restoreVault}
                          onChange={(e) => setRestoreVault(e.target.checked)}
                          className="focus:ring-indigo-500 h-4 w-4 text-indigo-600 border-gray-300 rounded"
                        />
                      </div>
                      <div className="ml-3 text-sm">
                        <label htmlFor="restore_vault" className="font-medium text-gray-700">Restore Vault Data</label>
                        <p className="text-gray-500">Restores encrypted keys and secrets. Requires Vault restart.</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="mt-5 sm:mt-6 sm:grid sm:grid-cols-2 sm:gap-3 sm:grid-flow-row-dense">
                <button
                  type="button"
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:col-start-2 sm:text-sm"
                  onClick={confirmRestore}
                >
                  Restore Backup
                </button>
                <button
                  type="button"
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:col-start-1 sm:text-sm"
                  onClick={() => setShowRestoreModal(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Test Email Modal */}
      {showTestEmailModal && (
        <div className="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
          <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true" onClick={() => setShowTestEmailModal(false)}></div>
            <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
            <div className="inline-block align-bottom bg-white rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div>
                <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-indigo-100">
                  <Bell className="h-6 w-6 text-indigo-600" aria-hidden="true" />
                </div>
                <div className="mt-3 text-center sm:mt-5">
                  <h3 className="text-lg leading-6 font-medium text-gray-900" id="modal-title">
                    Send Test Email
                  </h3>
                  <div className="mt-2">
                    <p className="text-sm text-gray-500">
                      Send a test email to verify the SMTP configuration.
                      This will use the current settings in the form (even if not saved).
                    </p>
                    <div className="mt-4 bg-gray-50 p-3 rounded-md text-left">
                        <p className="text-sm text-gray-700">
                            <span className="font-medium">Recipient:</span> {testEmailRecipient || <span className="text-red-500 italic">Not configured</span>}
                        </p>
                        {!testEmailRecipient && (
                            <p className="mt-1 text-xs text-red-500">
                                Please enter a "To Address" in the settings above.
                            </p>
                        )}
                    </div>
                  </div>
                </div>
              </div>
              <div className="mt-5 sm:mt-6 sm:grid sm:grid-cols-2 sm:gap-3 sm:grid-flow-row-dense">
                <button
                  type="button"
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-indigo-600 text-base font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:col-start-2 sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  onClick={handleSendTestEmail}
                  disabled={testEmailLoading || !testEmailRecipient}
                >
                  {testEmailLoading ? 'Sending...' : 'Send Test Email'}
                </button>
                <button
                  type="button"
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:col-start-1 sm:text-sm"
                  onClick={() => setShowTestEmailModal(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default SystemSettings
