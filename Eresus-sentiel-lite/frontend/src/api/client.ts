import axios from 'axios'
import type {
  Stats, ScannerInfo, HealthInfo, ScanEntry, ArtifactEntry,
  PathScanResult, DoctorResult, EvalResult, PluginRegistry, PolicyInfo,
} from '../types'

const api = axios.create({ baseURL: '/api' })

// Sync auth token from global axios defaults (set by AuthContext)
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinel_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export async function fetchStats(): Promise<Stats> {
  const { data } = await api.get<Stats>('/stats')
  return data
}

export async function fetchScanners(): Promise<ScannerInfo> {
  const { data } = await api.get<ScannerInfo>('/scanners')
  return data
}

export async function fetchHealth(): Promise<HealthInfo> {
  const { data } = await api.get<HealthInfo>('/health')
  return data
}

export async function scanFirewall(prompt: string, type: 'input' | 'output'): Promise<ScanEntry> {
  const { data } = await api.post<ScanEntry>('/firewall/scan', { prompt, scan_type: type })
  return data
}

export async function scanArtifact(file: File): Promise<ArtifactEntry> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post<ArtifactEntry>('/artifacts/scan', form)
  return data
}

export async function fetchHistory(): Promise<{ scans: ScanEntry[]; artifacts: ArtifactEntry[] }> {
  const { data } = await api.get('/history')
  return data
}

// ── New parity endpoints ──────────────────────────────────────

export async function scanSast(path: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/sast/scan', { path })
  return data
}

export async function scanAgent(path: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/agent/scan', { path })
  return data
}

export async function scanSupplyChain(path: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/supply-chain/scan', { path })
  return data
}

export async function scanDiff(target: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/diff/scan', { target })
  return data
}

export async function scanNotebook(path: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/notebook/scan', { path })
  return data
}

export async function scanRedTeam(target: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/redteam/scan', { target })
  return data
}

export async function scanSecrets(path: string, opts?: { enable_entropy?: boolean; git_history?: boolean }): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/secrets/scan', { path, ...opts })
  return data
}

export async function scanDeps(path: string, ecosystem?: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/dep-scan/scan', { path, ecosystem: ecosystem || 'pypi' })
  return data
}

export async function fetchDoctor(): Promise<DoctorResult> {
  const { data } = await api.get<DoctorResult>('/doctor')
  return data
}

export async function fetchEvaluate(): Promise<EvalResult[]> {
  const { data } = await api.get<EvalResult[]>('/evaluate')
  return data
}

export async function fetchPlugins(): Promise<PluginRegistry> {
  const { data } = await api.get<PluginRegistry>('/plugins')
  return data
}

export async function fetchPolicy(): Promise<PolicyInfo> {
  const { data } = await api.get<PolicyInfo>('/policy')
  return data
}
