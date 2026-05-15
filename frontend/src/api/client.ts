import axios from 'axios'
import type {
  Stats, ScannerInfo, HealthInfo, ScanEntry, ArtifactEntry,
  PathScanResult, DoctorResult, EvalResult, PluginRegistry, PolicyInfo,
  AibomResult, ValidateResult, BenchmarkResult,
} from '../types'

const api = axios.create({ baseURL: '/api' })

// Sync auth token from sessionStorage (more secure than localStorage for JWTs)
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('sentinel_token') || localStorage.getItem('sentinel_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Auto-logout on 401 (expired/invalid token)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !error.config?.url?.includes('/auth/login')) {
      sessionStorage.removeItem('sentinel_token')
      localStorage.removeItem('sentinel_token')
      localStorage.removeItem('sentinel_auth')
      delete axios.defaults.headers.common['Authorization']
      window.location.href = '/'
    }
    return Promise.reject(error)
  }
)

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

export async function scanMCP(target: string, manifest?: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/mcp/scan', { target, manifest: manifest || '' })
  return data
}

export async function scanA2A(path: string): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/a2a/scan', { path })
  return data
}

export async function generateAibom(path: string, format?: string): Promise<AibomResult> {
  const { data } = await api.post<AibomResult>('/aibom/generate', { path, format: format || 'cyclonedx' })
  return data
}

export async function scanHF(repo: string, deep?: boolean): Promise<PathScanResult> {
  const { data } = await api.post<PathScanResult>('/hf/scan', { repo, deep: deep || false })
  return data
}

export async function fetchValidate(): Promise<ValidateResult> {
  const { data } = await api.get<ValidateResult>('/validate')
  return data
}

export async function fetchBenchmark(): Promise<BenchmarkResult> {
  const { data } = await api.get<BenchmarkResult>('/benchmark')
  return data
}
