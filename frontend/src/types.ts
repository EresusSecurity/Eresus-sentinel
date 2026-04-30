export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface Finding {
  rule_id: string
  title: string
  severity: Severity
  confidence: number
  description: string
  evidence: string
  cwe_ids?: string[]
  remediation?: string
}

export interface ScanEntry {
  id: string
  timestamp: string
  type: 'input' | 'output'
  prompt: string
  action: string
  risk_score: number
  finding_count: number
  findings: Finding[]
  latency_ms: number
}

export interface ArtifactEntry {
  id: string
  timestamp: string
  filename: string
  size: number
  finding_count: number
  findings: Finding[]
  latency_ms: number
  status: 'CRITICAL' | 'WARNING' | 'CLEAN'
  sha256?: string
}

export interface Stats {
  total_scans: number
  total_findings: number
  blocked: number
  clean: number
  severity: Record<Severity, number>
  timeline: { ts: string; findings: number; latency: number }[]
  artifacts_scanned: number
  artifact_findings: number
}

export interface ScannerInfo {
  input: string[]
  output: string[]
  input_count: number
  output_count: number
}

export interface HealthInfo {
  status: string
  version: string
  uptime_s: number
  scans_processed: number
  artifacts_processed: number
  instance_id: string
}

export interface PathScanResult {
  findings: Finding[]
  count: number
  latency_ms: number
}

export interface DoctorCheck {
  name: string
  ok: boolean
  detail: string
}

export interface DoctorResult {
  checks: DoctorCheck[]
  passed: number
  total: number
}

export interface EvalResult {
  scanner_name: string
  tp: number
  fp: number
  fn: number
  tn: number
  precision: number
  recall: number
  f1: number
}

export interface PluginInfo {
  name: string
  doc: string
}

export type PluginRegistry = Record<string, PluginInfo[]>

export interface PolicyInfo {
  input_scanners: string[]
  output_scanners: string[]
  mode: string
}

export interface AibomResult {
  bom: Record<string, unknown> | string
  format: string
  path: string
  latency_ms: number
}

export interface ValidateResult {
  valid: boolean
  issues: Finding[]
  latency_ms: number
}

export interface BenchmarkEntry {
  prompt_preview: string
  action: string
  findings: number
  latency_ms: number
}

export interface BenchmarkResult {
  results: BenchmarkEntry[]
  total_ms: number
  avg_ms: number
  prompts_tested: number
}
