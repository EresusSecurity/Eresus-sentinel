import { useState, useRef, useCallback } from 'react'
import { useMutation } from '@tanstack/react-query'
import { FindingCard } from './FindingCard'
import { SeverityBadge } from './SeverityBadge'
import type { PathScanResult, Severity } from '../types'
import { clsx } from 'clsx'
import {
  Search,
  Shield,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  FolderOpen,
  RotateCcw,
  ChevronDown,
  ChevronRight,
  Database,
  Star,
  Lightbulb,
} from 'lucide-react'

interface PathScanPageProps {
  title: string
  description: string
  placeholder: string
  scanFn: (input: string) => Promise<PathScanResult>
  inputLabel?: string
  extraOptions?: React.ReactNode
  icon?: React.ReactNode
  suggestions?: { label: string; value: string; hint?: string }[]
}

const HF_QUICK_MODELS = [
  { label: 'Llama 3.1 8B', value: 'meta-llama/Meta-Llama-3.1-8B-Instruct' },
  { label: 'Mistral Small 3.1', value: 'mistralai/Mistral-Small-3.1-24B-Instruct-2503' },
  { label: 'Gemma 3 9B', value: 'google/gemma-3-9b-it' },
  { label: 'Phi-4 Mini', value: 'microsoft/Phi-4-mini-instruct' },
  { label: 'Qwen3.5 72B', value: 'Qwen/Qwen3.5-72B-Instruct' },
  { label: 'DeepSeek-R1', value: 'deepseek-ai/DeepSeek-R1' },
]

export function PathScanPage({
  title,
  description,
  placeholder,
  scanFn,
  inputLabel = 'PATH',
  extraOptions,
  icon,
  suggestions,
}: PathScanPageProps) {
  const [input, setInput] = useState('')
  const [inputError, setInputError] = useState('')
  const [history, setHistory] = useState<Array<PathScanResult & { path: string; ts: string }>>([])
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickerTab, setPickerTab] = useState<'recent' | 'suggestions' | 'hf'>('recent')
  const inputRef = useRef<HTMLInputElement>(null)

  // Validate path: reject traversal sequences and null bytes
  const validateInput = (value: string): string => {
    if (!value.trim()) return 'Path is required'
    if (/\.\.[/\\]|[/\\]\.\./.test(value)) return 'Path traversal sequences (../) are not allowed'
    if (/\0/.test(value)) return 'Null bytes are not allowed'
    if (value.length > 512) return 'Path too long (max 512 chars)'
    return ''
  }

  const mutation = useMutation({
    mutationFn: () => scanFn(input),
    onSuccess: (data) => {
      setHistory((prev) => [
        { ...data, path: input, ts: new Date().toISOString() },
        ...prev.slice(0, 9),
      ])
    },
  })

  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault()
    const err = validateInput(input)
    if (err) { setInputError(err); return }
    setInputError('')
    if (!input.trim() || mutation.isPending) return
    mutation.mutate()
  }, [input, mutation])

  const result = mutation.data
  const sevCounts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  if (result) {
    for (const f of result.findings) {
      sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1
    }
  }

  const maxSev = result && result.count > 0
    ? sevCounts.CRITICAL > 0 ? 'CRITICAL' : sevCounts.HIGH > 0 ? 'HIGH' : 'MEDIUM'
    : null

  return (
    <div className="space-y-4 max-w-4xl">
      {/* Header */}
      <div className="flex items-start gap-3">
        <div className="mt-0.5 text-gray-600">
          {icon || <Shield className="w-4 h-4" />}
        </div>
        <div>
          <h1 className="text-[11px] font-bold text-white tracking-[0.2em] uppercase">
            {title}
          </h1>
          <p className="text-[10px] text-gray-600 mt-0.5">{description}</p>
        </div>
      </div>

      {/* Input form */}
      <form onSubmit={handleSubmit}>
        <div className="bg-sentinel-card border border-sentinel-border p-3">
          <label className="text-[9px] text-gray-600 tracking-[0.2em] uppercase block mb-1.5">
            {inputLabel}
          </label>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <FolderOpen className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-700" />
              <input
                ref={inputRef}
                type="text"
                value={input}
                onChange={(e) => {
                  setInput(e.target.value)
                  if (inputError) setInputError('')
                }}
                placeholder={placeholder}
                className="w-full bg-black/40 border border-sentinel-border pl-9 pr-20 py-2.5 text-[11px] text-gray-300 font-mono placeholder:text-gray-700 focus:outline-none focus:border-red-500/40 transition-colors"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleSubmit(e)
                }}
              />
              {/* Picker toggle */}
              <button
                type="button"
                onClick={() => setPickerOpen((o) => !o)}
                title="Browse targets"
                className={clsx(
                  'absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1 px-1.5 py-1 text-[9px] transition-colors border',
                  pickerOpen
                    ? 'border-red-500/40 text-red-400 bg-red-500/5'
                    : 'border-sentinel-border text-gray-600 hover:text-gray-400 hover:border-gray-600'
                )}
              >
                <ChevronDown className={clsx('w-3 h-3 transition-transform', pickerOpen && 'rotate-180')} />
              </button>
            </div>
            <button
              type="submit"
              disabled={mutation.isPending || !input.trim()}
              className={clsx(
                'px-5 py-2.5 text-[10px] font-bold tracking-[0.15em] uppercase border transition-all flex items-center gap-2',
                mutation.isPending
                  ? 'border-gray-700 text-gray-600 cursor-wait'
                  : input.trim()
                    ? 'border-red-500/40 text-red-400 hover:bg-red-500/10 hover:border-red-500/60'
                    : 'border-gray-800 text-gray-700 cursor-not-allowed'
              )}
            >
              {mutation.isPending ? (
                <>
                  <div className="w-3 h-3 border border-gray-600 border-t-gray-300 animate-spin rounded-sm" />
                  SCANNING
                </>
              ) : (
                <>
                  <Search className="w-3 h-3" />
                  SCAN
                </>
              )}
            </button>
          </div>
          {extraOptions && <div className="mt-2">{extraOptions}</div>}
          {inputError && (
            <p className="text-[9px] text-red-400 mt-1.5">{inputError}</p>
          )}
          <p className="text-[9px] text-gray-800 mt-2">
            Enter an absolute path to a file or directory · ⏎ to scan
          </p>
        </div>
      </form>

      {/* ── Target Picker Panel ─────────────────────────── */}
      {pickerOpen && (
        <div className="bg-sentinel-card border border-sentinel-border animate-fade-in-up">
          {/* Tab bar */}
          <div className="flex border-b border-sentinel-border">
            {([
              { id: 'recent', icon: Clock, label: 'Recent' },
              ...(suggestions && suggestions.length > 0 ? [{ id: 'suggestions', icon: Lightbulb, label: 'Suggestions' }] : []),
              { id: 'hf', icon: Database, label: 'HuggingFace' },
            ] as { id: 'recent' | 'suggestions' | 'hf'; icon: React.ElementType; label: string }[]).map(({ id, icon: Icon, label }) => (
              <button
                key={id}
                type="button"
                onClick={() => setPickerTab(id)}
                className={clsx(
                  'flex items-center gap-1.5 px-3 py-2 text-[10px] border-b-2 transition-colors',
                  pickerTab === id
                    ? 'border-red-500/60 text-red-400'
                    : 'border-transparent text-gray-600 hover:text-gray-400'
                )}
              >
                <Icon className="w-3 h-3" />
                {label}
              </button>
            ))}
          </div>

          {/* Recent tab */}
          {pickerTab === 'recent' && (
            <div className="p-2 space-y-0.5">
              {history.length === 0 ? (
                <p className="text-[10px] text-gray-700 py-3 text-center">No recent scans yet</p>
              ) : (
                history.slice(0, 8).map((h, i) => (
                  <button
                    key={`${h.path}-${i}`}
                    type="button"
                    onClick={() => { setInput(h.path); setPickerOpen(false); inputRef.current?.focus() }}
                    className="w-full text-left flex items-center gap-2 px-2 py-1.5 text-[10px] hover:bg-white/[0.03] transition-colors group rounded-sm"
                  >
                    {h.count === 0 ? (
                      <CheckCircle2 className="w-3 h-3 text-green-600 flex-shrink-0" />
                    ) : (
                      <AlertTriangle className="w-3 h-3 text-orange-600 flex-shrink-0" />
                    )}
                    <span className="text-gray-400 font-mono truncate flex-1">{h.path}</span>
                    <span className="text-gray-700 text-[9px]">{h.count} findings</span>
                    <ChevronRight className="w-3 h-3 text-gray-700 group-hover:text-gray-400 flex-shrink-0" />
                  </button>
                ))
              )}
            </div>
          )}

          {/* Suggestions tab */}
          {pickerTab === 'suggestions' && suggestions && (
            <div className="p-2 space-y-0.5">
              {suggestions.map((s) => (
                <button
                  key={s.value}
                  type="button"
                  onClick={() => { setInput(s.value); setPickerOpen(false); inputRef.current?.focus() }}
                  className="w-full text-left flex items-center gap-2 px-2 py-1.5 text-[10px] hover:bg-white/[0.03] transition-colors rounded-sm"
                >
                  <Star className="w-3 h-3 text-amber-600 flex-shrink-0" />
                  <span className="text-gray-300 flex-1">{s.label}</span>
                  {s.hint && <span className="text-gray-700 font-mono text-[9px]">{s.hint}</span>}
                  <span className="text-gray-700 font-mono text-[9px] truncate max-w-[160px]">{s.value}</span>
                </button>
              ))}
            </div>
          )}

          {/* HuggingFace tab */}
          {pickerTab === 'hf' && (
            <div className="p-2 space-y-0.5">
              <p className="text-[9px] text-gray-700 px-2 pb-1">Quick-select popular models</p>
              {HF_QUICK_MODELS.map((m) => (
                <button
                  key={m.value}
                  type="button"
                  onClick={() => { setInput(m.value); setPickerOpen(false); inputRef.current?.focus() }}
                  className="w-full text-left flex items-center gap-2 px-2 py-1.5 text-[10px] hover:bg-white/[0.03] transition-colors rounded-sm"
                >
                  <Database className="w-3 h-3 text-amber-600 flex-shrink-0" />
                  <span className="text-gray-300 flex-1">{m.label}</span>
                  <span className="text-gray-600 font-mono text-[9px]">{m.value}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Loading skeleton */}
      {mutation.isPending && (
        <div className="bg-sentinel-card border border-sentinel-border p-4 animate-pulse">
          <div className="flex items-center gap-3">
            <div className="w-4 h-4 border-2 border-red-500/30 border-t-red-500 animate-spin rounded-full" />
            <div>
              <p className="text-[11px] text-gray-400">Scanning {input}...</p>
              <p className="text-[9px] text-gray-700 mt-0.5">Running security analysis</p>
            </div>
          </div>
          <div className="mt-3 space-y-2">
            <div className="h-2 bg-sentinel-border rounded w-3/4 animate-pulse" />
            <div className="h-2 bg-sentinel-border rounded w-1/2 animate-pulse" />
            <div className="h-2 bg-sentinel-border rounded w-2/3 animate-pulse" />
          </div>
        </div>
      )}

      {/* Error */}
      {mutation.isError && (
        <div className="bg-red-500/5 border border-red-500/20 p-3 flex items-start gap-2">
          <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-[11px] text-red-400 font-bold">Scan Failed</p>
            <p className="text-[10px] text-red-400/70 mt-0.5">
              {mutation.error instanceof Error ? mutation.error.message : 'Unknown error occurred'}
            </p>
            <button
              onClick={() => mutation.mutate()}
              className="text-[9px] text-red-400/60 hover:text-red-400 mt-1.5 flex items-center gap-1 transition-colors"
            >
              <RotateCcw className="w-3 h-3" /> Retry
            </button>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !mutation.isPending && (
        <div className="space-y-3 animate-fade-in-up">
          {/* Summary banner */}
          <div className={clsx(
            'border p-4',
            result.count === 0
              ? 'bg-green-500/5 border-green-500/20'
              : maxSev === 'CRITICAL'
                ? 'bg-red-500/5 border-red-500/20'
                : 'bg-orange-500/5 border-orange-500/20'
          )}>
            <div className="flex items-center gap-3">
              {result.count === 0 ? (
                <CheckCircle2 className="w-5 h-5 text-green-400" />
              ) : (
                <AlertTriangle className={clsx('w-5 h-5', maxSev === 'CRITICAL' ? 'text-red-400' : 'text-orange-400')} />
              )}
              <div className="flex-1">
                <p className={clsx(
                  'text-[12px] font-bold tracking-wide',
                  result.count === 0 ? 'text-green-400' : maxSev === 'CRITICAL' ? 'text-red-400' : 'text-orange-400'
                )}>
                  {result.count === 0 ? 'NO ISSUES FOUND' : `${result.count} SECURITY FINDING${result.count > 1 ? 'S' : ''}`}
                </p>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-[9px] text-gray-600 flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {result.latency_ms.toFixed(0)}ms
                  </span>
                  <span className="text-[9px] text-gray-600">
                    {input}
                  </span>
                </div>
              </div>
              <button
                onClick={() => mutation.mutate()}
                className="text-[9px] text-gray-600 hover:text-gray-300 border border-sentinel-border px-2 py-1 flex items-center gap-1 transition-colors"
              >
                <RotateCcw className="w-3 h-3" /> Rescan
              </button>
            </div>

            {/* Severity breakdown */}
            {result.count > 0 && (
              <div className="flex gap-2 mt-3 pt-3 border-t border-white/5">
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[]).map((s) => (
                  <div key={s} className={clsx(
                    'flex items-center gap-1.5 transition-opacity',
                    sevCounts[s] > 0 ? 'opacity-100' : 'opacity-30'
                  )}>
                    <SeverityBadge severity={s} />
                    <span className="text-[10px] text-gray-500 font-mono">{sevCounts[s]}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Findings list */}
          {result.findings.length > 0 && (
            <div className="space-y-1.5">
              {result.findings.map((f, i) => (
                <FindingCard key={`${f.rule_id}-${i}`} finding={f} delay={i * 30} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!result && !mutation.isPending && !mutation.isError && (
        <div className="text-center py-16">
          <Search className="w-8 h-8 mx-auto mb-3 text-gray-800" />
          <p className="text-[11px] text-gray-700">Enter a path above to start scanning</p>
          <p className="text-[9px] text-gray-800 mt-1">
            Supports files and directories · Results appear here
          </p>
        </div>
      )}

    </div>
  )
}
