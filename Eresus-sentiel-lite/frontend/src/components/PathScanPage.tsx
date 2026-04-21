import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { FindingCard } from './FindingCard'
import { SeverityBadge } from './SeverityBadge'
import type { PathScanResult, Severity } from '../types'
import { clsx } from 'clsx'

interface PathScanPageProps {
  title: string
  description: string
  placeholder: string
  scanFn: (input: string) => Promise<PathScanResult>
  inputLabel?: string
  extraOptions?: React.ReactNode
}

export function PathScanPage({
  title,
  description,
  placeholder,
  scanFn,
  inputLabel = 'PATH',
  extraOptions,
}: PathScanPageProps) {
  const [input, setInput] = useState('')

  const mutation = useMutation({
    mutationFn: () => scanFn(input),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim()) return
    mutation.mutate()
  }

  const result = mutation.data
  const sevCounts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  if (result) {
    for (const f of result.findings) {
      sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-[11px] font-bold text-white tracking-[0.2em] uppercase">
          {title}
        </h1>
        <p className="text-[10px] text-gray-600 mt-0.5">{description}</p>
      </div>

      {/* Input form */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="bg-sentinel-card border border-sentinel-border p-3">
          <label className="text-[9px] text-gray-600 tracking-[0.2em] uppercase block mb-1.5">
            {inputLabel}
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={placeholder}
              className="flex-1 bg-black/40 border border-sentinel-border px-3 py-2 text-[11px] text-gray-300 font-mono placeholder:text-gray-700 focus:outline-none focus:border-red-500/40"
            />
            <button
              type="submit"
              disabled={mutation.isPending || !input.trim()}
              className={clsx(
                'px-4 py-2 text-[10px] font-bold tracking-[0.15em] uppercase border transition-colors',
                mutation.isPending
                  ? 'border-gray-700 text-gray-600 cursor-wait'
                  : 'border-red-500/40 text-red-400 hover:bg-red-500/10'
              )}
            >
              {mutation.isPending ? 'SCANNING...' : 'SCAN'}
            </button>
          </div>
          {extraOptions}
        </div>
      </form>

      {/* Error */}
      {mutation.isError && (
        <div className="bg-red-500/5 border border-red-500/20 p-3">
          <p className="text-[10px] text-red-400">
            ERROR: {mutation.error instanceof Error ? mutation.error.message : 'Scan failed'}
          </p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-3">
          {/* Summary bar */}
          <div className="bg-sentinel-card border border-sentinel-border p-3 flex items-center gap-4">
            <span className={clsx(
              'text-[11px] font-bold',
              result.count === 0 ? 'text-green-400' : 'text-red-400'
            )}>
              {result.count === 0 ? '✓ CLEAN' : `✗ ${result.count} FINDING(S)`}
            </span>
            <span className="text-[10px] text-gray-700">
              {result.latency_ms.toFixed(0)}ms
            </span>
            <div className="flex gap-1.5 ml-auto">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[]).map((s) =>
                sevCounts[s] > 0 ? (
                  <div key={s} className="flex items-center gap-1">
                    <SeverityBadge severity={s} />
                    <span className="text-[10px] text-gray-500">{sevCounts[s]}</span>
                  </div>
                ) : null
              )}
            </div>
          </div>

          {/* Findings list */}
          {result.findings.length > 0 && (
            <div className="space-y-1">
              {result.findings.map((f, i) => (
                <FindingCard key={`${f.rule_id}-${i}`} finding={f} delay={i * 30} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
