import { useState, useCallback } from 'react'
import { useMutation } from '@tanstack/react-query'
import { generateAibom } from '../api/client'
import { FileText, FolderOpen, Download, Clock, CheckCircle2, XCircle, RotateCcw, Search } from 'lucide-react'
import { clsx } from 'clsx'
import type { AibomResult } from '../types'

export default function AibomPage() {
  const [path, setPath] = useState('.')
  const [format, setFormat] = useState('cyclonedx')

  const mutation = useMutation({
    mutationFn: () => generateAibom(path, format),
  })

  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault()
    if (!path.trim()) return
    mutation.mutate()
  }, [path, mutation])

  const result: AibomResult | undefined = mutation.data

  return (
    <div className="space-y-4 max-w-4xl">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 text-gray-600">
          <FileText className="w-4 h-4" />
        </div>
        <div>
          <h1 className="text-[11px] font-bold text-white tracking-[0.2em] uppercase">
            AI Bill of Materials
          </h1>
          <p className="text-[10px] text-gray-600 mt-0.5">
            Generate CycloneDX / SPDX / SARIF inventory of AI components, models, and dependencies
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="bg-sentinel-card border border-sentinel-border p-3">
          <label className="text-[9px] text-gray-600 tracking-[0.2em] uppercase block mb-1.5">
            PROJECT PATH
          </label>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <FolderOpen className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-700" />
              <input
                type="text"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="."
                className="w-full bg-black/40 border border-sentinel-border pl-9 pr-3 py-2.5 text-[11px] text-gray-300 font-mono placeholder:text-gray-700 focus:outline-none focus:border-red-500/40 transition-colors"
              />
            </div>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value)}
              className="bg-black/40 border border-sentinel-border px-3 py-2.5 text-[10px] text-gray-400 font-mono focus:outline-none focus:border-red-500/40"
            >
              <option value="cyclonedx">CycloneDX</option>
              <option value="spdx">SPDX</option>
              <option value="sarif">SARIF</option>
            </select>
            <button
              type="submit"
              disabled={mutation.isPending || !path.trim()}
              className={clsx(
                'px-5 py-2.5 text-[10px] font-bold tracking-[0.15em] uppercase border transition-all flex items-center gap-2',
                mutation.isPending
                  ? 'border-gray-700 text-gray-600 cursor-wait'
                  : 'border-red-500/40 text-red-400 hover:bg-red-500/10 hover:border-red-500/60'
              )}
            >
              {mutation.isPending ? (
                <>
                  <div className="w-3 h-3 border border-gray-600 border-t-gray-300 animate-spin rounded-sm" />
                  GENERATING
                </>
              ) : (
                <>
                  <Search className="w-3 h-3" />
                  GENERATE
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {mutation.isPending && (
        <div className="bg-sentinel-card border border-sentinel-border p-4 animate-pulse">
          <div className="flex items-center gap-3">
            <div className="w-4 h-4 border-2 border-red-500/30 border-t-red-500 animate-spin rounded-full" />
            <p className="text-[11px] text-gray-400">Generating AIBOM for {path}...</p>
          </div>
        </div>
      )}

      {mutation.isError && (
        <div className="bg-red-500/5 border border-red-500/20 p-3 flex items-start gap-2">
          <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-[11px] text-red-400 font-bold">Generation Failed</p>
            <p className="text-[10px] text-red-400/70 mt-0.5">
              {mutation.error instanceof Error ? mutation.error.message : 'Unknown error'}
            </p>
            <button onClick={() => mutation.mutate()} className="text-[9px] text-red-400/60 hover:text-red-400 mt-1.5 flex items-center gap-1">
              <RotateCcw className="w-3 h-3" /> Retry
            </button>
          </div>
        </div>
      )}

      {result && !mutation.isPending && (
        <div className="space-y-3 animate-fade-in-up">
          <div className="bg-green-500/5 border border-green-500/20 p-4">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="w-5 h-5 text-green-400" />
              <div className="flex-1">
                <p className="text-[12px] font-bold text-green-400">AIBOM GENERATED</p>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-[9px] text-gray-600 flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {result.latency_ms.toFixed(0)}ms
                  </span>
                  <span className="text-[9px] text-gray-600">Format: {result.format.toUpperCase()}</span>
                </div>
              </div>
              <button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(result.bom, null, 2)], { type: 'application/json' })
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a')
                  a.href = url; a.download = `aibom.${result.format}.json`; a.click()
                  URL.revokeObjectURL(url)
                }}
                className="text-[9px] text-gray-600 hover:text-gray-300 border border-sentinel-border px-2 py-1 flex items-center gap-1 transition-colors"
              >
                <Download className="w-3 h-3" /> Download
              </button>
            </div>
          </div>
          <div className="bg-sentinel-card border border-sentinel-border p-3 overflow-auto max-h-96">
            <pre className="text-[10px] text-gray-400 font-mono whitespace-pre-wrap">
              {JSON.stringify(result.bom, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {!result && !mutation.isPending && !mutation.isError && (
        <div className="text-center py-16">
          <FileText className="w-8 h-8 mx-auto mb-3 text-gray-800" />
          <p className="text-[11px] text-gray-700">Generate an AI Bill of Materials</p>
          <p className="text-[9px] text-gray-800 mt-1">
            CycloneDX · SPDX · SARIF formats supported
          </p>
        </div>
      )}
    </div>
  )
}
