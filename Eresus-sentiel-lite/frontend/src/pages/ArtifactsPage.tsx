import { useState, useCallback, useRef } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { scanArtifact } from '../api/client'
import { FindingCard } from '../components/FindingCard'
import {
  Upload,
  FileSearch,
  Ban,
  CheckCircle2,
  AlertTriangle,
  X,
  Hash,
  Clock,
  HardDrive,
} from 'lucide-react'
import { clsx } from 'clsx'
import type { ArtifactEntry } from '../types'

const FORMATS = '.pkl .pickle .pt .pth .bin .h5 .hdf5 .pb .onnx .safetensors .gguf .joblib .dill .npy .npz .keras .tflite'

const SCANNER_INFO = [
  { label: 'Pickle / Dill / Joblib', abbr: 'PKL', color: 'text-red-400 border-red-500/20' },
  { label: 'PyTorch / TorchScript', abbr: 'PT', color: 'text-orange-400 border-orange-500/20' },
  { label: 'TensorFlow / Keras', abbr: 'TF', color: 'text-blue-400 border-blue-500/20' },
  { label: 'SafeTensors', abbr: 'SF', color: 'text-green-400 border-green-500/20' },
  { label: 'GGUF / GGML', abbr: 'GG', color: 'text-purple-400 border-purple-500/20' },
  { label: 'ONNX', abbr: 'ON', color: 'text-amber-400 border-amber-500/20' },
  { label: 'NumPy (.npy/.npz)', abbr: 'NP', color: 'text-cyan-400 border-cyan-500/20' },
  { label: 'XGBoost / Sklearn', abbr: 'XG', color: 'text-pink-400 border-pink-500/20' },
]

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export default function ArtifactsPage() {
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<ArtifactEntry | null>(null)
  const [history, setHistory] = useState<ArtifactEntry[]>([])
  const [isDragging, setIsDragging] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: () => scanArtifact(file!),
    onSuccess: (data) => {
      setResult(data)
      setHistory((prev) => [data, ...prev].slice(0, 50))
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
  })

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault()
      if (file) mutation.mutate()
    },
    [file, mutation]
  )

  return (
    <div className="flex gap-4">
      {/* Main panel */}
      <div className="flex-1 space-y-4">
        {/* Header */}
        <div className="flex items-center gap-2 text-[10px] text-gray-600 uppercase tracking-[0.2em]">
          <FileSearch className="w-3 h-3" />
          <span>artifact scanner</span>
          <div className="flex-1 border-t border-sentinel-border ml-2" />
          <span className="text-gray-700">{FORMATS.split(' ').length} formats</span>
        </div>

        {/* Upload zone */}
        <form onSubmit={handleSubmit}>
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => {
              e.preventDefault()
              setIsDragging(false)
              const f = e.dataTransfer.files[0]
              if (f) setFile(f)
            }}
            onClick={() => inputRef.current?.click()}
            className={clsx(
              'relative bg-sentinel-card border border-dashed p-8 text-center cursor-pointer transition-colors',
              isDragging ? 'border-red-500/50 bg-red-500/5' : 'border-sentinel-border hover:border-gray-600'
            )}
          >
            <Upload className="w-6 h-6 text-gray-700 mx-auto mb-2" strokeWidth={1.5} />
            <p className="text-[11px] text-gray-500">
              Drop model file or <span className="text-red-400">click to browse</span>
            </p>
            <p className="text-[9px] text-gray-700 mt-1 font-mono">{FORMATS}</p>
            <input
              ref={inputRef}
              type="file"
              className="hidden"
              accept={FORMATS.split(' ').join(',')}
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </div>

          {/* Selected file */}
          {file && (
            <div className="mt-2 flex items-center justify-between px-3 py-2 bg-sentinel-card border border-sentinel-border">
              <div className="flex items-center gap-2 min-w-0">
                <FileSearch className="w-3.5 h-3.5 text-purple-400 flex-shrink-0" />
                <span className="text-[11px] text-gray-300 truncate">{file.name}</span>
                <span className="text-[9px] text-gray-600">{formatBytes(file.size)}</span>
              </div>
              <div className="flex items-center gap-2">
                <button type="button" onClick={() => setFile(null)} className="text-gray-600 hover:text-red-400">
                  <X className="w-3 h-3" />
                </button>
                <button
                  type="submit"
                  disabled={mutation.isPending}
                  className={clsx(
                    'flex items-center gap-1.5 px-3 py-1 text-[10px] uppercase tracking-wider transition-all',
                    mutation.isPending
                      ? 'bg-sentinel-border text-gray-600'
                      : 'bg-red-600 text-white hover:bg-red-500'
                  )}
                >
                  {mutation.isPending ? (
                    <div className="w-3 h-3 border border-white/30 border-t-white animate-spin" />
                  ) : (
                    <FileSearch className="w-3 h-3" />
                  )}
                  {mutation.isPending ? 'SCANNING' : 'SCAN'}
                </button>
              </div>
            </div>
          )}
        </form>

        {/* Error */}
        {mutation.isError && (
          <div className="flex items-center gap-2 p-2 bg-red-500/5 border border-red-500/20 text-[10px] text-red-400">
            <AlertTriangle className="w-3 h-3 flex-shrink-0" />
            {mutation.error?.message ?? 'Scan failed'}
          </div>
        )}

        {/* Result */}
        {result && (
          <div className={clsx(
            'bg-sentinel-card border overflow-hidden animate-fade-in-up',
            result.status === 'CRITICAL' ? 'border-red-500/30' :
            result.status === 'WARNING' ? 'border-amber-500/30' : 'border-green-500/30'
          )}>
            {/* Status header */}
            <div className="flex items-center justify-between px-3 py-2 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                {result.status === 'CRITICAL' ? (
                  <><Ban className="w-3.5 h-3.5 text-red-400" /><span className="text-[10px] text-red-400 font-bold uppercase tracking-wider">CRITICAL</span></>
                ) : result.status === 'WARNING' ? (
                  <><AlertTriangle className="w-3.5 h-3.5 text-amber-400" /><span className="text-[10px] text-amber-400 font-bold uppercase tracking-wider">WARNING</span></>
                ) : (
                  <><CheckCircle2 className="w-3.5 h-3.5 text-green-400" /><span className="text-[10px] text-green-400 font-bold uppercase tracking-wider">CLEAN</span></>
                )}
                <span className="text-[10px] text-gray-500">— {result.filename}</span>
              </div>
              <span className="text-[9px] text-gray-700">{result.finding_count} findings · {result.latency_ms}ms</span>
            </div>

            {/* Metadata */}
            <div className="px-3 py-2 flex items-center gap-4 text-[9px] text-gray-600 bg-black/20">
              <span className="flex items-center gap-1"><HardDrive className="w-2.5 h-2.5" />{formatBytes(result.size)}</span>
              <span className="flex items-center gap-1"><Clock className="w-2.5 h-2.5" />{result.latency_ms}ms</span>
              {result.sha256 && (
                <span className="flex items-center gap-1"><Hash className="w-2.5 h-2.5" />{result.sha256.slice(0, 16)}…</span>
              )}
            </div>

            {/* Findings */}
            {result.findings.length > 0 && (
              <div className="px-3 py-2 space-y-2">
                {result.findings.map((f, i) => (
                  <FindingCard key={i} finding={f} delay={i * 40} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* History */}
        {history.length > 1 && (
          <div>
            <div className="flex items-center gap-2 text-[10px] text-gray-600 uppercase tracking-[0.2em] mb-2">
              <span>session log</span>
              <div className="flex-1 border-t border-sentinel-border ml-2" />
            </div>
            <div className="space-y-0.5">
              {history.slice(1).map((a) => (
                <div key={a.id} className="flex items-center gap-2 px-3 py-1.5 bg-sentinel-card border border-sentinel-border text-[10px]">
                  <span className={clsx(
                    'w-1.5 h-1.5',
                    a.status === 'CRITICAL' ? 'bg-red-500' : a.status === 'WARNING' ? 'bg-amber-500' : 'bg-green-500'
                  )} />
                  <span className="text-gray-400 truncate flex-1">{a.filename}</span>
                  <span className="text-gray-700">{formatBytes(a.size)}</span>
                  <span className="text-gray-700">{a.finding_count}f</span>
                  <span className="text-gray-700">{a.latency_ms}ms</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {!result && !mutation.isPending && (
          <div className="text-center py-16 text-gray-700">
            <FileSearch className="w-8 h-8 mx-auto mb-3 opacity-30" />
            <p className="text-[11px]">Upload a model artifact to scan</p>
            <p className="text-[9px] mt-1">Supports pickle, PyTorch, TensorFlow, SafeTensors, GGUF, ONNX, NumPy</p>
          </div>
        )}
      </div>

      {/* Right panel — scanner capabilities */}
      <div className="hidden xl:block w-52">
        <div className="sticky top-16 space-y-3">
          <div className="text-[9px] text-gray-600 uppercase tracking-[0.15em]">
            SCANNER MATRIX
          </div>
          <div className="space-y-0.5">
            {SCANNER_INFO.map(({ label, abbr, color }, i) => (
              <div
                key={abbr}
                className="flex items-center gap-2 px-2 py-1.5 bg-sentinel-card border border-sentinel-border animate-slide-in"
                style={{ animationDelay: `${i * 30}ms` }}
              >
                <span className={clsx('text-[9px] font-bold px-1 py-0.5 border', color)}>{abbr}</span>
                <span className="text-[9px] text-gray-500 truncate">{label}</span>
              </div>
            ))}
          </div>

          <div className="mt-4 text-[9px] text-gray-600 uppercase tracking-[0.15em]">
            DETECTION
          </div>
          <div className="space-y-1.5 text-[9px]">
            {[
              { label: 'Code Execution', pct: 100, color: 'bg-red-500' },
              { label: 'Data Exfiltration', pct: 95, color: 'bg-orange-500' },
              { label: 'Backdoor Injection', pct: 90, color: 'bg-amber-500' },
              { label: 'Weight Tampering', pct: 85, color: 'bg-blue-500' },
              { label: 'Evasion', pct: 80, color: 'bg-purple-500' },
            ].map(({ label, pct, color }) => (
              <div key={label}>
                <div className="flex justify-between text-gray-600 mb-0.5">
                  <span>{label}</span>
                  <span>{pct}%</span>
                </div>
                <div className="w-full h-0.5 bg-sentinel-border">
                  <div className={clsx('h-full', color)} style={{ width: `${pct}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
