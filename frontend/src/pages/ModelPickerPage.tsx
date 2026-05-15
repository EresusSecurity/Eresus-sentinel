import { useState, useCallback, useRef } from 'react'
import { useMutation } from '@tanstack/react-query'
import { scanArtifact, scanHF } from '../api/client'
import { FindingCard } from '../components/FindingCard'
import {
  Database,
  Upload,
  FileSearch,
  Cpu,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  X,
  Link as LinkIcon,
  Info,
  HardDrive,
  Clock,
  Shield,
  Zap,
  Eye,
  FolderOpen,
  Cloud,
  Bot,
  Brain,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { clsx } from 'clsx'
import type { ArtifactEntry, PathScanResult } from '../types'

/* ── Model catalog by family ────────────────────────────── */
const HF_MODEL_FAMILIES: { family: string; color: string; models: { label: string; repo: string; size: string }[] }[] = [
  {
    family: 'Meta / Llama',
    color: 'text-blue-400',
    models: [
      { label: 'Llama 3.3 70B', repo: 'meta-llama/Llama-3.3-70B-Instruct', size: '70B' },
      { label: 'Llama 3.2 3B', repo: 'meta-llama/Llama-3.2-3B-Instruct', size: '3B' },
      { label: 'Llama 3.1 8B', repo: 'meta-llama/Meta-Llama-3.1-8B-Instruct', size: '8B' },
      { label: 'Llama 3.1 405B', repo: 'meta-llama/Meta-Llama-3.1-405B-Instruct', size: '405B' },
    ],
  },
  {
    family: 'Mistral AI',
    color: 'text-orange-400',
    models: [
      { label: 'Devstral Small 2 (24B)', repo: 'mistralai/Devstral-Small-2505', size: '24B' },
      { label: 'Mistral Small 3.1', repo: 'mistralai/Mistral-Small-3.1-24B-Instruct-2503', size: '24B' },
      { label: 'Ministral 8B', repo: 'mistralai/Ministral-8B-Instruct-2410', size: '8B' },
      { label: 'Ministral 3B', repo: 'mistralai/Ministral-3B-Instruct-2410', size: '3B' },
      { label: 'Codestral', repo: 'mistralai/Codestral-22B-v0.1', size: '22B' },
      { label: 'Mistral NeMo', repo: 'mistralai/Mistral-Nemo-Instruct-2407', size: '12B' },
    ],
  },
  {
    family: 'Google',
    color: 'text-green-400',
    models: [
      { label: 'Gemma 4 27B', repo: 'google/gemma-4-27b-it', size: '27B' },
      { label: 'Gemma 4 9B', repo: 'google/gemma-4-9b-it', size: '9B' },
      { label: 'Gemma 3 27B', repo: 'google/gemma-3-27b-it', size: '27B' },
      { label: 'Gemma 3 9B', repo: 'google/gemma-3-9b-it', size: '9B' },
      { label: 'MedGemma 27B', repo: 'google/medgemma-27b-it', size: '27B' },
      { label: 'MedGemma 4B', repo: 'google/medgemma-4b-it', size: '4B' },
      { label: 'TranslateGemma 27B', repo: 'google/translate-gemma-3-27b', size: '27B' },
    ],
  },
  {
    family: 'Microsoft',
    color: 'text-sky-400',
    models: [
      { label: 'Phi-4', repo: 'microsoft/phi-4', size: '14B' },
      { label: 'Phi-4 Mini', repo: 'microsoft/Phi-4-mini-instruct', size: '3.8B' },
      { label: 'Phi-3.5 Mini', repo: 'microsoft/Phi-3.5-mini-instruct', size: '3.8B' },
    ],
  },
  {
    family: 'Qwen / Alibaba',
    color: 'text-violet-400',
    models: [
      { label: 'Qwen3.6 35B', repo: 'Qwen/Qwen3.6-35B-Instruct', size: '35B' },
      { label: 'Qwen3.6 27B', repo: 'Qwen/Qwen3.6-27B-Instruct', size: '27B' },
      { label: 'Qwen3.5 72B', repo: 'Qwen/Qwen3.5-72B-Instruct', size: '72B' },
      { label: 'Qwen3.5 35B', repo: 'Qwen/Qwen3.5-35B-Instruct', size: '35B' },
      { label: 'Qwen3-Coder-Next', repo: 'Qwen/Qwen3-Coder-Next', size: '235B' },
      { label: 'QwQ-32B', repo: 'Qwen/QwQ-32B', size: '32B' },
      { label: 'Qwen2.5 72B', repo: 'Qwen/Qwen2.5-72B-Instruct', size: '72B' },
      { label: 'Qwen2.5-Coder 32B', repo: 'Qwen/Qwen2.5-Coder-32B-Instruct', size: '32B' },
    ],
  },
  {
    family: 'DeepSeek',
    color: 'text-rose-400',
    models: [
      { label: 'DeepSeek-V4-Pro', repo: 'deepseek-ai/DeepSeek-V4-Pro', size: '671B' },
      { label: 'DeepSeek-V4-Flash', repo: 'deepseek-ai/DeepSeek-V4-Flash', size: '284B' },
      { label: 'DeepSeek-R1', repo: 'deepseek-ai/DeepSeek-R1', size: '671B' },
      { label: 'DeepSeek-R1 Distill 14B', repo: 'deepseek-ai/DeepSeek-R1-Distill-Qwen-14B', size: '14B' },
      { label: 'DeepSeek-R1 Distill 7B', repo: 'deepseek-ai/DeepSeek-R1-Distill-Qwen-7B', size: '7B' },
      { label: 'DeepSeek-V3', repo: 'deepseek-ai/DeepSeek-V3', size: '685B' },
    ],
  },
  {
    family: 'THUDM / GLM',
    color: 'text-cyan-400',
    models: [
      { label: 'GLM-5.1', repo: 'THUDM/glm-5.1', size: '9B' },
      { label: 'GLM-4.7-Flash', repo: 'THUDM/glm-4.7-flash', size: '32B' },
      { label: 'GLM-4V-9B', repo: 'THUDM/glm-4v-9b', size: '9B' },
    ],
  },
  {
    family: 'Moonshot / Kimi',
    color: 'text-amber-400',
    models: [
      { label: 'Kimi K2.6', repo: 'moonshotai/Kimi-K2.6', size: '32B' },
    ],
  },
  {
    family: 'NVIDIA Nemotron',
    color: 'text-lime-400',
    models: [
      { label: 'Nemotron-3-Super 120B', repo: 'nvidia/Nemotron-3-Super-120B-Instruct', size: '120B' },
      { label: 'Nemotron-Cascade-2 30B', repo: 'nvidia/Nemotron-Cascade-2-30B', size: '30B' },
    ],
  },
  {
    family: 'Liquid AI',
    color: 'text-pink-400',
    models: [
      { label: 'LFM2 24B', repo: 'LiquidAI/LFM2-24B', size: '24B' },
      { label: 'LFM2.5-Thinking 1.2B', repo: 'LiquidAI/LFM2.5-1.2B-Thinking', size: '1.2B' },
    ],
  },
  {
    family: 'Cohere',
    color: 'text-teal-400',
    models: [
      { label: 'Command A 03', repo: 'CohereForAI/c4ai-command-a-03-2025', size: '111B' },
      { label: 'Command R+', repo: 'CohereForAI/c4ai-command-r-plus-08-2024', size: '104B' },
    ],
  },
]

const AI_BACKENDS: { id: string; label: string; icon: LucideIcon; models: string[] }[] = [
  {
    id: 'openai', label: 'OpenAI', icon: Bot,
    models: ['gpt-5.5-pro', 'gpt-5.5', 'gpt-5.4-pro', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-5.4-nano', 'gpt-5', 'gpt-5-mini', 'gpt-5-nano', 'gpt-4.1'],
  },
  {
    id: 'anthropic', label: 'Anthropic', icon: Brain,
    models: ['claude-opus-4-7', 'claude-opus-4-6', 'claude-sonnet-4-6', 'claude-sonnet-4-5', 'claude-haiku-4-5'],
  },
  {
    id: 'ollama', label: 'Ollama (Local)', icon: HardDrive,
    models: ['llama3.3', 'gemma4:27b', 'qwen3.6:27b', 'qwen3.5:27b', 'phi4', 'deepseek-r1', 'devstral-small-2', 'lfm2:24b', 'ministral:8b', 'glm-4.7-flash', 'lfm2.5-thinking', 'codestral', 'mistral-small3.1'],
  },
  {
    id: 'ollama-cloud', label: 'Ollama (Cloud)', icon: Cloud,
    models: ['kimi-k2.6', 'deepseek-v4-pro', 'deepseek-v4-flash', 'glm-5.1', 'qwen3-coder-next', 'nemotron-3-super', 'nemotron-cascade-2'],
  },
]

const ACCEPTED_EXTENSIONS = '.pkl,.pickle,.pt,.pth,.bin,.h5,.hdf5,.pb,.onnx,.safetensors,.gguf,.joblib,.dill,.npy,.npz,.keras,.tflite'
const SCAN_THREATS = [
  { icon: Shield, label: 'Pickle RCE', desc: 'Pickle deserialization remote code execution' },
  { icon: Eye, label: 'Backdoors', desc: 'Embedded malicious model layers' },
  { icon: AlertTriangle, label: 'GGUF Overflow', desc: 'GGUF header overflow vulnerabilities' },
  { icon: Zap, label: 'Model Poisoning', desc: 'Weight manipulation / supply chain attacks' },
]

const RECENT_KEY = 'sentinel_recent_hf_models'
const MAX_RECENT = 5

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

function loadRecent(): string[] {
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]') } catch { return [] }
}
function saveRecent(repo: string) {
  const list = [repo, ...loadRecent().filter((r) => r !== repo)].slice(0, MAX_RECENT)
  localStorage.setItem(RECENT_KEY, JSON.stringify(list))
}

type Tab = 'hf' | 'local' | 'backend'

export default function ModelPickerPage() {
  const [activeTab, setActiveTab] = useState<Tab>('hf')

  /* ── HF Scanner state ─────────────────────────────────── */
  const [hfRepo, setHfRepo] = useState('')
  const [deepScan, setDeepScan] = useState(false)
  const [hfResult, setHfResult] = useState<PathScanResult | null>(null)
  const [recentModels, setRecentModels] = useState<string[]>(loadRecent)
  const [expandedFamily, setExpandedFamily] = useState<string | null>(null)

  const hfMutation = useMutation({
    mutationFn: () => scanHF(hfRepo.trim(), deepScan),
    onSuccess: (data) => {
      setHfResult(data)
      saveRecent(hfRepo.trim())
      setRecentModels(loadRecent())
    },
  })

  /* ── Local artifact state ─────────────────────────────── */
  const [file, setFile] = useState<File | null>(null)
  const [isDragOver, setIsDragOver] = useState(false)
  const [artifactResult, setArtifactResult] = useState<ArtifactEntry | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const artifactMutation = useMutation({
    mutationFn: () => scanArtifact(file!),
    onSuccess: (data) => setArtifactResult(data),
  })

  /* ── AI Backend config state ──────────────────────────── */
  const [selectedBackend, setSelectedBackend] = useState(AI_BACKENDS[0].id)
  const [selectedModel, setSelectedModel] = useState(AI_BACKENDS[0].models[0])
  const backend = AI_BACKENDS.find((b) => b.id === selectedBackend)!

  const handleBackendChange = useCallback((id: string) => {
    const b = AI_BACKENDS.find((x) => x.id === id)!
    setSelectedBackend(id)
    setSelectedModel(b.models[0])
  }, [])

  return (
    <div className="max-w-4xl space-y-4">
      {/* ── Page header ─────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-2 text-[10px] text-gray-600 uppercase tracking-[0.2em] mb-1">
          <Cpu className="w-3 h-3" />
          <span>model manager</span>
          <div className="flex-1 border-t border-sentinel-border ml-2" />
        </div>
        <p className="text-[12px] text-gray-500 mt-1">
          Scan local model files, fetch HuggingFace repos, or configure AI enrichment backends.
        </p>
      </div>

      {/* ── Tab bar ─────────────────────────────────────── */}
      <div className="flex border-b border-sentinel-border">
        {([
          { id: 'hf', icon: Database, label: 'HuggingFace', color: 'text-amber-400' },
          { id: 'local', icon: HardDrive, label: 'Local File', color: 'text-purple-400' },
          { id: 'backend', icon: Cpu, label: 'AI Backend', color: 'text-blue-400' },
        ] as const).map(({ id, icon: Icon, label, color }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={clsx(
              'flex items-center gap-1.5 px-4 py-2.5 text-[11px] border-b-2 transition-all',
              activeTab === id
                ? `border-current ${color} bg-white/[0.02]`
                : 'border-transparent text-gray-600 hover:text-gray-400'
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* ══════════════════════════════════════════════════
          TAB 1 — HuggingFace Scanner
      ══════════════════════════════════════════════════ */}
      {activeTab === 'hf' && (
        <div className="space-y-4">
          {/* Recent models */}
          {recentModels.length > 0 && (
            <div className="bg-sentinel-card border border-sentinel-border p-3 space-y-1.5">
              <div className="flex items-center gap-1.5 text-[10px] text-gray-600 uppercase tracking-wider">
                <Clock className="w-3 h-3" />
                Recent scans
              </div>
              <div className="flex flex-wrap gap-1.5">
                {recentModels.map((repo) => (
                  <button
                    key={repo}
                    onClick={() => { setHfRepo(repo); setHfResult(null) }}
                    className={clsx(
                      'flex items-center gap-1 px-2.5 py-1 text-[10px] border transition-colors font-mono',
                      hfRepo === repo
                        ? 'border-amber-500/50 bg-amber-500/10 text-amber-400'
                        : 'border-sentinel-border text-gray-600 hover:border-gray-500 hover:text-gray-300'
                    )}
                  >
                    <Clock className="w-2.5 h-2.5" />
                    {repo}
                  </button>
                ))}
                <button
                  onClick={() => { localStorage.removeItem(RECENT_KEY); setRecentModels([]) }}
                  className="px-2 py-1 text-[9px] text-gray-700 hover:text-red-400 transition-colors"
                  title="Clear history"
                >
                  <X className="w-2.5 h-2.5" />
                </button>
              </div>
            </div>
          )}

          {/* Model family catalog */}
          <div className="bg-sentinel-card border border-sentinel-border">
            <div className="px-4 py-2.5 border-b border-sentinel-border flex items-center justify-between">
              <span className="text-[10px] text-gray-600 uppercase tracking-wider">Quick-select by family</span>
              <span className="text-[9px] text-gray-700">{HF_MODEL_FAMILIES.reduce((n, f) => n + f.models.length, 0)} models</span>
            </div>
            <div className="p-3 space-y-2">
              {HF_MODEL_FAMILIES.map((fam) => (
                <div key={fam.family}>
                  <button
                    onClick={() => setExpandedFamily(expandedFamily === fam.family ? null : fam.family)}
                    className="flex items-center gap-2 w-full text-left py-1"
                  >
                    <ChevronRight
                      className={clsx('w-3 h-3 transition-transform', fam.color,
                        expandedFamily === fam.family && 'rotate-90')}
                    />
                    <span className={clsx('text-[11px] font-medium', fam.color)}>{fam.family}</span>
                    <span className="text-[9px] text-gray-700 ml-auto">{fam.models.length} models</span>
                  </button>
                  {expandedFamily === fam.family && (
                    <div className="ml-5 mt-1 flex flex-wrap gap-1.5">
                      {fam.models.map((m) => (
                        <button
                          key={m.repo}
                          onClick={() => { setHfRepo(m.repo); setHfResult(null) }}
                          className={clsx(
                            'flex items-center gap-1.5 px-2.5 py-1.5 text-[10px] border transition-colors rounded-sm',
                            hfRepo === m.repo
                              ? 'border-amber-500/50 bg-amber-500/10 text-amber-400'
                              : 'border-sentinel-border text-gray-500 hover:border-gray-500 hover:text-gray-300'
                          )}
                        >
                          <span>{m.label}</span>
                          <span className="text-[9px] px-1 bg-gray-800 text-gray-600 rounded">{m.size}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Manual entry + scan */}
          <div className="bg-sentinel-card border border-sentinel-border p-4 space-y-3">
            <div>
              <label className="text-[10px] text-gray-600 uppercase tracking-wider block mb-1.5">
                Repository ID
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={hfRepo}
                  onChange={(e) => { setHfRepo(e.target.value); setHfResult(null) }}
                  onKeyDown={(e) => e.key === 'Enter' && hfRepo.trim() && hfMutation.mutate()}
                  placeholder="org/model-name  e.g. meta-llama/Meta-Llama-3.1-8B"
                  className="flex-1 bg-sentinel-bg border border-sentinel-border px-3 py-2 text-[12px] text-gray-300 placeholder-gray-700 focus:outline-none focus:border-amber-500/50 font-mono"
                  spellCheck={false}
                />
                <a
                  href="https://huggingface.co/models"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 px-3 text-[10px] border border-sentinel-border text-gray-600 hover:text-amber-400 hover:border-amber-500/30 transition-colors"
                  title="Browse HuggingFace"
                >
                  <FolderOpen className="w-3.5 h-3.5" />
                </a>
              </div>
              {hfRepo && (
                <p className="text-[9px] text-gray-700 mt-1 font-mono">
                  → https://huggingface.co/{hfRepo}
                </p>
              )}
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 text-[10px] text-gray-500 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={deepScan}
                  onChange={(e) => setDeepScan(e.target.checked)}
                  className="w-3 h-3 accent-amber-500"
                />
                Deep scan
                <span className="text-[9px] text-gray-700">(downloads & analyses model files — needs HF_TOKEN)</span>
              </label>
              <button
                disabled={!hfRepo.trim() || hfMutation.isPending}
                onClick={() => hfMutation.mutate()}
                className={clsx(
                  'flex items-center gap-1.5 px-4 py-1.5 text-[10px] uppercase tracking-wider transition-all',
                  hfRepo.trim() && !hfMutation.isPending
                    ? 'bg-amber-600 text-white hover:bg-amber-500'
                    : 'bg-sentinel-border text-gray-600 cursor-not-allowed'
                )}
              >
                {hfMutation.isPending ? (
                  <div className="w-3 h-3 border border-white/30 border-t-white animate-spin" />
                ) : (
                  <Database className="w-3 h-3" />
                )}
                {hfMutation.isPending ? 'Scanning…' : 'Scan Repo'}
              </button>
            </div>

            {hfMutation.isError && (
              <div className="flex items-center gap-2 p-2 bg-red-500/5 border border-red-500/20 text-[10px] text-red-400">
                <AlertTriangle className="w-3 h-3" />
                {(hfMutation.error as Error)?.message ?? 'Scan failed'}
              </div>
            )}
          </div>

          {/* Results */}
          {hfResult && (
            <div className="bg-sentinel-card border border-sentinel-border p-4 space-y-2">
              <div className="flex items-center gap-2 text-[10px]">
                {hfResult.count === 0 ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                ) : (
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                )}
                <span className={hfResult.count === 0 ? 'text-green-400' : 'text-red-400'}>
                  {hfResult.count === 0 ? 'No threats detected' : `${hfResult.count} finding${hfResult.count !== 1 ? 's' : ''} detected`}
                </span>
                {hfResult.latency_ms != null && (
                  <span className="ml-auto text-gray-700 font-mono">{hfResult.latency_ms.toFixed(0)}ms</span>
                )}
              </div>
              {hfResult.findings?.map((f, i) => <FindingCard key={i} finding={f} />)}
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════
          TAB 2 — Local File Scanner
      ══════════════════════════════════════════════════ */}
      {activeTab === 'local' && (
        <div className="space-y-4">
          {/* What we detect */}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {SCAN_THREATS.map(({ icon: Icon, label, desc }) => (
              <div key={label} className="bg-sentinel-card border border-sentinel-border p-2.5 space-y-1">
                <div className="flex items-center gap-1.5">
                  <Icon className="w-3 h-3 text-red-400" />
                  <span className="text-[10px] font-medium text-gray-300">{label}</span>
                </div>
                <p className="text-[9px] text-gray-600 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>

          {/* Drop zone */}
          <div className="bg-sentinel-card border border-sentinel-border p-4 space-y-3">
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDragOver(true) }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={(e) => {
                e.preventDefault()
                setIsDragOver(false)
                const f = e.dataTransfer.files[0]
                if (f) { setFile(f); setArtifactResult(null) }
              }}
              onClick={() => fileRef.current?.click()}
              className={clsx(
                'border border-dashed p-8 text-center cursor-pointer transition-all',
                isDragOver
                  ? 'border-purple-400/60 bg-purple-500/5'
                  : 'border-sentinel-border hover:border-gray-600 hover:bg-white/[0.01]'
              )}
            >
              <Upload
                className={clsx('w-6 h-6 mx-auto mb-2 transition-colors', isDragOver ? 'text-purple-400' : 'text-gray-700')}
                strokeWidth={1.5}
              />
              <p className="text-[12px] text-gray-500 mb-1">
                Drop model file here or <span className="text-purple-400 cursor-pointer">click to browse</span>
              </p>
              <p className="text-[9px] text-gray-700">
                Supported: .pkl .pt .pth .bin .gguf .safetensors .onnx .h5 .keras .npy .npz .tflite .joblib
              </p>
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                accept={ACCEPTED_EXTENSIONS}
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  if (f) { setFile(f); setArtifactResult(null) }
                }}
              />
            </div>

            {file && (
              <div className="flex items-center justify-between px-3 py-2 bg-sentinel-bg border border-sentinel-border">
                <div className="flex items-center gap-2 min-w-0">
                  <FileSearch className="w-3.5 h-3.5 text-purple-400 flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-[11px] text-gray-300 truncate font-mono">{file.name}</p>
                    <p className="text-[9px] text-gray-600">{formatBytes(file.size)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => { setFile(null); setArtifactResult(null) }}
                    className="text-gray-600 hover:text-red-400 transition-colors"
                  >
                    <X className="w-3 h-3" />
                  </button>
                  <button
                    disabled={artifactMutation.isPending}
                    onClick={() => artifactMutation.mutate()}
                    className={clsx(
                      'flex items-center gap-1.5 px-3 py-1.5 text-[10px] uppercase tracking-wider transition-all',
                      !artifactMutation.isPending
                        ? 'bg-purple-600 text-white hover:bg-purple-500'
                        : 'bg-sentinel-border text-gray-600'
                    )}
                  >
                    {artifactMutation.isPending ? (
                      <div className="w-3 h-3 border border-white/30 border-t-white animate-spin" />
                    ) : (
                      <FileSearch className="w-3 h-3" />
                    )}
                    {artifactMutation.isPending ? 'Scanning…' : 'Scan File'}
                  </button>
                </div>
              </div>
            )}

            {artifactMutation.isError && (
              <div className="flex items-center gap-2 p-2 bg-red-500/5 border border-red-500/20 text-[10px] text-red-400">
                <AlertTriangle className="w-3 h-3" />
                {(artifactMutation.error as Error)?.message ?? 'Scan failed'}
              </div>
            )}

            {artifactResult && (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-[10px]">
                  {artifactResult.finding_count === 0 ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                  ) : (
                    <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                  )}
                  <span className={artifactResult.finding_count === 0 ? 'text-green-400' : 'text-red-400'}>
                    {artifactResult.finding_count === 0
                      ? 'No threats detected'
                      : `${artifactResult.finding_count} finding${artifactResult.finding_count !== 1 ? 's' : ''}`}
                  </span>
                  <span className="ml-auto text-[9px] text-gray-600 font-mono uppercase">{artifactResult.status}</span>
                </div>
                {artifactResult.findings?.map((f, i) => <FindingCard key={i} finding={f} />)}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════
          TAB 3 — AI Backend Configuration
      ══════════════════════════════════════════════════ */}
      {activeTab === 'backend' && (
        <div className="space-y-4">
          <div className="flex items-start gap-2 p-3 bg-blue-500/5 border border-blue-500/20 text-[10px] text-blue-400">
            <Info className="w-3 h-3 mt-0.5 flex-shrink-0" />
            <span>
              AI enrichment is <strong>optional</strong>. All core scanning is deterministic and YAML-rule based.
              Set <code className="font-mono bg-blue-500/10 px-1">OPENAI_API_KEY</code> or{' '}
              <code className="font-mono bg-blue-500/10 px-1">ANTHROPIC_API_KEY</code> and enable{' '}
              <code className="font-mono bg-blue-500/10 px-1">[ai] enabled = true</code> in{' '}
              <code className="font-mono bg-blue-500/10 px-1">sentinel.toml</code> to activate.
            </span>
          </div>

          {/* Backend selector */}
          <div className="bg-sentinel-card border border-sentinel-border p-4 space-y-4">
            <div>
              <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-2">Provider</p>
              <div className="grid grid-cols-3 gap-2">
                {AI_BACKENDS.map((b) => (
                  <button
                    key={b.id}
                    onClick={() => handleBackendChange(b.id)}
                    className={clsx(
                      'px-3 py-3 text-[11px] border transition-colors text-left rounded-sm',
                      selectedBackend === b.id
                        ? 'border-blue-500/50 bg-blue-500/10 text-blue-300'
                        : 'border-sentinel-border text-gray-500 hover:border-gray-500 hover:text-gray-300'
                    )}
                  >
                    <b.icon className="w-4 h-4 mb-0.5 mx-auto" />
                    <p className="font-medium">{b.label}</p>
                    <p className="text-[9px] text-gray-600 mt-0.5">{b.models.length} models</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Model selector */}
            <div>
              <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">Model</p>
              <div className="flex flex-wrap gap-1.5">
                {backend.models.map((m) => (
                  <button
                    key={m}
                    onClick={() => setSelectedModel(m)}
                    className={clsx(
                      'px-2.5 py-1.5 text-[10px] border transition-colors rounded-sm font-mono',
                      selectedModel === m
                        ? 'border-blue-500/50 bg-blue-500/10 text-blue-300'
                        : 'border-sentinel-border text-gray-600 hover:border-gray-500 hover:text-gray-300'
                    )}
                  >
                    {m}
                  </button>
                ))}
              </div>
            </div>

            {/* Generated config */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-[10px] text-gray-600 uppercase tracking-wider">sentinel.toml snippet</p>
                <button
                  onClick={() => {
                    const snippet = `[ai]\nenabled = true\nprovider = "${selectedBackend === 'ollama' ? 'ollama' : selectedBackend}"\nmodel = "${selectedModel}"\ntimeout_seconds = 30`
                    navigator.clipboard.writeText(snippet)
                  }}
                  className="text-[9px] text-gray-600 hover:text-blue-400 transition-colors flex items-center gap-1"
                >
                  Copy
                </button>
              </div>
              <pre className="bg-sentinel-bg border border-sentinel-border p-3 text-[10px] text-gray-400 font-mono overflow-x-auto leading-relaxed">
{`[ai]
enabled = true
provider = "${selectedBackend === 'ollama' ? 'ollama' : selectedBackend}"
model = "${selectedModel}"
timeout_seconds = 30`}
              </pre>
            </div>
          </div>

          <a
            href="https://huggingface.co/models"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-[10px] text-amber-500 hover:text-amber-400 transition-colors"
          >
            <LinkIcon className="w-3 h-3" />
            Browse models on HuggingFace
            <ChevronRight className="w-3 h-3" />
          </a>
        </div>
      )}
    </div>
  )
}
