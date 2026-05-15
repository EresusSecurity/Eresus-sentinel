import { useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { clsx } from 'clsx'
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  Brain,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  Code,
  Crosshair,
  Database,
  FileSearch,
  Filter,
  GitBranch,
  Globe2,
  Layers3,
  ListChecks,
  LockKeyhole,
  Network,
  Play,
  Radar,
  Route,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  Target,
  Terminal,
  TriangleAlert,
  WandSparkles,
  XCircle,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import { scanRedTeam } from '../api/client'
import { FindingCard } from '../components/FindingCard'
import { SeverityBadge } from '../components/SeverityBadge'
import type { PathScanResult, Severity } from '../types'

type WorkbenchTab = 'run' | 'catalog' | 'matrix' | 'roadmap'

interface CoverageCard {
  title: string
  count: string
  status: string
  icon: LucideIcon
  tone: string
  route?: string
}

interface AttackPlugin {
  category: string
  icon: LucideIcon
  items: string[]
  coverage: number
  maturity: 'Live' | 'Next' | 'Design'
}

const productCoverage: CoverageCard[] = [
  {
    title: 'Red Teaming',
    count: '90+ probes',
    status: 'Endpoint, model, agent, RAG, and policy playbooks',
    icon: Crosshair,
    tone: 'text-red-500 bg-red-500/10 border-red-500/20',
  },
  {
    title: 'Evaluations',
    count: 'Matrix',
    status: 'Provider x prompt x assertion comparison surface',
    icon: ListChecks,
    tone: 'text-blue-600 bg-blue-500/10 border-blue-500/20',
  },
  {
    title: 'Model Audit',
    count: '30+ formats',
    status: 'No-load artifact scanning, SBOM, SARIF, HF paths',
    icon: FileSearch,
    tone: 'text-emerald-600 bg-emerald-500/10 border-emerald-500/20',
    route: '/models',
  },
  {
    title: 'Code Scanning',
    count: 'Local SAST',
    status: 'SAST, secrets, notebooks, diffs, supply-chain checks',
    icon: Code,
    tone: 'text-slate-700 bg-slate-500/10 border-slate-500/20',
    route: '/sast',
  },
  {
    title: 'Guardrails',
    count: 'Feedback loop',
    status: 'Firewall rules generated from red-team failures',
    icon: ShieldCheck,
    tone: 'text-amber-600 bg-amber-500/10 border-amber-500/20',
    route: '/firewall',
  },
  {
    title: 'MCP Security',
    count: 'Proxy + scan',
    status: 'Manifest, live server, proxy, and tool-call review',
    icon: Network,
    tone: 'text-cyan-700 bg-cyan-500/10 border-cyan-500/20',
    route: '/mcp',
  },
]

const attackPlugins: AttackPlugin[] = [
  {
    category: 'Security and access control',
    icon: LockKeyhole,
    items: ['Prompt injection', 'BOLA/BFLA', 'SSRF', 'Shell/SQL injection', 'Cross-session leak'],
    coverage: 84,
    maturity: 'Live',
  },
  {
    category: 'Agent and tool abuse',
    icon: Bot,
    items: ['Tool discovery', 'Excessive agency', 'Memory poisoning', 'MCP abuse', 'Repo prompt injection'],
    coverage: 78,
    maturity: 'Live',
  },
  {
    category: 'Privacy and data leakage',
    icon: Shield,
    items: ['PII exposure', 'Data exfiltration', 'RAG document leak', 'Canary replay', 'Model identification'],
    coverage: 82,
    maturity: 'Live',
  },
  {
    category: 'Trust and safety',
    icon: TriangleAlert,
    items: ['Harmful content', 'Bias', 'Misinformation', 'Overreliance', 'Specialized advice'],
    coverage: 66,
    maturity: 'Next',
  },
  {
    category: 'Model and artifact security',
    icon: Database,
    items: ['Pickle RCE', 'GGUF metadata', 'HF supply chain', 'SBOM', 'Remote resolver'],
    coverage: 88,
    maturity: 'Live',
  },
  {
    category: 'Compliance profiles',
    icon: ClipboardCheck,
    items: ['OWASP LLM', 'NIST AI RMF', 'EU AI Act', 'GDPR', 'Industry policy packs'],
    coverage: 42,
    maturity: 'Design',
  },
]

const strategies = [
  { name: 'Basic', icon: Target, active: true },
  { name: 'Composite jailbreak', icon: Brain, active: true },
  { name: 'Meta jailbreak', icon: Sparkles, active: true },
  { name: 'ASCII smuggling', icon: Filter, active: true },
  { name: 'Multilingual', icon: Globe2, active: true },
  { name: 'Best-of-N', icon: Route, active: true },
  { name: 'Tree search', icon: GitBranch, active: false },
  { name: 'RAG poison', icon: Layers3, active: false },
  { name: 'Browser agent', icon: WandSparkles, active: false },
]

const matrixRows = [
  { probe: 'Direct prompt injection', target: 'HTTP agent', gpt: 'fail', claude: 'pass', local: 'fail', risk: 'HIGH' },
  { probe: 'Indirect web injection', target: 'Browser tool', gpt: 'fail', claude: 'fail', local: 'warn', risk: 'CRITICAL' },
  { probe: 'BOLA account switch', target: 'Support bot', gpt: 'pass', claude: 'pass', local: 'warn', risk: 'MEDIUM' },
  { probe: 'RAG document exfiltration', target: 'Knowledge base', gpt: 'fail', claude: 'warn', local: 'fail', risk: 'HIGH' },
  { probe: 'Tool discovery', target: 'MCP server', gpt: 'warn', claude: 'pass', local: 'warn', risk: 'MEDIUM' },
  { probe: 'Pickle artifact chain', target: 'Model registry', gpt: 'pass', claude: 'pass', local: 'pass', risk: 'LOW' },
] as const

const sprintRows = [
  { track: '30 days', goal: 'Make every scanner contract boringly reliable', status: 'Hardening', progress: 72 },
  { track: '90 days', goal: 'Normalize findings across JSON, SARIF, Markdown, HTML, CSV, and JUnit', status: 'Beta gate', progress: 46 },
  { track: '6 months', goal: 'Own agent, MCP, artifact, and eval workflows with team policy packs', status: 'Expansion', progress: 24 },
]

const yamlPreview = `targets:
  - id: https
    label: sentinel-customer-agent
    config:
      url: http://localhost:8000/v1/chat
      method: POST
      body:
        message: "{{prompt}}"

redteam:
  purpose: Customer-support agent with tools and RAG access
  plugins:
    - prompt-injection
    - data-exfiltration
    - mcp
    - bola
    - pii:direct
  strategies:
    - basic
    - jailbreak:composite
    - ascii-smuggling
    - multilingual
  numTests: 10`

function scoreFor(result?: PathScanResult): { label: string; severity: Severity; tone: string } {
  if (!result || result.count === 0) {
    return { label: 'Clean', severity: 'INFO', tone: 'text-emerald-600 bg-emerald-500/10 border-emerald-500/20' }
  }

  const severities = result.findings.map((finding) => finding.severity)
  if (severities.includes('CRITICAL')) {
    return { label: 'Critical risk', severity: 'CRITICAL', tone: 'text-red-600 bg-red-500/10 border-red-500/20' }
  }
  if (severities.includes('HIGH')) {
    return { label: 'High risk', severity: 'HIGH', tone: 'text-orange-600 bg-orange-500/10 border-orange-500/20' }
  }
  return { label: 'Needs review', severity: 'MEDIUM', tone: 'text-amber-600 bg-amber-500/10 border-amber-500/20' }
}

function MatrixCell({ value }: { value: 'pass' | 'warn' | 'fail' }) {
  const styles = {
    pass: 'bg-emerald-500/10 text-emerald-700 border-emerald-500/20',
    warn: 'bg-amber-500/10 text-amber-700 border-amber-500/20',
    fail: 'bg-red-500/10 text-red-700 border-red-500/20',
  }
  return (
    <span className={clsx('inline-flex min-w-14 items-center justify-center rounded-md border px-2 py-1 text-[11px] font-semibold uppercase', styles[value])}>
      {value}
    </span>
  )
}

function PanelHeader({ eyebrow, title, action }: { eyebrow: string; title: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col gap-2 border-b border-sentinel-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-gray-500">{eyebrow}</p>
        <h2 className="mt-1 text-sm font-semibold text-white">{title}</h2>
      </div>
      {action}
    </div>
  )
}

export default function RedTeamPage() {
  const [target, setTarget] = useState('http://localhost:8000/v1/chat')
  const [activeTab, setActiveTab] = useState<WorkbenchTab>('run')
  const [inputError, setInputError] = useState('')

  const mutation = useMutation({
    mutationFn: () => scanRedTeam(target.trim()),
  })

  const resultScore = useMemo(() => scoreFor(mutation.data), [mutation.data])
  const findingCounts = useMemo(() => {
    const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    for (const finding of mutation.data?.findings ?? []) {
      counts[finding.severity] += 1
    }
    return counts
  }, [mutation.data])

  const handleRun = (event: FormEvent) => {
    event.preventDefault()
    if (!target.trim()) {
      setInputError('Target is required')
      return
    }
    if (target.length > 512) {
      setInputError('Target is too long')
      return
    }
    setInputError('')
    mutation.mutate()
  }

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5">
      <section className="overflow-hidden rounded-lg border border-sentinel-border bg-sentinel-card">
        <div className="grid gap-5 p-5 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2 rounded-full border border-red-500/20 bg-red-500/10 px-3 py-1 text-xs font-semibold text-red-600">
                <Radar className="h-3.5 w-3.5" />
                EvalOps Workbench
              </span>
              <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-700">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Deterministic-first
              </span>
            </div>

            <div>
              <h1 className="max-w-3xl text-3xl font-semibold tracking-tight text-white md:text-4xl">
                Sentinel red-team, eval, guardrail, and model-audit control plane
              </h1>
              <p className="mt-3 max-w-3xl text-sm leading-6 text-gray-500">
                One white workbench for target setup, attack generation, side-by-side evals, findings triage, and the hardening roadmap.
              </p>
            </div>

            <form onSubmit={handleRun} className="rounded-lg border border-sentinel-border bg-sentinel-bg p-3">
              <label className="text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">
                Target endpoint, script, model, or MCP server
              </label>
              <div className="mt-2 flex flex-col gap-2 sm:flex-row">
                <div className="relative flex-1">
                  <Terminal className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                  <input
                    value={target}
                    onChange={(event) => {
                      setTarget(event.target.value)
                      if (inputError) {
                        setInputError('')
                      }
                    }}
                    className="h-11 w-full rounded-md border border-sentinel-border bg-white pl-10 pr-3 font-mono text-sm text-gray-300 placeholder:text-gray-600"
                    placeholder="http://localhost:8000/v1/chat"
                  />
                </div>
                <button
                  type="submit"
                  disabled={mutation.isPending}
                  className="inline-flex h-11 items-center justify-center gap-2 rounded-md bg-red-600 px-4 text-sm font-semibold text-white transition-colors hover:bg-red-500 disabled:cursor-wait disabled:bg-gray-400"
                >
                  {mutation.isPending ? (
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                  Run red team
                </button>
              </div>
              {inputError && <p className="mt-2 text-xs font-medium text-red-600">{inputError}</p>}
            </form>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
            <div className={clsx('rounded-lg border p-4', resultScore.tone)}>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.2em] opacity-80">Current risk</p>
                  <p className="mt-1 text-2xl font-semibold">{resultScore.label}</p>
                </div>
                <SeverityBadge severity={resultScore.severity} />
              </div>
              <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
                <div className="rounded-md bg-white/70 p-2">
                  <p className="font-mono text-lg font-semibold">{mutation.data?.count ?? 0}</p>
                  <p className="text-gray-500">findings</p>
                </div>
                <div className="rounded-md bg-white/70 p-2">
                  <p className="font-mono text-lg font-semibold">{mutation.data?.latency_ms?.toFixed(0) ?? '-'}</p>
                  <p className="text-gray-500">ms</p>
                </div>
                <div className="rounded-md bg-white/70 p-2">
                  <p className="font-mono text-lg font-semibold">4</p>
                  <p className="text-gray-500">exports</p>
                </div>
              </div>
            </div>

            <div className="rounded-lg border border-sentinel-border bg-sentinel-bg p-4">
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">Race plan</p>
              <div className="mt-3 space-y-3">
                {sprintRows.map((row) => (
                  <div key={row.track}>
                    <div className="flex items-center justify-between gap-3 text-xs">
                      <span className="font-semibold text-white">{row.track}</span>
                      <span className="text-gray-500">{row.status}</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-sentinel-border">
                      <div className="h-full rounded-full bg-red-500" style={{ width: `${row.progress}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
        {productCoverage.map(({ title, count, status, icon: Icon, tone, route }) => {
          const body = (
            <div className="h-full rounded-lg border border-sentinel-border bg-sentinel-card p-4 transition-colors hover:border-red-500/30">
              <div className={clsx('mb-4 inline-flex h-9 w-9 items-center justify-center rounded-md border', tone)}>
                <Icon className="h-4 w-4" />
              </div>
              <p className="text-sm font-semibold text-white">{title}</p>
              <p className="mt-1 text-2xl font-semibold tracking-tight text-gray-300">{count}</p>
              <p className="mt-2 min-h-10 text-xs leading-5 text-gray-500">{status}</p>
              {route && (
                <span className="mt-3 inline-flex items-center gap-1 text-xs font-semibold text-red-600">
                  Open <ArrowRight className="h-3 w-3" />
                </span>
              )}
            </div>
          )

          return route ? (
            <Link key={title} to={route} className="block">
              {body}
            </Link>
          ) : (
            <div key={title}>{body}</div>
          )
        })}
      </section>

      <section className="overflow-hidden rounded-lg border border-sentinel-border bg-sentinel-card">
        <div className="flex flex-wrap gap-2 border-b border-sentinel-border bg-sentinel-bg p-2">
          {[
            { id: 'run', label: 'Run plan', icon: Play },
            { id: 'catalog', label: 'Attack catalog', icon: Search },
            { id: 'matrix', label: 'Eval matrix', icon: ListChecks },
            { id: 'roadmap', label: 'Roadmap', icon: Zap },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as WorkbenchTab)}
              className={clsx(
                'inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-semibold transition-colors',
                activeTab === id
                  ? 'bg-white text-red-600 shadow-sm'
                  : 'text-gray-500 hover:bg-white/70 hover:text-gray-300'
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>

        {activeTab === 'run' && (
          <div className="grid gap-0 lg:grid-cols-[0.9fr_1.1fr]">
            <div className="border-b border-sentinel-border lg:border-b-0 lg:border-r">
              <PanelHeader
                eyebrow="Generated config"
                title="Red-team playbook"
                action={<span className="rounded-md border border-sentinel-border px-2 py-1 text-xs font-mono text-gray-500">sentinel redteam scan</span>}
              />
              <div className="p-4">
                <pre className="max-h-[520px] overflow-auto rounded-lg border border-sentinel-border bg-white p-4 text-xs leading-5 text-gray-300">
                  {yamlPreview}
                </pre>
              </div>
            </div>

            <div>
              <PanelHeader eyebrow="Live result" title="Findings and guardrail candidates" />
              <div className="space-y-4 p-4">
                <div className="grid gap-3 sm:grid-cols-5">
                  {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[]).map((severity) => (
                    <div key={severity} className="rounded-lg border border-sentinel-border bg-sentinel-bg p-3">
                      <SeverityBadge severity={severity} />
                      <p className="mt-3 font-mono text-2xl font-semibold text-white">{findingCounts[severity]}</p>
                    </div>
                  ))}
                </div>

                {mutation.isPending && (
                  <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4">
                    <div className="flex items-center gap-3">
                      <span className="h-5 w-5 animate-spin rounded-full border-2 border-red-500/30 border-t-red-500" />
                      <div>
                        <p className="text-sm font-semibold text-red-600">Running probes</p>
                        <p className="text-xs text-gray-500">Generating attacks, calling target, and grading responses.</p>
                      </div>
                    </div>
                  </div>
                )}

                {mutation.isError && (
                  <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4">
                    <div className="flex items-start gap-3">
                      <XCircle className="mt-0.5 h-5 w-5 text-red-600" />
                      <div>
                        <p className="text-sm font-semibold text-red-600">Scan failed</p>
                        <p className="mt-1 text-xs text-red-500">
                          {mutation.error instanceof Error ? mutation.error.message : 'Unknown error'}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {mutation.data && mutation.data.findings.length > 0 && (
                  <div className="space-y-3">
                    {mutation.data.findings.map((finding, index) => (
                      <FindingCard key={`${finding.rule_id}-${index}`} finding={finding} />
                    ))}
                  </div>
                )}

                {mutation.data && mutation.data.findings.length === 0 && (
                  <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-5 text-center">
                    <CheckCircle2 className="mx-auto h-8 w-8 text-emerald-600" />
                    <p className="mt-2 text-sm font-semibold text-emerald-700">No findings from this run</p>
                    <p className="mt-1 text-xs text-gray-500">Increase strategies or switch to deep/paranoid profile for stronger coverage.</p>
                  </div>
                )}

                {!mutation.data && !mutation.isPending && !mutation.isError && (
                  <div className="rounded-lg border border-sentinel-border bg-sentinel-bg p-5 text-center">
                    <Crosshair className="mx-auto h-8 w-8 text-gray-500" />
                    <p className="mt-2 text-sm font-semibold text-white">Ready to attack the target</p>
                    <p className="mt-1 text-xs text-gray-500">Run once, then convert failures into firewall and guardrail rules.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'catalog' && (
          <div>
            <PanelHeader eyebrow="Coverage map" title="Plugin coverage and maturity" />
            <div className="grid gap-3 p-4 lg:grid-cols-3">
              {attackPlugins.map(({ category, icon: Icon, items, coverage, maturity }) => (
                <div key={category} className="rounded-lg border border-sentinel-border bg-sentinel-bg p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-red-500/20 bg-red-500/10 text-red-600">
                        <Icon className="h-4 w-4" />
                      </span>
                      <div>
                        <p className="text-sm font-semibold text-white">{category}</p>
                        <p className="text-xs text-gray-500">{maturity}</p>
                      </div>
                    </div>
                    <span className="font-mono text-sm font-semibold text-gray-300">{coverage}%</span>
                  </div>
                  <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-sentinel-border">
                    <div className="h-full rounded-full bg-red-500" style={{ width: `${coverage}%` }} />
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {items.map((item) => (
                      <span key={item} className="rounded-full border border-sentinel-border bg-white px-2 py-1 text-xs text-gray-500">
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="border-t border-sentinel-border p-4">
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">Delivery strategies</p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {strategies.map(({ name, icon: Icon, active }) => (
                  <button
                    key={name}
                    className={clsx(
                      'flex items-center justify-between rounded-lg border px-3 py-2 text-left transition-colors',
                      active
                        ? 'border-red-500/20 bg-red-500/5 text-red-600'
                        : 'border-sentinel-border bg-white text-gray-500 hover:border-red-500/20 hover:text-gray-300'
                    )}
                  >
                    <span className="flex items-center gap-2 text-sm font-semibold">
                      <Icon className="h-4 w-4" />
                      {name}
                    </span>
                    <ChevronRight className="h-4 w-4" />
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'matrix' && (
          <div>
            <PanelHeader
              eyebrow="Side-by-side evals"
              title="Provider, prompt, and assertion comparison"
              action={<Link to="/history" className="inline-flex items-center gap-1 text-sm font-semibold text-red-600">History <ArrowRight className="h-4 w-4" /></Link>}
            />
            <div className="overflow-auto p-4">
              <table className="w-full min-w-[760px] border-collapse overflow-hidden rounded-lg text-left text-sm">
                <thead>
                  <tr className="border-b border-sentinel-border bg-sentinel-bg text-xs uppercase tracking-[0.18em] text-gray-500">
                    <th className="px-3 py-3">Probe</th>
                    <th className="px-3 py-3">Target</th>
                    <th className="px-3 py-3">GPT</th>
                    <th className="px-3 py-3">Claude</th>
                    <th className="px-3 py-3">Local</th>
                    <th className="px-3 py-3">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {matrixRows.map((row) => (
                    <tr key={row.probe} className="border-b border-sentinel-border last:border-b-0">
                      <td className="px-3 py-3 font-semibold text-white">{row.probe}</td>
                      <td className="px-3 py-3 text-gray-500">{row.target}</td>
                      <td className="px-3 py-3"><MatrixCell value={row.gpt} /></td>
                      <td className="px-3 py-3"><MatrixCell value={row.claude} /></td>
                      <td className="px-3 py-3"><MatrixCell value={row.local} /></td>
                      <td className="px-3 py-3"><SeverityBadge severity={row.risk as Severity} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'roadmap' && (
          <div>
            <PanelHeader eyebrow="Sentinel public roadmap" title="Reliability first, then product expansion" />
            <div className="grid gap-4 p-4 lg:grid-cols-3">
              {sprintRows.map((row) => (
                <div key={row.track} className="rounded-lg border border-sentinel-border bg-sentinel-bg p-4">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-semibold text-white">{row.track}</p>
                    <span className="rounded-full border border-red-500/20 bg-red-500/10 px-2 py-1 text-xs font-semibold text-red-600">{row.status}</span>
                  </div>
                  <p className="mt-3 min-h-12 text-sm leading-6 text-gray-500">{row.goal}</p>
                  <div className="mt-4 h-2 overflow-hidden rounded-full bg-sentinel-border">
                    <div className="h-full rounded-full bg-red-500" style={{ width: `${row.progress}%` }} />
                  </div>
                </div>
              ))}
            </div>

            <div className="grid gap-4 border-t border-sentinel-border p-4 lg:grid-cols-2">
              <div className="rounded-lg border border-sentinel-border bg-sentinel-bg p-4">
                <p className="text-sm font-semibold text-white">Next hardening gates</p>
                <div className="mt-3 space-y-2">
                  {['Pickle fuzz CI gate', 'MCP proxy HTTP passthrough E2E', 'HF mocked/live integration split', 'SARIF/JSON snapshots', 'Duplicate rule ID CI gate'].map((item) => (
                    <div key={item} className="flex items-center gap-2 rounded-md bg-white px-3 py-2 text-sm text-gray-500">
                      <AlertTriangle className="h-4 w-4 text-amber-600" />
                      {item}
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-lg border border-sentinel-border bg-sentinel-bg p-4">
                <p className="text-sm font-semibold text-white">Leapfrog bets</p>
                <div className="mt-3 space-y-2">
                  {['Deterministic grader registry before judge enrichment', 'AIBOM graph plus artifact exploit-chain tracing', 'Agent sandbox sabotage tests', 'Policy profiles for teams and industries', 'Local-first reports with enterprise exports'].map((item) => (
                    <div key={item} className="flex items-center gap-2 rounded-md bg-white px-3 py-2 text-sm text-gray-500">
                      <Zap className="h-4 w-4 text-red-600" />
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  )
}
