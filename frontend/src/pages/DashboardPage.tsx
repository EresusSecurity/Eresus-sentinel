import { useQuery } from '@tanstack/react-query'
import type { ElementType } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BarChart3,
  Box,
  BrainCircuit,
  ClipboardList,
  Code,
  Crosshair,
  Database,
  FileSearch,
  FlaskConical,
  Gauge,
  GitBranch,
  Lock,
  Network,
  Plug,
  Radar,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  WandSparkles,
} from 'lucide-react'
import { clsx } from 'clsx'
import { fetchScanners, fetchStats } from '../api/client'
import { SeverityChart } from '../components/SeverityChart'
import { TimelineChart } from '../components/TimelineChart'

const capabilityMap = [
  {
    title: 'Eval Matrix',
    status: 'Designing',
    detail: 'Prompt x model x dataset comparison with filterable pass/fail cells.',
    Icon: BarChart3,
    tone: 'blue',
  },
  {
    title: 'Red Team Wizard',
    status: 'In UI',
    detail: 'Purpose, target, plugin, strategy, and review flow for repeatable scans.',
    Icon: Crosshair,
    tone: 'red',
  },
  {
    title: 'Plugin Registry',
    status: 'Partial',
    detail: 'Deterministic rule packs first; attacker-model generators stay optional.',
    Icon: Plug,
    tone: 'violet',
  },
  {
    title: 'Strategy Engine',
    status: 'Next',
    detail: 'Encoding, prompt-injection, replay, and multi-turn attack templates.',
    Icon: WandSparkles,
    tone: 'amber',
  },
  {
    title: 'Provider Adapters',
    status: 'Next',
    detail: 'HTTP, local model, Ollama, HF, MCP, browser, and custom provider contracts.',
    Icon: Network,
    tone: 'green',
  },
  {
    title: 'Model Audit',
    status: 'Beta',
    detail: 'No-load artifact scanning across pickle, Torch, ONNX, SafeTensors, GGUF.',
    Icon: FileSearch,
    tone: 'blue',
  },
  {
    title: 'Code Scanning',
    status: 'Beta',
    detail: 'SAST, secrets, notebooks, diffs, dependency and supply-chain scans.',
    Icon: Code,
    tone: 'slate',
  },
  {
    title: 'Reports',
    status: 'Hardening',
    detail: 'JSON, SARIF, Markdown, HTML, CSV, JUnit and diff snapshots.',
    Icon: ClipboardList,
    tone: 'amber',
  },
]

const roadmapRows = [
  ['30 days', 'Reliability gates', 'Pickle fuzz, MCP HTTP E2E, HF split, SARIF snapshots'],
  ['90 days', 'Beta contract', 'Normalized Finding/ScanResult outputs across every domain'],
  ['6 months', 'Platform expansion', 'AIBOM graph, remote resolvers, team policy profiles'],
]

const hardeningRows = [
  ['Artifact', 'Pickle fuzz CI gate', 'Next'],
  ['MCP', 'Proxy local HTTP passthrough E2E', 'Next'],
  ['HF', 'Mocked/live integration split', 'Next'],
  ['Reporting', 'SARIF/JSON snapshots across domains', 'Next'],
  ['Rules', 'Duplicate rule ID CI gate', 'Next'],
  ['Release', 'Package-data smoke and release checklist', 'Next'],
]

const evalMatrix = [
  ['Travel Agent', 'Prompt Injection', 'openai:gpt-5-mini', 'Fail', 'critical'],
  ['MCP Server', 'Tool Poisoning', 'mcp:stdio', 'Warn', 'high'],
  ['HF Model', 'Pickle Opcode', 'hf://model', 'Block', 'critical'],
  ['Notebook', 'Secret Echo', 'local:ipynb', 'Pass', 'low'],
  ['Agent', 'Repo Prompt Injection', 'codex-agent', 'Review', 'medium'],
]

const maturityRows = [
  ['Artifact no-load scanning', 'Beta', 82],
  ['Prompt firewall checks', 'Beta', 76],
  ['MCP manifest/live scanning', 'Beta', 70],
  ['Dashboard/API', 'Experimental', 42],
  ['Runtime gateway adapters', 'Experimental', 22],
  ['AI/judge enrichment', 'Optional', 18],
]

const toneClasses: Record<string, string> = {
  blue: 'bg-blue-50 text-blue-700 border-blue-100',
  red: 'bg-red-50 text-red-700 border-red-100',
  violet: 'bg-violet-50 text-violet-700 border-violet-100',
  amber: 'bg-amber-50 text-amber-700 border-amber-100',
  green: 'bg-emerald-50 text-emerald-700 border-emerald-100',
  slate: 'bg-slate-50 text-slate-700 border-slate-200',
}

function formatNumber(value: number) {
  return new Intl.NumberFormat('en-US').format(value)
}

function StatusPill({ status }: { status: string }) {
  const tone =
    status === 'Beta' || status === 'In UI'
      ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
      : status === 'Next' || status === 'Designing' || status === 'Hardening'
        ? 'bg-amber-50 text-amber-700 border-amber-100'
        : status === 'Partial' || status === 'Experimental' || status === 'Optional'
          ? 'bg-sky-50 text-sky-700 border-sky-100'
          : 'bg-slate-50 text-slate-600 border-slate-200'

  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium', tone)}>
      {status}
    </span>
  )
}

function MetricCard({
  label,
  value,
  detail,
  Icon,
  accent,
}: {
  label: string
  value: string | number
  detail: string
  Icon: ElementType
  accent: string
}) {
  return (
    <div className="bg-white border border-sentinel-border rounded-lg p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-600">{label}</p>
        <span className={clsx('inline-flex h-8 w-8 items-center justify-center rounded-md border', accent)}>
          <Icon className="h-4 w-4" />
        </span>
      </div>
      <p className="mt-4 text-3xl font-semibold tracking-tight text-gray-200">{value}</p>
      <p className="mt-1 text-xs text-gray-500">{detail}</p>
    </div>
  )
}

function RiskDot({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-amber-400',
    low: 'bg-emerald-500',
  }
  return <span className={clsx('h-2 w-2 rounded-full', colors[level] ?? 'bg-slate-300')} />
}

export default function DashboardPage() {
  const { data: stats } = useQuery({ queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 5000 })
  const { data: scanners } = useQuery({ queryKey: ['scanners'], queryFn: fetchScanners })

  const s = stats ?? {
    total_scans: 0,
    total_findings: 0,
    blocked: 0,
    clean: 0,
    severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    timeline: [],
    artifacts_scanned: 0,
    artifact_findings: 0,
  }

  const totalScanners = (scanners?.input_count ?? 0) + (scanners?.output_count ?? 0)
  const blockRate = s.total_scans > 0 ? Math.round((s.blocked / s.total_scans) * 100 * 10) / 10 : 0

  return (
    <div className="space-y-5 pb-8">
      <section className="overflow-hidden rounded-lg border border-sentinel-border bg-white shadow-sm">
        <div className="grid gap-0 lg:grid-cols-[minmax(0,1.35fr)_minmax(360px,0.65fr)]">
          <div className="p-5 md:p-7">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-red-100 bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-700">
                <ShieldCheck className="h-3.5 w-3.5" />
                Deterministic-first
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-100 bg-blue-50 px-2.5 py-1 text-xs font-semibold text-blue-700">
                <Sparkles className="h-3.5 w-3.5" />
                Platform hardening mode
              </span>
            </div>

            <div className="mt-5 max-w-3xl">
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-gray-600">Eresus Sentinel</p>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight text-gray-200 md:text-5xl">
                AI security command center
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-6 text-gray-500">
                Sentinel brings prompt firewall testing, model artifact audit, MCP and agent review,
                local SAST, supply-chain checks, and repeatable red-team playbooks into one operator console.
              </p>
            </div>

            <div className="mt-6 flex flex-wrap gap-2">
              <Link
                to="/red-team"
                className="inline-flex items-center gap-2 rounded-md bg-gray-900 px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-gray-800"
              >
                <Crosshair className="h-4 w-4" />
                Launch red team
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                to="/artifacts"
                className="inline-flex items-center gap-2 rounded-md border border-sentinel-border bg-white px-4 py-2 text-sm font-semibold text-gray-300 transition-colors hover:bg-slate-50"
              >
                <FileSearch className="h-4 w-4" />
                Scan model artifact
              </Link>
              <a
                href="/api/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 rounded-md border border-sentinel-border bg-white px-4 py-2 text-sm font-semibold text-gray-300 transition-colors hover:bg-slate-50"
              >
                <Terminal className="h-4 w-4" />
                API contract
              </a>
            </div>
          </div>

          <div className="border-t border-sentinel-border bg-slate-50/70 p-5 lg:border-l lg:border-t-0">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-600">Coverage Radar</p>
                <p className="mt-1 text-sm text-gray-500">Product surface we need to close.</p>
              </div>
              <Radar className="h-5 w-5 text-red-500" />
            </div>

            <div className="mt-5 space-y-3">
              {[
                ['Security packs', 157, 'target catalog'],
                ['Attack strategies', 31, 'static, agentic, multi-turn'],
                ['Provider targets', 30, 'HTTP, MCP, browser, models'],
                ['Export formats', 7, 'JSON, SARIF, CSV, HTML, JUnit'],
              ].map(([label, value, detail]) => (
                <div key={label} className="flex items-center justify-between border-b border-sentinel-border pb-3 last:border-b-0 last:pb-0">
                  <div>
                    <p className="text-sm font-medium text-gray-300">{label}</p>
                    <p className="text-xs text-gray-500">{detail}</p>
                  </div>
                  <span className="text-2xl font-semibold text-gray-200">{value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <MetricCard
          label="Scans"
          value={formatNumber(s.total_scans)}
          detail={`${totalScanners} firewall scanners active`}
          Icon={Shield}
          accent="border-blue-100 bg-blue-50 text-blue-700"
        />
        <MetricCard
          label="Findings"
          value={formatNumber(s.total_findings)}
          detail={`${s.artifact_findings} from model artifacts`}
          Icon={AlertTriangle}
          accent="border-red-100 bg-red-50 text-red-700"
        />
        <MetricCard
          label="Block Rate"
          value={`${blockRate}%`}
          detail={`${s.blocked} blocked / ${s.clean} clean`}
          Icon={Lock}
          accent="border-amber-100 bg-amber-50 text-amber-700"
        />
        <MetricCard
          label="Artifacts"
          value={formatNumber(s.artifacts_scanned)}
          detail="No-load model security scans"
          Icon={Box}
          accent="border-emerald-100 bg-emerald-50 text-emerald-700"
        />
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(360px,0.65fr)]">
        <div className="rounded-lg border border-sentinel-border bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-600">Evaluation Matrix</p>
              <h2 className="mt-1 text-lg font-semibold text-gray-200">The missing core table</h2>
            </div>
            <BarChart3 className="h-5 w-5 text-blue-600" />
          </div>

          <div className="mt-4 overflow-hidden rounded-md border border-sentinel-border">
            <div className="grid grid-cols-[1.1fr_1.2fr_1fr_0.7fr] bg-slate-50 px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-gray-600">
              <span>Target</span>
              <span>Check</span>
              <span>Provider</span>
              <span>Result</span>
            </div>
            {evalMatrix.map(([target, check, provider, result, level]) => (
              <div key={`${target}-${check}`} className="grid grid-cols-[1.1fr_1.2fr_1fr_0.7fr] border-t border-sentinel-border px-3 py-3 text-sm">
                <span className="font-medium text-gray-300">{target}</span>
                <span className="text-gray-500">{check}</span>
                <span className="font-mono text-xs text-gray-500">{provider}</span>
                <span className="flex items-center gap-2 font-medium text-gray-300">
                  <RiskDot level={level} />
                  {result}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-sentinel-border bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-600">Roadmap</p>
              <h2 className="mt-1 text-lg font-semibold text-gray-200">Reliability first, then platform</h2>
            </div>
            <GitBranch className="h-5 w-5 text-emerald-600" />
          </div>
          <div className="mt-4 space-y-4">
            {roadmapRows.map(([window, title, detail]) => (
              <div key={window} className="flex gap-3">
                <div className="mt-1 h-2.5 w-2.5 rounded-full bg-gray-900" />
                <div>
                  <p className="text-sm font-semibold text-gray-300">
                    {window} - {title}
                  </p>
                  <p className="mt-1 text-xs leading-5 text-gray-500">{detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
        {capabilityMap.map(({ title, status, detail, Icon, tone }) => (
          <div key={title} className="rounded-lg border border-sentinel-border bg-white p-4 shadow-sm">
            <div className="flex items-start justify-between gap-3">
              <span className={clsx('inline-flex h-9 w-9 items-center justify-center rounded-md border', toneClasses[tone])}>
                <Icon className="h-4 w-4" />
              </span>
              <StatusPill status={status} />
            </div>
            <h3 className="mt-4 text-sm font-semibold text-gray-200">{title}</h3>
            <p className="mt-2 text-xs leading-5 text-gray-500">{detail}</p>
          </div>
        ))}
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(360px,0.75fr)_minmax(0,1.25fr)]">
        <div className="rounded-lg border border-sentinel-border bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-600">Hardening Sprint</p>
              <h2 className="mt-1 text-lg font-semibold text-gray-200">Next gates</h2>
            </div>
            <Gauge className="h-5 w-5 text-amber-600" />
          </div>
          <div className="mt-4 divide-y divide-sentinel-border">
            {hardeningRows.map(([track, item, status]) => (
              <div key={item} className="grid grid-cols-[88px_1fr_auto] items-center gap-3 py-3 text-sm">
                <span className="font-semibold text-gray-300">{track}</span>
                <span className="text-gray-500">{item}</span>
                <StatusPill status={status} />
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-sentinel-border bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-600">Maturity</p>
              <h2 className="mt-1 text-lg font-semibold text-gray-200">Where Sentinel is today</h2>
            </div>
            <BadgeCheck className="h-5 w-5 text-blue-600" />
          </div>
          <div className="mt-5 grid gap-4 md:grid-cols-2">
            {maturityRows.map(([domain, label, pct]) => (
              <div key={domain}>
                <div className="flex items-center justify-between gap-3 text-sm">
                  <span className="font-medium text-gray-300">{domain}</span>
                  <span className="text-xs text-gray-500">{label}</span>
                </div>
                <div className="mt-2 h-2 rounded-full bg-slate-100">
                  <div className="h-full rounded-full bg-gray-900" style={{ width: `${pct}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-sentinel-border bg-white p-5 shadow-sm">
          <div className="flex items-center gap-2 mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-gray-600">
            <Activity className="h-4 w-4" />
            Severity Distribution
          </div>
          <SeverityChart data={s.severity} />
        </div>
        <div className="rounded-lg border border-sentinel-border bg-white p-5 shadow-sm lg:col-span-2">
          <div className="flex items-center gap-2 mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-gray-600">
            <FlaskConical className="h-4 w-4" />
            Scan Activity Timeline
          </div>
          <TimelineChart data={s.timeline} />
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        {[
          { to: '/firewall', label: 'Prompt Firewall', desc: 'Input/output policy checks', Icon: Shield },
          { to: '/mcp', label: 'MCP Scanner', desc: 'Manifest and live endpoint review', Icon: Plug },
          { to: '/aibom', label: 'AIBOM', desc: 'Component inventory and graph path', Icon: Database },
        ].map(({ to, label, desc, Icon }) => (
          <Link
            key={to}
            to={to}
            className="group flex items-center justify-between rounded-lg border border-sentinel-border bg-white p-4 shadow-sm transition-colors hover:border-blue-200 hover:bg-blue-50/40"
          >
            <span className="flex items-center gap-3">
              <Icon className="h-5 w-5 text-gray-500 group-hover:text-blue-700" />
              <span>
                <span className="block text-sm font-semibold text-gray-300">{label}</span>
                <span className="block text-xs text-gray-500">{desc}</span>
              </span>
            </span>
            <ArrowRight className="h-4 w-4 text-gray-700 group-hover:text-blue-700" />
          </Link>
        ))}
      </section>

      <section className="rounded-lg border border-sentinel-border bg-white p-5 shadow-sm">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-600">Operating Model</p>
            <h2 className="mt-1 text-lg font-semibold text-gray-200">How we beat them</h2>
          </div>
          <BrainCircuit className="h-5 w-5 text-violet-600" />
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          {[
            ['Map', 'Attack surfaces, trust boundaries, assets'],
            ['Probe', 'Deterministic tests before AI judges'],
            ['Prove', 'Stable exports, fixtures, CI snapshots'],
            ['Harden', 'Policy packs, baselines, remediation loops'],
          ].map(([title, detail], index) => (
            <div key={title} className="rounded-md border border-sentinel-border bg-slate-50/70 p-4">
              <span className="text-xs font-semibold text-gray-500">0{index + 1}</span>
              <p className="mt-2 text-sm font-semibold text-gray-300">{title}</p>
              <p className="mt-1 text-xs leading-5 text-gray-500">{detail}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
