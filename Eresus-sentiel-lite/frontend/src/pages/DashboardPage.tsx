import { useQuery } from '@tanstack/react-query'
import { fetchStats, fetchScanners } from '../api/client'
import { StatCard } from '../components/StatCard'
import { SeverityChart } from '../components/SeverityChart'
import { TimelineChart } from '../components/TimelineChart'
import { Shield, AlertTriangle, Ban, FileWarning, ArrowRight, Terminal, Target, ScanSearch } from 'lucide-react'
import { Link } from 'react-router-dom'
import { clsx } from 'clsx'

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

  const hasData = s.total_scans > 0 || s.artifacts_scanned > 0

  // ── Onboarding view (no scans yet) ─────────────────────
  if (!hasData) {
    return (
      <div className="flex flex-col items-center pt-12">
        <h1 className="text-2xl md:text-3xl font-semibold text-gray-200 text-center leading-snug max-w-xl">
          Initiate Scan to activate Dashboard and generate your first Report.
        </h1>

        {/* Step wizard */}
        <div className="flex items-center gap-0 mt-10 mb-8">
          {/* Step 1 */}
          <div className="flex flex-col items-center">
            <div className="w-10 h-10 rounded-full border-2 border-amber-500 flex items-center justify-center text-amber-500 font-bold text-sm">
              1
            </div>
            <div className="h-8 w-0.5 bg-amber-500" />
            <Link
              to="/firewall"
              className="flex items-center gap-2 px-8 py-3 bg-amber-500 hover:bg-amber-400 text-black font-semibold rounded-lg transition-colors"
            >
              <Target className="w-5 h-5" />
              SETUP TARGET
              <ArrowRight className="w-4 h-4 ml-1" />
            </Link>
          </div>

          {/* Connector line */}
          <div className="w-32 md:w-48 h-0.5 bg-sentinel-border self-start mt-5" />

          {/* Step 2 */}
          <div className="flex flex-col items-center">
            <div className="w-10 h-10 rounded-full border-2 border-gray-600 flex items-center justify-center text-gray-500 font-bold text-sm">
              2
            </div>
            <div className="h-8 w-0.5 bg-transparent" />
            <Link
              to="/artifacts"
              className="flex items-center gap-2 px-8 py-3 bg-sentinel-card hover:bg-sentinel-hover border border-sentinel-border text-gray-300 font-semibold rounded-lg transition-colors"
            >
              <ScanSearch className="w-5 h-5" />
              SETUP SCAN
              <ArrowRight className="w-4 h-4 ml-1" />
            </Link>
          </div>
        </div>

        {/* Preview screenshots area */}
        <div className="mt-6 w-full max-w-5xl grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Preview card 1 — Dashboard overview */}
          <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2 text-xs text-amber-500 font-bold">
              <div className="w-2 h-2 rounded-full bg-amber-500" />
              ERESUS SENTINEL
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="bg-sentinel-bg rounded p-2">
                <p className="text-[10px] text-gray-600">Total Probes</p>
                <p className="text-lg font-bold text-white">1,450</p>
              </div>
              <div className="bg-sentinel-bg rounded p-2">
                <p className="text-[10px] text-gray-600">Total Scans</p>
                <p className="text-lg font-bold text-white">250</p>
              </div>
              <div className="bg-sentinel-bg rounded p-2">
                <p className="text-[10px] text-gray-600">Detections</p>
                <p className="text-lg font-bold text-amber-500">91</p>
              </div>
            </div>
            {/* Mini chart placeholders */}
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-sentinel-bg rounded p-3 h-20 flex items-end gap-0.5">
                {[40, 65, 30, 80, 55, 70, 45, 60, 35, 75, 50, 85].map((h, i) => (
                  <div key={i} className="flex-1 bg-amber-500/60 rounded-t" style={{ height: `${h}%` }} />
                ))}
              </div>
              <div className="bg-sentinel-bg rounded p-3 h-20 flex items-end gap-0.5">
                {[20, 35, 55, 40, 60, 45, 30, 50, 65, 40, 55, 70].map((h, i) => (
                  <div key={i} className="flex-1 bg-green-500/60 rounded-t" style={{ height: `${h}%` }} />
                ))}
              </div>
            </div>
            <div className="bg-sentinel-bg rounded p-3 h-16 flex items-end gap-px">
              {Array.from({ length: 30 }, (_, i) => (
                <div key={i} className="flex-1 flex flex-col gap-px">
                  {Array.from({ length: 5 }, (_, j) => (
                    <div key={j} className={clsx(
                      'h-2 rounded-sm',
                      Math.random() > 0.5 ? 'bg-amber-500/40' : Math.random() > 0.7 ? 'bg-red-500/40' : 'bg-sentinel-border'
                    )} />
                  ))}
                </div>
              ))}
            </div>
          </div>

          {/* Preview card 2 — Report view */}
          <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-amber-500 font-bold">
                <div className="w-2 h-2 rounded-full bg-amber-500" />
                ERESUS SENTINEL
              </div>
              <span className="text-xs text-gray-500">Report 4031</span>
            </div>
            <div className="space-y-2">
              <div className="bg-sentinel-bg rounded p-2">
                <p className="text-[10px] text-gray-600">Vulnerabilities</p>
                <div className="flex gap-1 mt-1">
                  <span className="px-1.5 py-0.5 text-[9px] bg-red-500/20 text-red-400 rounded">CRITICAL: 3</span>
                  <span className="px-1.5 py-0.5 text-[9px] bg-amber-500/20 text-amber-400 rounded">HIGH: 12</span>
                  <span className="px-1.5 py-0.5 text-[9px] bg-yellow-500/20 text-yellow-400 rounded">MED: 28</span>
                </div>
              </div>
              <div className="bg-sentinel-bg rounded p-3 h-20 flex items-end gap-0.5">
                {[20, 45, 60, 35, 80, 55, 70, 90, 40, 65, 50, 75].map((h, i) => (
                  <div key={i} className="flex-1 bg-red-500/50 rounded-t" style={{ height: `${h}%` }} />
                ))}
              </div>
              <div className="bg-sentinel-bg rounded p-2">
                <p className="text-[10px] text-gray-600">Detector Statistics</p>
                <div className="mt-1 space-y-1">
                  {['Prompt Injection', 'Code Execution', 'Data Exfil', 'Model Tampering'].map((name) => (
                    <div key={name} className="flex items-center gap-2">
                      <span className="text-[9px] text-gray-500 w-24 truncate">{name}</span>
                      <div className="flex-1 h-1.5 bg-sentinel-border rounded-full overflow-hidden">
                        <div className="h-full bg-amber-500/60 rounded-full" style={{ width: `${30 + Math.random() * 60}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  // ── Active dashboard (has scan data) ───────────────────
  const blockRate = s.total_scans > 0 ? Math.round((s.blocked / s.total_scans) * 100 * 10) / 10 : 0

  return (
    <div className="space-y-5">
      {/* Section label */}
      <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
        <span>System Overview</span>
        <div className="flex-1 border-t border-sentinel-border ml-2" />
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="SCANS"
          value={s.total_scans}
          subtitle={`${scanners?.input_count ?? 0}in · ${scanners?.output_count ?? 0}out scanners`}
          icon={<Shield className="w-4 h-4 text-amber-500" />}
          iconBg=""
          delay={0}
        />
        <StatCard
          title="FINDINGS"
          value={s.total_findings}
          subtitle={`${s.artifact_findings} from artifacts`}
          icon={<AlertTriangle className="w-4 h-4 text-red-500" />}
          iconBg=""
          delay={60}
          highlight={s.total_findings > 0}
        />
        <StatCard
          title="BLOCK RATE"
          value={`${blockRate}%`}
          subtitle={`${s.blocked} blocked · ${s.clean} clean`}
          icon={<Ban className="w-4 h-4 text-amber-500" />}
          iconBg=""
          delay={120}
        />
        <StatCard
          title="ARTIFACTS"
          value={s.artifacts_scanned}
          subtitle={`${s.artifact_findings} findings`}
          icon={<FileWarning className="w-4 h-4 text-amber-500" />}
          iconBg=""
          delay={180}
          highlight={s.artifact_findings > 0}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 animate-fade-in-up" style={{ animationDelay: '240ms' }}>
          <div className="flex items-center gap-2 mb-3 text-xs text-gray-500 uppercase tracking-wider">
            <span>Severity Distribution</span>
          </div>
          <SeverityChart data={s.severity} />
        </div>
        <div className="lg:col-span-2 bg-sentinel-card border border-sentinel-border rounded-xl p-5 animate-fade-in-up" style={{ animationDelay: '300ms' }}>
          <div className="flex items-center gap-2 mb-3 text-xs text-gray-500 uppercase tracking-wider">
            <span>Scan Activity Timeline</span>
          </div>
          <TimelineChart data={s.timeline} />
        </div>
      </div>

      {/* Quick Actions */}
      <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
        <span>Quick Actions</span>
        <div className="flex-1 border-t border-sentinel-border ml-2" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { to: '/firewall', label: 'Firewall Scan', desc: 'Test prompts for injection threats', Icon: Shield, color: 'group-hover:border-amber-500/30' },
          { to: '/artifacts', label: 'Artifact Scan', desc: 'Upload and scan model files', Icon: FileWarning, color: 'group-hover:border-amber-500/30' },
          { href: '/api/docs', label: 'API Reference', desc: 'OpenAPI documentation', Icon: Terminal, color: 'group-hover:border-amber-500/30' },
        ].map((item) => {
          const Inner = (
            <div className={clsx(
              'flex items-center justify-between p-4 bg-sentinel-card border border-sentinel-border rounded-xl transition-colors animate-fade-in-up',
              item.color
            )}>
              <div className="flex items-center gap-3">
                <item.Icon className="w-5 h-5 text-gray-500 group-hover:text-amber-500 transition-colors" strokeWidth={1.5} />
                <div>
                  <p className="text-sm text-gray-300">{item.label}</p>
                  <p className="text-xs text-gray-600">{item.desc}</p>
                </div>
              </div>
              <ArrowRight className="w-3 h-3 text-gray-700" />
            </div>
          )

          if ('href' in item && item.href) {
            return (
              <a key={item.label} href={item.href} target="_blank" rel="noopener noreferrer" className="group">
                {Inner}
              </a>
            )
          }
          return (
            <Link key={item.label} to={item.to!} className="group">
              {Inner}
            </Link>
          )
        })}
      </div>

      {/* Scanner matrix */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 animate-fade-in-up" style={{ animationDelay: '400ms' }}>
        <div className="flex items-center gap-2 mb-3 text-xs text-gray-500 uppercase tracking-wider">
          <span>Active Scanners ({(scanners?.input_count ?? 0) + (scanners?.output_count ?? 0)})</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-1">
          {[...(scanners?.input ?? [])].map((name) => (
            <div key={`in-${name}`} className="flex items-center gap-2 px-2 py-1.5 text-xs">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full flex-shrink-0" />
              <span className="text-gray-500 truncate">{name}</span>
              <span className="text-gray-700 ml-auto text-[10px]">IN</span>
            </div>
          ))}
          {[...(scanners?.output ?? [])].map((name) => (
            <div key={`out-${name}`} className="flex items-center gap-2 px-2 py-1.5 text-xs">
              <span className="w-1.5 h-1.5 bg-amber-500 rounded-full flex-shrink-0" />
              <span className="text-gray-500 truncate">{name}</span>
              <span className="text-gray-700 ml-auto text-[10px]">OUT</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
