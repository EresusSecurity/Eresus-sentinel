import { NavLink, Outlet } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchHealth } from '../api/client'
import {
  LayoutDashboard,
  Shield,
  FileSearch,
  Clock,
  Menu,
  X,
  Code,
  Key,
  GitBranch,
  FileText,
  Bot,
  Link,
  Crosshair,
  LogOut,
  Settings,
  ChevronRight,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/firewall', label: 'Firewall', icon: Shield },
  { to: '/artifacts', label: 'Artifacts', icon: FileSearch },
  { to: '/sast', label: 'SAST', icon: Code },
  { to: '/secrets', label: 'Secrets', icon: Key },
  { to: '/diff', label: 'Diff Scan', icon: GitBranch },
  { to: '/notebook', label: 'Notebooks', icon: FileText },
  { to: '/agent', label: 'Agent / MCP', icon: Bot },
  { to: '/supply-chain', label: 'Supply Chain', icon: Link },
  { to: '/red-team', label: 'Red Team', icon: Crosshair },
  { to: '/history', label: 'History', icon: Clock },
]

export default function AppLayout() {
  const { logout } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    refetchInterval: 10_000,
  })

  return (
    <div className="flex min-h-screen bg-sentinel-bg text-gray-300">
      {/* ── Sidebar ──────────────────────────────────── */}
      <aside
        className={clsx(
          'fixed inset-y-0 left-0 z-50 w-56 bg-sentinel-card border-r border-sentinel-border flex flex-col transition-transform duration-200 lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Brand */}
        <div className="px-5 py-5">
          <h1 className="text-amber-500 text-lg font-bold tracking-wide">SENTINEL</h1>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 space-y-0.5 overflow-y-auto">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-150',
                  isActive
                    ? 'text-amber-500 bg-amber-500/10 border-l-3 border-amber-500'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.03] border-l-3 border-transparent'
                )
              }
            >
              <Icon className="w-[18px] h-[18px]" strokeWidth={1.5} />
              <span>{label}</span>
            </NavLink>
          ))}

          {/* Configuration expandable (visual only) */}
          <div className="pt-2">
            <a
              href="/api/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-gray-400 hover:text-gray-200 hover:bg-white/[0.03] transition-colors"
            >
              <Settings className="w-[18px] h-[18px]" strokeWidth={1.5} />
              <span>Configuration</span>
              <ChevronRight className="w-4 h-4 ml-auto text-gray-600" />
            </a>
          </div>
        </nav>

        {/* Bottom section */}
        <div className="px-3 pb-2 space-y-1">
          <div className="border-t border-sentinel-border pt-3 px-2 pb-2 space-y-2">
            <div className="flex items-center justify-between text-xs text-gray-500">
              <span>REPORTS RUNNING</span>
              <span className="bg-sentinel-border text-gray-400 text-[10px] px-1.5 py-0.5 rounded">
                {health?.scans_processed ?? 0}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs text-gray-500">
              <span>SYSTEM TOTAL</span>
              <span className="bg-sentinel-border text-gray-400 text-[10px] px-1.5 py-0.5 rounded">
                {health?.artifacts_processed ?? 0}
              </span>
            </div>
          </div>

          <button
            onClick={logout}
            className="flex items-center gap-3 w-full px-3 py-2.5 text-sm text-gray-500 hover:text-amber-500 hover:bg-amber-500/5 rounded-lg transition-colors"
          >
            <LogOut className="w-[18px] h-[18px]" strokeWidth={1.5} />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      {/* Mobile toggle */}
      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="lg:hidden fixed top-3 left-3 z-50 p-2 bg-sentinel-card border border-sentinel-border rounded-lg text-gray-500 hover:text-white"
      >
        {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {/* Backdrop */}
      {sidebarOpen && (
        <div
          className="lg:hidden fixed inset-0 z-40 bg-black/70"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* ── Main ─────────────────────────────────────── */}
      <main className="flex-1 lg:ml-56 min-h-screen flex flex-col">
        <div className="flex-1 p-6">
          <Outlet />
        </div>

        {/* Footer — version centered */}
        <footer className="py-3 text-center">
          <span className="text-amber-500/60 text-xs font-mono">{health?.version ?? '0.1.0'}</span>
        </footer>
      </main>
    </div>
  )
}
