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
  ChevronDown,
  Plug,
  Users,
  Database,
  Sun,
  Moon,
  HelpCircle,
  Cpu,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useState } from 'react'
import { useAuth } from '../contexts/useAuth'
import { useTheme } from '../contexts/useTheme'

const navGroups = [
  {
    label: 'Overview',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/history', label: 'History', icon: Clock },
    ],
  },
  {
    label: 'Firewall',
    items: [
      { to: '/firewall', label: 'Firewall', icon: Shield },
      { to: '/agent', label: 'Agent / MCP', icon: Bot },
      { to: '/mcp', label: 'MCP Scanner', icon: Plug },
      { to: '/a2a', label: 'A2A Scanner', icon: Users },
    ],
  },
  {
    label: 'Code & Files',
    items: [
      { to: '/sast', label: 'SAST', icon: Code },
      { to: '/secrets', label: 'Secrets', icon: Key },
      { to: '/diff', label: 'Diff Scan', icon: GitBranch },
      { to: '/notebook', label: 'Notebooks', icon: FileText },
    ],
  },
  {
    label: 'Models',
    items: [
      { to: '/models', label: 'Model Manager', icon: Cpu },
      { to: '/artifacts', label: 'Artifacts', icon: FileSearch },
      { to: '/hf-scan', label: 'HuggingFace', icon: Database },
      { to: '/aibom', label: 'AI BOM', icon: FileText },
    ],
  },
  {
    label: 'Advanced',
    items: [
      { to: '/red-team', label: 'EvalOps Lab', icon: Crosshair },
      { to: '/supply-chain', label: 'Supply Chain', icon: Link },
    ],
  },
]

export default function AppLayout() {
  const { logout, user } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    refetchInterval: 10_000,
  })

  return (
    <div className="flex min-h-screen bg-sentinel-bg text-gray-300">
      <aside
        className={clsx(
          'fixed inset-y-0 left-0 z-50 w-60 bg-sentinel-card border-r border-sentinel-border flex flex-col transition-transform duration-200 lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <div className="px-5 py-4 flex items-center justify-between border-b border-sentinel-border">
          <div>
            <h1 className="text-red-600 text-base font-bold tracking-wide">SENTINEL</h1>
            <p className="text-[9px] text-gray-600 uppercase tracking-widest mt-0.5">AI security workbench</p>
          </div>
          <button
            onClick={toggleTheme}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            className="p-1.5 rounded-lg text-gray-500 hover:text-blue-700 hover:bg-blue-50 transition-colors"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </div>

        <nav className="flex-1 px-2 py-3 overflow-y-auto space-y-4">
          {navGroups.map((group) => (
            <div key={group.label}>
              <p className="px-3 pb-1 text-[9px] text-gray-600 uppercase tracking-[0.18em]">
                {group.label}
              </p>
              <div className="space-y-0.5">
                {group.items.map(({ to, label, icon: Icon }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === '/'}
                    onClick={() => setSidebarOpen(false)}
                    className={({ isActive }) =>
                      clsx(
                        'flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] transition-all duration-150',
                        isActive
                          ? 'text-blue-700 bg-blue-50 ring-1 ring-blue-100 font-semibold'
                          : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.03]'
                      )
                    }
                  >
                    <Icon className="w-[16px] h-[16px] flex-shrink-0" strokeWidth={1.5} />
                    <span>{label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          ))}

          <div>
            <p className="px-3 pb-1 text-[9px] text-gray-600 uppercase tracking-[0.18em]">
              System
            </p>
            <button
              onClick={() => setSettingsOpen((o) => !o)}
              className="flex items-center gap-3 w-full px-3 py-2 rounded-lg text-[13px] text-gray-400 hover:text-gray-200 hover:bg-white/[0.03] transition-colors"
            >
              <Settings className="w-[16px] h-[16px]" strokeWidth={1.5} />
              <span>Settings</span>
              <ChevronDown
                className={clsx('w-3.5 h-3.5 ml-auto text-gray-600 transition-transform', settingsOpen && 'rotate-180')}
              />
            </button>
            {settingsOpen && (
              <div className="mt-1 mx-2 px-3 py-3 rounded-lg bg-sentinel-border/30 space-y-3 text-[11px]">
                <a
                  href="/api/docs"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-gray-400 hover:text-blue-700 transition-colors"
                >
                  <HelpCircle className="w-3.5 h-3.5" />
                  API Docs
                </a>
                <a
                  href="/api/redoc"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-gray-400 hover:text-blue-700 transition-colors"
                >
                  <FileText className="w-3.5 h-3.5" />
                  ReDoc
                </a>
                <div className="border-t border-sentinel-border pt-2 space-y-1">
                  <div className="flex justify-between text-gray-600">
                    <span>Version</span>
                    <span className="font-mono text-blue-700">{health?.version ?? '—'}</span>
                  </div>
                  <div className="flex justify-between text-gray-600">
                    <span>Scans run</span>
                    <span className="font-mono">{health?.scans_processed ?? 0}</span>
                  </div>
                  <div className="flex justify-between text-gray-600">
                    <span>Artifacts</span>
                    <span className="font-mono">{health?.artifacts_processed ?? 0}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </nav>

        <div className="px-3 pb-3 border-t border-sentinel-border pt-3 space-y-1">
          {user && (
            <div className="px-3 py-2 rounded-lg bg-sentinel-border/20">
              <p className="text-[10px] text-gray-600 uppercase tracking-wider">Signed in as</p>
              <p className="text-[12px] text-gray-300 font-medium truncate mt-0.5">{user}</p>
            </div>
          )}
          <button
            onClick={logout}
            className="flex items-center gap-3 w-full px-3 py-2 text-[13px] text-gray-500 hover:text-red-400 hover:bg-red-500/5 rounded-lg transition-colors"
          >
            <LogOut className="w-[16px] h-[16px]" strokeWidth={1.5} />
            <span>Sign out</span>
          </button>
        </div>
      </aside>

      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="lg:hidden fixed top-3 left-3 z-50 p-2 bg-sentinel-card border border-sentinel-border rounded-lg text-gray-500 hover:text-blue-700"
      >
        {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {sidebarOpen && (
        <div
          className="lg:hidden fixed inset-0 z-40 bg-black/70"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <main className="flex-1 lg:ml-60 min-h-screen flex flex-col">
        <div className="flex-1 p-6">
          <Outlet />
        </div>

        <footer className="py-3 text-center">
          <span className="text-gray-500 text-xs font-mono">{health?.version ?? '0.1.0'}</span>
        </footer>
      </main>
    </div>
  )
}
