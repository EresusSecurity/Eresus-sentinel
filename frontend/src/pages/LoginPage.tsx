import { useState, type FormEvent } from 'react'
import axios from 'axios'
import { AlertCircle, Loader2, LogIn, ShieldCheck, UserPlus } from 'lucide-react'
import { useAuth } from '../contexts/useAuth'

type AuthMode = 'signin' | 'signup'

export default function LoginPage() {
  const { login, signup } = useAuth()
  const [mode, setMode] = useState<AuthMode>('signin')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const isSignup = mode === 'signup'

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (isSignup) {
        await signup(username, password)
      } else {
        await login(username, password)
      }
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err)
        ? err.response?.data?.detail || err.message
        : err instanceof Error ? err.message : 'Authentication failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-950">
      <main className="mx-auto flex min-h-screen w-full max-w-6xl items-center justify-center px-4 py-10">
        <div className="grid w-full gap-8 lg:grid-cols-[0.95fr_1.05fr] lg:items-center">
          <section className="space-y-8">
            <div className="inline-flex h-14 w-14 items-center justify-center rounded-lg border border-amber-200 bg-amber-50 text-amber-700">
              <ShieldCheck className="h-7 w-7" aria-hidden="true" />
            </div>
            <div className="space-y-4">
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-amber-700">Eresus Sentinel</p>
              <h1 className="max-w-xl text-4xl font-semibold leading-tight tracking-normal text-slate-950 md:text-5xl">
                Deterministic security control plane for AI systems.
              </h1>
              <p className="max-w-xl text-base leading-7 text-slate-600">
                Sign in to run artifact scans, prompt firewall checks, MCP reviews, local SAST, supply-chain audits, and repeatable red-team playbooks.
              </p>
            </div>
            <div className="grid max-w-xl grid-cols-2 gap-3 text-sm">
              {['Artifact scanning', 'Prompt firewall', 'MCP review', 'Red-team plans'].map(item => (
                <div key={item} className="rounded-lg border border-slate-200 bg-white px-4 py-3 font-medium text-slate-700 shadow-sm">
                  {item}
                </div>
              ))}
            </div>
          </section>

          <section className="mx-auto w-full max-w-md rounded-lg border border-slate-200 bg-white p-6 shadow-xl shadow-slate-200/70">
            <div className="mb-6 flex rounded-lg border border-slate-200 bg-slate-100 p-1">
              <button
                type="button"
                onClick={() => {
                  setMode('signin')
                  setError('')
                }}
                className={`flex h-10 flex-1 items-center justify-center gap-2 rounded-md text-sm font-semibold transition ${
                  !isSignup ? 'bg-white text-slate-950 shadow-sm' : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                <LogIn className="h-4 w-4" aria-hidden="true" />
                Sign in
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode('signup')
                  setError('')
                }}
                className={`flex h-10 flex-1 items-center justify-center gap-2 rounded-md text-sm font-semibold transition ${
                  isSignup ? 'bg-white text-slate-950 shadow-sm' : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                <UserPlus className="h-4 w-4" aria-hidden="true" />
                Create account
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <h2 className="text-xl font-semibold text-slate-950">
                  {isSignup ? 'Create your workspace account' : 'Sign in to continue'}
                </h2>
                <p className="mt-2 text-sm leading-6 text-slate-500">
                  {isSignup
                    ? 'Signup is available when SENTINEL_ALLOW_SIGNUP=1 is enabled on the server.'
                    : 'Use your Sentinel credentials to unlock the local security console.'}
                </p>
              </div>

              {error && (
                <div className="flex gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-3 text-sm text-red-700">
                  <AlertCircle className="mt-0.5 h-4 w-4 flex-none" aria-hidden="true" />
                  <span>{error}</span>
                </div>
              )}

              <label className="block">
                <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                  Username
                </span>
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder="admin"
                  required
                  autoFocus
                  autoComplete="username"
                  className="h-12 w-full rounded-lg border border-slate-300 bg-white px-4 text-base text-slate-950 outline-none transition placeholder:text-slate-400 focus:border-amber-500 focus:ring-4 focus:ring-amber-100"
                />
              </label>

              <label className="block">
                <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                  Password
                </span>
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Minimum 8 characters"
                  required
                  autoComplete={isSignup ? 'new-password' : 'current-password'}
                  className="h-12 w-full rounded-lg border border-slate-300 bg-white px-4 text-base text-slate-950 outline-none transition placeholder:text-slate-400 focus:border-amber-500 focus:ring-4 focus:ring-amber-100"
                />
              </label>

              <button
                type="submit"
                disabled={loading || !username || !password}
                className="flex h-12 w-full items-center justify-center gap-2 rounded-lg bg-slate-950 px-4 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500 focus:outline-none focus:ring-4 focus:ring-slate-200"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                ) : isSignup ? (
                  <UserPlus className="h-4 w-4" aria-hidden="true" />
                ) : (
                  <LogIn className="h-4 w-4" aria-hidden="true" />
                )}
                {loading ? 'Working...' : isSignup ? 'Create account' : 'Sign in'}
              </button>
            </form>
          </section>
        </div>
      </main>
    </div>
  )
}
