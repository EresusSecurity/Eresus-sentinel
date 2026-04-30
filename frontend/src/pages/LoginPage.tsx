import { useState, type FormEvent } from 'react'
import axios from 'axios'
import { useAuth } from '../contexts/useAuth'
import { Shield } from 'lucide-react'

export default function LoginPage() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
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
    <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center p-4">
      {/* Background grid effect */}
      <div className="fixed inset-0 opacity-5">
        <div className="absolute inset-0" style={{
          backgroundImage: 'linear-gradient(rgba(245,158,11,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(245,158,11,0.3) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }} />
      </div>

      <div className="relative w-full max-w-md">
        {/* Logo section */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/20 mb-4">
            <Shield className="w-8 h-8 text-amber-500" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">ERESUS</h1>
          <p className="text-amber-500 text-sm font-mono tracking-[0.3em] mt-1">SENTINEL</p>
          <p className="text-zinc-500 text-xs mt-3">AI/LLM Security Platform</p>
        </div>

        {/* Login card */}
        <form onSubmit={handleSubmit}
          className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-8 backdrop-blur-sm shadow-2xl shadow-red-500/5"
        >
          <h2 className="text-lg font-semibold text-zinc-200 mb-6">Sign in to continue</h2>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="admin"
                required
                autoFocus
                autoComplete="username"
                className="w-full px-4 py-3 bg-zinc-800/50 border border-zinc-700 rounded-lg
                           text-zinc-100 placeholder-zinc-600
                           focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/30
                           transition-all"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5 uppercase tracking-wider">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                autoComplete="current-password"
                className="w-full px-4 py-3 bg-zinc-800/50 border border-zinc-700 rounded-lg
                           text-zinc-100 placeholder-zinc-600
                           focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/30
                           transition-all"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || !username || !password}
            className="mt-6 w-full py-3 px-4 bg-amber-600 hover:bg-amber-500 disabled:bg-zinc-700 disabled:text-zinc-500
                       text-white font-medium rounded-lg transition-colors
                       focus:outline-none focus:ring-2 focus:ring-amber-500/50 focus:ring-offset-2 focus:ring-offset-zinc-900"
          >
            {loading ? (
              <span className="inline-flex items-center gap-2">
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Authenticating...
              </span>
            ) : (
              'Sign In'
            )}
          </button>

          <div className="mt-4 pt-4 border-t border-zinc-800">
            <p className="text-zinc-600 text-xs text-center">
              Set <code className="text-zinc-500">SENTINEL_USER</code> and <code className="text-zinc-500">SENTINEL_PASSWORD</code> env vars to configure credentials
            </p>
          </div>
        </form>

        {/* Footer */}
        <p className="text-center text-zinc-600 text-xs mt-6 font-mono">
          v0.1.0 · Eresus Security
        </p>
      </div>
    </div>
  )
}
