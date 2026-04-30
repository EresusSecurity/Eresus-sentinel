import { useState, useCallback, useEffect, type ReactNode } from 'react'
import axios from 'axios'
import { AuthContext, type AuthState } from './auth-context'

// Token stored in sessionStorage (cleared on tab close; harder to steal via XSS
// than localStorage because it is not persisted across sessions and is isolated
// per tab).  Non-sensitive auth state (user, role) kept in localStorage for UX.
const TOKEN_KEY = 'sentinel_token'
const AUTH_KEY = 'sentinel_auth'

function getToken(): string | null {
  // Prefer sessionStorage; fall back to localStorage for backwards compat then
  // migrate it to sessionStorage immediately.
  let token = sessionStorage.getItem(TOKEN_KEY)
  if (!token) {
    const legacy = localStorage.getItem(TOKEN_KEY)
    if (legacy) {
      sessionStorage.setItem(TOKEN_KEY, legacy)
      localStorage.removeItem(TOKEN_KEY)
      token = legacy
    }
  }
  return token
}

function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token)
  localStorage.removeItem(TOKEN_KEY) // ensure no stale copy
}

function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(TOKEN_KEY)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const saved = localStorage.getItem(AUTH_KEY)
    if (saved) {
      try { return JSON.parse(saved) } catch { /* ignore */ }
    }
    return { authenticated: false, user: '', role: '' }
  })

  // Set default auth header on mount if token exists
  useEffect(() => {
    const token = getToken()
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const { data } = await axios.post('/api/auth/login', { username, password })
    const token = data.token as string
    const user = data.user as string
    const role = data.role as string
    setToken(token)
    localStorage.setItem(AUTH_KEY, JSON.stringify({ authenticated: true, user, role }))
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    setState({ authenticated: true, user, role })
  }, [])

  const logout = useCallback(() => {
    clearToken()
    localStorage.removeItem(AUTH_KEY)
    delete axios.defaults.headers.common['Authorization']
    setState({ authenticated: false, user: '', role: '' })
  }, [])

  return (
    <AuthContext.Provider value={{ ...state, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}
