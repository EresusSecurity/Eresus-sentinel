import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react'
import axios from 'axios'

interface AuthState {
  authenticated: boolean
  user: string
  role: string
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

const TOKEN_KEY = 'sentinel_token'
const AUTH_KEY = 'sentinel_auth'

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
    const token = localStorage.getItem(TOKEN_KEY)
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const { data } = await axios.post('/api/auth/login', { username, password })
    const token = data.token as string
    const user = data.user as string
    const role = data.role as string
    localStorage.setItem(TOKEN_KEY, token)
    localStorage.setItem(AUTH_KEY, JSON.stringify({ authenticated: true, user, role }))
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    setState({ authenticated: true, user, role })
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
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

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
