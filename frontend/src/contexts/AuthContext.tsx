import { useState, useCallback, useEffect, type ReactNode } from 'react'
import axios from 'axios'
import { AuthContext, type AuthState } from './auth-context'

const TOKEN_KEY = 'sentinel_token'
const AUTH_KEY = 'sentinel_auth'

function getToken(): string | null {
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
  localStorage.removeItem(TOKEN_KEY)
}

function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(TOKEN_KEY)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const token = getToken()
    if (!token) {
      localStorage.removeItem(AUTH_KEY)
      return { authenticated: false, user: '', role: '' }
    }
    const saved = localStorage.getItem(AUTH_KEY)
    if (saved) {
      try { return JSON.parse(saved) } catch { return { authenticated: false, user: '', role: '' } }
    }
    return { authenticated: false, user: '', role: '' }
  })

  useEffect(() => {
    const token = getToken()
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    }
  }, [])

  const applyAuthPayload = useCallback((data: { token: string; user: string; role: string }) => {
    const token = data.token as string
    const user = data.user as string
    const role = data.role as string
    setToken(token)
    localStorage.setItem(AUTH_KEY, JSON.stringify({ authenticated: true, user, role }))
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    setState({ authenticated: true, user, role })
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const { data } = await axios.post('/api/auth/login', { username, password })
    applyAuthPayload(data)
  }, [applyAuthPayload])

  const signup = useCallback(async (username: string, password: string) => {
    const { data } = await axios.post('/api/auth/signup', { username, password })
    applyAuthPayload(data)
  }, [applyAuthPayload])

  const logout = useCallback(() => {
    if (getToken()) {
      void axios.post('/api/auth/logout').catch(() => undefined)
    }
    clearToken()
    localStorage.removeItem(AUTH_KEY)
    delete axios.defaults.headers.common['Authorization']
    setState({ authenticated: false, user: '', role: '' })
  }, [])

  return (
    <AuthContext.Provider value={{ ...state, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  )
}
