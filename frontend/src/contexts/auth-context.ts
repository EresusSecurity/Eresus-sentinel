import { createContext } from 'react'

export interface AuthState {
  authenticated: boolean
  user: string
  role: string
}

export interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)
