import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AppLayout from './layouts/AppLayout'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { lazy, Suspense } from 'react'

const LoginPage = lazy(() => import('./pages/LoginPage'))
const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const FirewallPage = lazy(() => import('./pages/FirewallPage'))
const ArtifactsPage = lazy(() => import('./pages/ArtifactsPage'))
const HistoryPage = lazy(() => import('./pages/HistoryPage'))
const SastPage = lazy(() => import('./pages/SastPage'))
const SecretsPage = lazy(() => import('./pages/SecretsPage'))
const DiffPage = lazy(() => import('./pages/DiffPage'))
const NotebookPage = lazy(() => import('./pages/NotebookPage'))
const AgentPage = lazy(() => import('./pages/AgentPage'))
const SupplyChainPage = lazy(() => import('./pages/SupplyChainPage'))
const RedTeamPage = lazy(() => import('./pages/RedTeamPage'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 10_000, retry: 1 },
  },
})

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-60">
      <div className="animate-spin w-6 h-6 border-2 border-red-500 border-t-transparent rounded-full" />
    </div>
  )
}

const P = ({ children }: { children: React.ReactNode }) => (
  <Suspense fallback={<PageLoader />}>{children}</Suspense>
)

function AppRoutes() {
  const { authenticated } = useAuth()

  if (!authenticated) {
    return (
      <Suspense fallback={<PageLoader />}>
        <LoginPage />
      </Suspense>
    )
  }

  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<P><DashboardPage /></P>} />
        <Route path="firewall" element={<P><FirewallPage /></P>} />
        <Route path="artifacts" element={<P><ArtifactsPage /></P>} />
        <Route path="history" element={<P><HistoryPage /></P>} />
        <Route path="sast" element={<P><SastPage /></P>} />
        <Route path="secrets" element={<P><SecretsPage /></P>} />
        <Route path="diff" element={<P><DiffPage /></P>} />
        <Route path="notebook" element={<P><NotebookPage /></P>} />
        <Route path="agent" element={<P><AgentPage /></P>} />
        <Route path="supply-chain" element={<P><SupplyChainPage /></P>} />
        <Route path="red-team" element={<P><RedTeamPage /></P>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  )
}

export default App
