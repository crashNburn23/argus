import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import AppShell from './app/AppShell'
import LoadingState from './components/LoadingState'

const Chat = lazy(() => import('./pages/Chat'))
const Cases = lazy(() => import('./pages/Cases'))
const CaseDetail = lazy(() => import('./pages/CaseDetail'))
const Settings = lazy(() => import('./pages/Settings'))
const Tools = lazy(() => import('./pages/Tools'))

export default function App() {
  return (
    <AppShell>
      <Suspense fallback={<LoadingState label="Loading workspace" />}>
        <Routes>
          <Route path="/" element={<Navigate to="/chat" replace />} />
          <Route path="/chat" element={<Chat />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/cases/:id" element={<CaseDetail />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </Suspense>
    </AppShell>
  )
}
