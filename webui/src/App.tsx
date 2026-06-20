import { useEffect } from 'react'
import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import Chat from './pages/Chat'
import Cases from './pages/Cases'
import CaseDetail from './pages/CaseDetail'
import Settings from './pages/Settings'
import Tools from './pages/Tools'

const NAV = [
  { to: '/chat', label: 'Chat' },
  { to: '/cases', label: 'Cases' },
  { to: '/tools', label: 'Tools' },
  { to: '/settings', label: 'Settings' },
]

const THEME_STORAGE_KEY = 'argus-ui-theme'

function applyTheme(theme: string) {
  document.documentElement.dataset.theme = theme
}

export default function App() {
  useEffect(() => {
    applyTheme(localStorage.getItem(THEME_STORAGE_KEY) || 'graphite')

    const onThemeChange = (event: Event) => {
      const detail = (event as CustomEvent<string>).detail
      applyTheme(detail || localStorage.getItem(THEME_STORAGE_KEY) || 'graphite')
    }
    window.addEventListener('argus-theme-change', onThemeChange)
    return () => window.removeEventListener('argus-theme-change', onThemeChange)
  }, [])

  return (
    <div className="flex h-screen bg-zinc-950 text-zinc-100 overflow-hidden flex-col md:flex-row">
      <nav className="flex-none md:w-44 bg-zinc-900 border-b md:border-b-0 md:border-r border-zinc-800 flex md:flex-col p-2 md:p-4 gap-1 overflow-x-auto md:overflow-x-visible">
        <div className="text-blue-400 font-bold text-sm md:text-base px-2 md:mb-4 flex items-center whitespace-nowrap">
          Argus CTI
        </div>
        <div className="flex md:flex-col gap-1">
          {NAV.map(n => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) =>
                `px-3 py-2 rounded text-sm transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-blue-600 text-white'
                    : 'text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100'
                }`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </div>
      </nav>
      <main className="flex-1 overflow-hidden">
        <Routes>
          <Route path="/" element={<Navigate to="/chat" replace />} />
          <Route path="/chat" element={<Chat />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/cases/:id" element={<CaseDetail />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  )
}
