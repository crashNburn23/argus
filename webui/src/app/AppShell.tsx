import { useEffect, useState, type ReactNode } from 'react'
import { BriefcaseBusiness, Eye, Menu, MessageSquare, Settings, Wrench, X, type LucideIcon } from 'lucide-react'
import { NavLink, useLocation } from 'react-router-dom'
import { useSettings } from '../features/settings/queries'
import { cn } from '../lib/cn'
import type { AppSettings } from '../features/settings/types'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
}

const NAV_ITEMS: NavItem[] = [
  { to: '/chat', label: 'Chat', icon: MessageSquare },
  { to: '/cases', label: 'Cases', icon: BriefcaseBusiness },
  { to: '/tools', label: 'Tools', icon: Wrench },
  { to: '/settings', label: 'Settings', icon: Settings },
]

function Sidebar({ onNavigate, settings }: { onNavigate?: () => void; settings?: AppSettings }) {
  return (
    <div className="flex h-full flex-col bg-sidebar text-sidebar-foreground">
      <div className="flex h-16 items-center gap-3 border-b border-sidebar-border px-4">
        <div className="flex size-9 items-center justify-center rounded-lg bg-accent text-accent-foreground shadow-sm">
          <Eye className="size-5" aria-hidden="true" />
        </div>
        <div>
          <div className="text-sm font-semibold tracking-wide">ARGUS</div>
          <div className="text-[11px] text-muted-foreground">Threat intelligence</div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 p-3" aria-label="Primary navigation">
        {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            onClick={onNavigate}
            className={({ isActive }) => cn(
              'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
              isActive
                ? 'bg-sidebar-active text-sidebar-active-foreground'
                : 'text-muted-foreground hover:bg-sidebar-hover hover:text-sidebar-foreground',
            )}
          >
            <Icon className="size-4" aria-hidden="true" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="space-y-2 border-t border-sidebar-border px-4 py-3 text-[11px] text-muted-foreground">
        {settings ? <>
          <div className="flex items-center justify-between gap-2">
            <span className="capitalize">{settings.model_provider}</span>
            <span className="truncate font-mono" title={settings.model}>{settings.model || 'No model'}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="size-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
            <span className="truncate capitalize">{settings.disclosure_mode.replace(/-/g, ' ')}</span>
          </div>
        </> : <span>Loading workspace…</span>}
      </div>
    </div>
  )
}

export default function AppShell({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false)
  const location = useLocation()
  const { data: settings } = useSettings()

  useEffect(() => setMobileOpen(false), [location.pathname])

  return (
    <div className="flex h-dvh overflow-hidden bg-background text-foreground">
      <aside className="hidden w-60 shrink-0 border-r border-sidebar-border lg:block">
        <Sidebar settings={settings} />
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation"
          />
          <aside className="relative h-full w-72 max-w-[85vw] border-r border-sidebar-border shadow-2xl">
            <Sidebar settings={settings} onNavigate={() => setMobileOpen(false)} />
            <button
              type="button"
              onClick={() => setMobileOpen(false)}
              className="absolute right-3 top-3 rounded-md p-2 text-muted-foreground hover:bg-sidebar-hover hover:text-foreground"
              aria-label="Close navigation"
            >
              <X className="size-4" aria-hidden="true" />
            </button>
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex h-14 shrink-0 items-center border-b border-border bg-surface px-3 lg:hidden">
          <button
            type="button"
            onClick={() => setMobileOpen(true)}
            className="rounded-md p-2 text-muted-foreground hover:bg-surface-raised hover:text-foreground"
            aria-label="Open navigation"
          >
            <Menu className="size-5" aria-hidden="true" />
          </button>
          <span className="ml-2 text-sm font-semibold tracking-wide">ARGUS</span>
        </div>
        <main className="min-h-0 flex-1 overflow-hidden">{children}</main>
      </div>
    </div>
  )
}
