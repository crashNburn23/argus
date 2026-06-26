import { useEffect, useState } from 'react'
import { cn } from '../../lib/cn'

const STORAGE_KEY = 'argus-ui-theme'

const THEMES = [
  { value: 'graphite', label: 'Graphite' },
  { value: 'midnight', label: 'Midnight' },
  { value: 'forest', label: 'Forest' },
  { value: 'ember', label: 'Ember' },
  { value: 'violet', label: 'Violet' },
  { value: 'teal', label: 'Teal' },
  { value: 'steel', label: 'Steel' },
  { value: 'light', label: 'Light' },
]

export default function AppearanceSettings() {
  const [theme, setTheme] = useState(() => localStorage.getItem(STORAGE_KEY) ?? 'graphite')

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem(STORAGE_KEY, theme)
    window.dispatchEvent(new CustomEvent('argus-theme-change', { detail: theme }))
  }, [theme])

  return (
    <section>
      <h2 className="mb-4 text-base font-semibold">Appearance</h2>
      <div className="divide-y divide-border rounded-lg border border-border bg-surface">
        <div className="flex items-center justify-between gap-4 px-4 py-3 sm:justify-start">
          <span className="text-sm text-muted-foreground sm:w-40 sm:shrink-0">Theme</span>
          <span className="font-mono text-sm text-foreground capitalize">{theme}</span>
        </div>
        <div className="px-4 py-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {THEMES.map(t => (
              <button
                key={t.value}
                type="button"
                onClick={() => setTheme(t.value)}
                className={cn(
                  'theme-swatch h-14 rounded border transition-colors',
                  `theme-swatch-${t.value}`,
                  theme === t.value
                    ? 'border-transparent ring-2 ring-accent'
                    : 'border-border',
                )}
                title={t.label}
              >
                <span className="theme-swatch-panel">
                  <span className="theme-swatch-text">{t.label}</span>
                  <span className="theme-swatch-bubbles" aria-hidden="true">
                    <span className="theme-swatch-bubble theme-swatch-bubble-bg" />
                    <span className="theme-swatch-bubble theme-swatch-bubble-panel" />
                    <span className="theme-swatch-bubble theme-swatch-bubble-border" />
                    <span className="theme-swatch-bubble theme-swatch-bubble-accent" />
                  </span>
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
