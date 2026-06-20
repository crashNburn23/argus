import { useState, useEffect } from 'react'

interface AppSettings {
  model_provider: string
  model: string
  disclosure_mode: string
  log_level: string
  ollama_base_url: string
  cases_dir: string
  reports_dir: string
  db_path: string
  model_options: Record<string, string[]>
  api_keys_configured: Record<string, boolean>
}

interface Tool {
  name: string
  available: boolean
  reason?: string
}

interface Agent {
  name: string
  description: string
  tools: string[]
}

const ANTHROPIC_MODELS = [
  'claude-sonnet-4-6',
  'claude-opus-4-8',
  'claude-haiku-4-5-20251001',
]

const LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
const DISCLOSURE_MODES = ['unrestricted', 'confirm-external', 'local-only']
const THEME_STORAGE_KEY = 'argus-ui-theme'
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

const API_KEY_FIELDS: Array<[string, string, string]> = [
  ['anthropic_api_key', 'Anthropic', 'anthropic'],
  ['virustotal_api_key', 'VirusTotal', 'virustotal'],
  ['shodan_api_key', 'Shodan', 'shodan'],
  ['recorded_future_api_key', 'Recorded Future', 'recorded_future'],
  ['otx_api_key', 'AlienVault OTX', 'otx'],
  ['abuseipdb_api_key', 'AbuseIPDB', 'abuseipdb'],
  ['misp_api_key', 'MISP', 'misp'],
]

function modelListForProvider(settings: AppSettings | null, provider: string) {
  return settings?.model_options?.[provider] ?? (provider === 'anthropic' ? ANTHROPIC_MODELS : [])
}

export default function Settings() {
  const [settings, setSettings] = useState<AppSettings | null>(null)
  const [tools, setTools] = useState<Tool[]>([])
  const [agents, setAgents] = useState<Agent[]>([])
  const [loading, setLoading] = useState(true)

  // General settings edit state
  const [editingGeneral, setEditingGeneral] = useState(false)
  const [form, setForm] = useState<Record<string, string>>({})
  const [savingGeneral, setSavingGeneral] = useState(false)
  const [savedGeneral, setSavedGeneral] = useState(false)
  const [theme, setTheme] = useState(() => localStorage.getItem(THEME_STORAGE_KEY) || 'graphite')

  // API keys edit state
  const [keyForm, setKeyForm] = useState<Record<string, string>>({})
  const [savingKeys, setSavingKeys] = useState(false)
  const [savedKeys, setSavedKeys] = useState(false)
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({})

  const load = async () => {
    try {
      const [s, t, a] = await Promise.all([
        fetch('/api/settings').then(r => r.json() as Promise<AppSettings>),
        fetch('/api/tools').then(r => r.json() as Promise<Tool[]>),
        fetch('/api/agents').then(r => r.json() as Promise<Agent[]>),
      ])
      setSettings(s)
      setTools(t)
      setAgents(a)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem(THEME_STORAGE_KEY, theme)
    window.dispatchEvent(new CustomEvent('argus-theme-change', { detail: theme }))
  }, [theme])

  const startEditGeneral = () => {
    if (!settings) return
    setForm({
      model_provider: settings.model_provider,
      model: settings.model,
      disclosure_mode: settings.disclosure_mode,
      log_level: settings.log_level,
      ollama_base_url: settings.ollama_base_url,
    })
    setEditingGeneral(true)
    setSavedGeneral(false)
  }

  const saveGeneral = async () => {
    setSavingGeneral(true)
    const r = await fetch('/api/settings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(form),
    })
    const updated = (await r.json()) as AppSettings
    setSettings(updated)
    setEditingGeneral(false)
    setSavingGeneral(false)
    setSavedGeneral(true)
    setTimeout(() => setSavedGeneral(false), 2000)
  }

  const saveKeys = async () => {
    const payload: Record<string, string> = {}
    for (const [field, , ] of API_KEY_FIELDS) {
      const val = keyForm[field]
      if (val?.trim()) payload[field] = val.trim()
    }
    if (Object.keys(payload).length === 0) return
    setSavingKeys(true)
    const r = await fetch('/api/settings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const updated = (await r.json()) as AppSettings
    setSettings(updated)
    setKeyForm({})
    setSavingKeys(false)
    setSavedKeys(true)
    setTimeout(() => setSavedKeys(false), 2000)
  }

  const modelSuggestions = modelListForProvider(settings, form.model_provider)
  const modelOptions =
    form.model && form.model_provider !== 'ollama' && !modelSuggestions.includes(form.model)
      ? [form.model, ...modelSuggestions]
      : modelSuggestions
  const hasModelOptions = modelOptions.length > 0

  if (loading) return <div className="p-6 text-zinc-400 text-sm">Loading…</div>
  if (!settings) return <div className="p-6 text-zinc-400 text-sm">Failed to load settings.</div>

  return (
    <div className="h-full overflow-y-auto p-6 max-w-3xl mx-auto space-y-8">
      {/* General settings */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-semibold">Settings</h1>
          <div className="flex items-center gap-3">
            {savedGeneral && <span className="text-xs text-green-400">Saved</span>}
            {!editingGeneral ? (
              <button
                onClick={startEditGeneral}
                className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded text-sm transition-colors"
              >
                Edit
              </button>
            ) : (
              <div className="flex gap-2">
                <button
                  onClick={saveGeneral}
                  disabled={savingGeneral || !form.model}
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
                >
                  Save
                </button>
                <button
                  onClick={() => setEditingGeneral(false)}
                  className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded text-sm transition-colors"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-lg divide-y divide-zinc-800">
          {/* Model Provider */}
          <div className="flex items-center px-4 py-3 gap-4">
            <span className="text-sm text-zinc-400 w-44 flex-none">Model Provider</span>
            {editingGeneral ? (
              <select
                className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500"
                value={form.model_provider}
                onChange={e => {
                  const provider = e.target.value
                  setForm(f => ({ ...f, model_provider: provider, model: modelListForProvider(settings, provider)[0] ?? '' }))
                }}
              >
                <option value="anthropic">anthropic</option>
                <option value="ollama">ollama</option>
              </select>
            ) : (
              <span className="text-sm text-zinc-200 font-mono">{settings.model_provider}</span>
            )}
          </div>

          {/* Model */}
          <div className="flex items-center px-4 py-3 gap-4">
            <span className="text-sm text-zinc-400 w-44 flex-none">Model</span>
            {editingGeneral ? (
              <select
                className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500"
                value={form.model || modelOptions[0] || ''}
                onChange={e => setForm(f => ({ ...f, model: e.target.value }))}
                disabled={!hasModelOptions}
              >
                {hasModelOptions ? (
                  modelOptions.map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))
                ) : (
                  <option value="">No models found</option>
                )}
              </select>
            ) : (
              <span className="text-sm text-zinc-200 font-mono">{settings.model || '—'}</span>
            )}
          </div>

          {/* Disclosure Mode */}
          <div className="flex items-center px-4 py-3 gap-4">
            <span className="text-sm text-zinc-400 w-44 flex-none">Disclosure Mode</span>
            {editingGeneral ? (
              <select
                className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500"
                value={form.disclosure_mode}
                onChange={e => setForm(f => ({ ...f, disclosure_mode: e.target.value }))}
              >
                {DISCLOSURE_MODES.map(m => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            ) : (
              <span className="text-sm text-zinc-200 font-mono">{settings.disclosure_mode}</span>
            )}
          </div>

          {/* Log Level */}
          <div className="flex items-center px-4 py-3 gap-4">
            <span className="text-sm text-zinc-400 w-44 flex-none">Log Level</span>
            {editingGeneral ? (
              <select
                className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500"
                value={form.log_level}
                onChange={e => setForm(f => ({ ...f, log_level: e.target.value }))}
              >
                {LOG_LEVELS.map(l => (
                  <option key={l} value={l}>{l}</option>
                ))}
              </select>
            ) : (
              <span className="text-sm text-zinc-200 font-mono">{settings.log_level}</span>
            )}
          </div>

          {/* Ollama URL — only shown when provider is ollama */}
          {(editingGeneral ? form.model_provider === 'ollama' : settings.model_provider === 'ollama') && (
            <div className="flex items-center px-4 py-3 gap-4">
              <span className="text-sm text-zinc-400 w-44 flex-none">Ollama URL</span>
              {editingGeneral ? (
                <input
                  className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500"
                  value={form.ollama_base_url}
                  onChange={e => setForm(f => ({ ...f, ollama_base_url: e.target.value }))}
                />
              ) : (
                <span className="text-sm text-zinc-200 font-mono">{settings.ollama_base_url || '—'}</span>
              )}
            </div>
          )}

          {/* Read-only paths */}
          {[
            ['Cases Dir', settings.cases_dir],
            ['Reports Dir', settings.reports_dir],
            ['DB Path', settings.db_path],
          ].map(([label, val]) => (
            <div key={label} className="flex items-center px-4 py-3 gap-4">
              <span className="text-sm text-zinc-400 w-44 flex-none">{label}</span>
              <span className="text-sm text-zinc-500 font-mono truncate">{val}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Appearance */}
      <div>
        <h2 className="text-base font-semibold mb-3">Appearance</h2>
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg divide-y divide-zinc-800">
          <div className="flex items-center px-4 py-3 gap-4">
            <span className="text-sm text-zinc-400 w-44 flex-none">Theme</span>
            <select
              className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500"
              value={theme}
              onChange={e => setTheme(e.target.value)}
            >
              {THEMES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          </div>
          <div className="px-4 py-3">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {THEMES.map(t => (
                <button
                  key={t.value}
                  onClick={() => setTheme(t.value)}
                  className={`h-14 rounded border transition-colors theme-swatch theme-swatch-${t.value} ${
                    theme === t.value ? 'ring-2 ring-blue-500 border-transparent' : 'border-zinc-700'
                  }`}
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
      </div>

      {/* API Keys */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold">API Keys</h2>
          <div className="flex items-center gap-3">
            {savedKeys && <span className="text-xs text-green-400">Saved</span>}
            <button
              onClick={saveKeys}
              disabled={savingKeys || Object.values(keyForm).every(v => !v?.trim())}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
            >
              Save Keys
            </button>
          </div>
        </div>
        <p className="text-xs text-zinc-500 mb-3">
          Leave a field blank to keep the existing key. Values are written to <span className="font-mono">.env</span>.
        </p>
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg divide-y divide-zinc-800">
          {API_KEY_FIELDS.map(([field, label, statusKey]) => {
            const configured = settings.api_keys_configured[statusKey] ?? false
            const isVisible = showKeys[field] ?? false
            return (
              <div key={field} className="flex items-center px-4 py-3 gap-3">
                <span className="text-sm text-zinc-400 w-36 flex-none">{label}</span>
                <span
                  className={`text-xs px-2 py-0.5 rounded-full flex-none ${
                    configured ? 'bg-green-900 text-green-300' : 'bg-zinc-800 text-zinc-500'
                  }`}
                >
                  {configured ? 'set' : 'not set'}
                </span>
                <div className="flex-1 flex items-center gap-1">
                  <input
                    type={isVisible ? 'text' : 'password'}
                    className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500 font-mono transition-colors"
                    placeholder={configured ? '••••••••  (leave blank to keep)' : 'Enter API key…'}
                    value={keyForm[field] ?? ''}
                    onChange={e => setKeyForm(f => ({ ...f, [field]: e.target.value }))}
                    autoComplete="off"
                  />
                  <button
                    onClick={() => setShowKeys(s => ({ ...s, [field]: !s[field] }))}
                    className="text-xs text-zinc-500 hover:text-zinc-300 px-2 py-1 flex-none"
                    title={isVisible ? 'Hide' : 'Show'}
                  >
                    {isVisible ? '🙈' : '👁'}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Tools */}
      <div>
        <h2 className="text-base font-semibold mb-3">Tools</h2>
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg divide-y divide-zinc-800">
          {tools.length === 0 && (
            <div className="px-4 py-3 text-sm text-zinc-500">No tools registered.</div>
          )}
          {tools.map(t => (
            <div key={t.name} className="flex items-center px-4 py-3 gap-3">
              <span className="text-sm text-zinc-200 w-48 flex-none font-mono">{t.name}</span>
              <span
                className={`text-xs px-2 py-0.5 rounded-full flex-none ${
                  t.available ? 'bg-green-900 text-green-300' : 'bg-zinc-800 text-zinc-500'
                }`}
              >
                {t.available ? 'available' : 'unavailable'}
              </span>
              {t.reason && <span className="text-xs text-zinc-500">{t.reason}</span>}
            </div>
          ))}
        </div>
      </div>

      {/* Agents */}
      <div>
        <h2 className="text-base font-semibold mb-3">Agents</h2>
        <div className="space-y-2">
          {agents.map(a => (
            <div key={a.name} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <div className="font-medium text-sm capitalize mb-1">{a.name}</div>
              <div className="text-xs text-zinc-400 mb-2">{a.description}</div>
              <div className="flex flex-wrap gap-1">
                {a.tools.map(t => (
                  <span
                    key={t}
                    className="text-xs bg-zinc-800 text-zinc-300 px-2 py-0.5 rounded font-mono"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
