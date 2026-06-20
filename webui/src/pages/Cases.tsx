import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

interface CaseSummary {
  case_id: string
  title: string
  status: string
  classification: string
  description: string
  created_at: string
  updated_at: string
  observable_count: number
  note_count: number
  tags: string[]
}

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-blue-700 text-blue-100',
  investigating: 'bg-yellow-700 text-yellow-100',
  escalated: 'bg-orange-700 text-orange-100',
  closed: 'bg-zinc-700 text-zinc-300',
  false_positive: 'bg-green-800 text-green-200',
}

export default function Cases() {
  const [cases, setCases] = useState<CaseSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [showNew, setShowNew] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [creating, setCreating] = useState(false)
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [sortBy, setSortBy] = useState<'updated' | 'created' | 'title'>('updated')

  const load = () => {
    setLoading(true)
    fetch('/api/cases')
      .then(r => r.json())
      .then((data: CaseSummary[]) => {
        setCases(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  const createCase = async () => {
    if (!newTitle.trim()) return
    setCreating(true)
    await fetch('/api/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: newTitle.trim(), description: newDesc.trim() }),
    })
    setNewTitle('')
    setNewDesc('')
    setShowNew(false)
    setCreating(false)
    load()
  }

  const statuses = Array.from(new Set(cases.map(c => c.status))).sort()
  const visibleCases = cases
    .filter(c => {
      const q = query.trim().toLowerCase()
      const matchesQuery =
        !q ||
        c.title.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.case_id.toLowerCase().includes(q) ||
        c.tags.some(t => t.toLowerCase().includes(q))
      const matchesStatus = statusFilter === 'all' || c.status === statusFilter
      return matchesQuery && matchesStatus
    })
    .sort((a, b) => {
      if (sortBy === 'title') return a.title.localeCompare(b.title)
      const field = sortBy === 'created' ? 'created_at' : 'updated_at'
      return new Date(b[field]).getTime() - new Date(a[field]).getTime()
    })

  return (
    <div className="p-4 md:p-6 max-w-6xl mx-auto h-full overflow-y-auto">
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between mb-5">
        <div>
          <h1 className="text-xl font-semibold">Cases</h1>
          <div className="text-xs text-zinc-500 mt-1">{cases.length} total · {visibleCases.length} shown</div>
        </div>
        <button
          onClick={() => setShowNew(v => !v)}
          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm transition-colors self-start md:self-auto"
        >
          + New Case
        </button>
      </div>

      <div className="mb-4 grid grid-cols-1 md:grid-cols-[1fr_12rem_12rem] gap-2">
        <input
          className="bg-zinc-900 border border-zinc-800 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500"
          placeholder="Search title, description, tag, or case ID"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
        <select
          className="bg-zinc-900 border border-zinc-800 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500"
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
        >
          <option value="all">All statuses</option>
          {statuses.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          className="bg-zinc-900 border border-zinc-800 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500"
          value={sortBy}
          onChange={e => setSortBy(e.target.value as 'updated' | 'created' | 'title')}
        >
          <option value="updated">Recently updated</option>
          <option value="created">Recently created</option>
          <option value="title">Title A-Z</option>
        </select>
      </div>

      {showNew && (
        <div className="mb-6 bg-zinc-900 border border-zinc-700 rounded p-4 space-y-3">
          <h2 className="font-medium text-sm text-zinc-300">New Case</h2>
          <input
            className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm outline-none focus:border-blue-500 transition-colors"
            placeholder="Title"
            value={newTitle}
            onChange={e => setNewTitle(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && createCase()}
            autoFocus
          />
          <textarea
            className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm outline-none focus:border-blue-500 resize-none transition-colors"
            placeholder="Description (optional)"
            rows={2}
            value={newDesc}
            onChange={e => setNewDesc(e.target.value)}
          />
          <div className="flex gap-2">
            <button
              onClick={createCase}
              disabled={creating || !newTitle.trim()}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
            >
              Create
            </button>
            <button
              onClick={() => setShowNew(false)}
              className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-sm transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="text-zinc-400 text-sm">Loading…</div>
      ) : cases.length === 0 ? (
        <div className="text-zinc-500 text-sm">No cases yet. Create one to get started.</div>
      ) : visibleCases.length === 0 ? (
        <div className="text-zinc-500 text-sm">No cases match the current filters.</div>
      ) : (
        <div className="space-y-2">
          {visibleCases.map(c => (
            <Link
              key={c.case_id}
              to={`/cases/${c.case_id}`}
              className="block bg-zinc-900 border border-zinc-800 rounded p-4 hover:border-zinc-600 hover:bg-zinc-900/80 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full ${STATUS_COLORS[c.status] ?? 'bg-zinc-700 text-zinc-300'}`}
                    >
                      {c.status}
                    </span>
                    <span className="text-xs text-zinc-500">{c.classification}</span>
                    <span className="text-xs text-zinc-600 font-mono">{c.case_id.slice(0, 8)}</span>
                  </div>
                  <div className="font-medium text-sm text-zinc-100 truncate">{c.title}</div>
                  {c.description && (
                    <div className="text-xs text-zinc-400 mt-1 truncate">{c.description}</div>
                  )}
                  {c.tags.length > 0 && (
                    <div className="flex gap-1 mt-2 flex-wrap">
                      {c.tags.map(t => (
                        <span
                          key={t}
                          className="text-xs bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex-none text-xs text-zinc-500 text-right space-y-1">
                  <div>{c.observable_count} IOCs · {c.note_count} notes</div>
                  <div>{new Date(c.updated_at).toLocaleDateString()}</div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
