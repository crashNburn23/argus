import { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import IocGraph from './IocGraph'

// ── Model types ────────────────────────────────────────────────────────────────

interface Observable {
  observable_id: string
  value: string
  observable_type: string
  labels: string[]
  confidence: number
  metadata: Record<string, unknown>
}

interface Note {
  note_id: string
  body: string
  author: string
  created_at: string
  metadata: Record<string, unknown>
}

interface Reference {
  ref_id: string
  url: string
  title: string
  added_by: string
  added_at: string
  needs_review: boolean
  metadata: Record<string, unknown>
}

interface ReportArtifact {
  report_id: string
  report_type: string
  title: string
  classification: string
  generated_at: string
  content: string
  metadata: Record<string, unknown>
}

interface PIR {
  question: string
  priority: string
}

interface CaseData {
  case_id: string
  title: string
  status: string
  classification: string
  description: string
  created_at: string
  updated_at: string
  observables: Observable[]
  notes: Note[]
  references: Reference[]
  reports: ReportArtifact[]
  pirs: PIR[]
  tags: string[]
}

interface ChatMessage {
  role: 'user' | 'assistant' | 'system'
  content: string
  streaming?: boolean
}

type TabId = 'overview' | 'chat' | 'notes' | 'references' | 'report' | 'graph'

// ── IOC auto-detection ─────────────────────────────────────────────────────────

function detectType(value: string): string {
  const v = value.trim()
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$/.test(v)) return 'ip'
  if (/^[a-fA-F0-9]{64}$/.test(v)) return 'sha256'
  if (/^[a-fA-F0-9]{40}$/.test(v)) return 'sha1'
  if (/^[a-fA-F0-9]{32}$/.test(v)) return 'md5'
  if (/^CVE-\d{4}-\d+$/i.test(v)) return 'cve'
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return 'email'
  if (/^https?:\/\//i.test(v)) return 'url'
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/.test(v)) return 'domain'
  return 'unknown'
}

function parseIOCText(text: string): Array<{ value: string; observable_type: string }> {
  return text
    .split(/[\n,;]+/)
    .map(s => s.trim())
    .filter(s => s.length > 0)
    .map(value => ({ value, observable_type: detectType(value) }))
}

// ── Constants ──────────────────────────────────────────────────────────────────

const STATUS_OPTIONS = ['open', 'active', 'monitoring', 'closed']

const AUDIENCE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'cti',       label: 'CTI Team — Intelligence Product' },
  { value: 'soc',       label: 'SOC / Detection Engineering' },
  { value: 'vm',        label: 'Vulnerability Management' },
  { value: 'ir',        label: 'Incident Response' },
  { value: 'exec',      label: 'Executive Leadership' },
  { value: 'awareness', label: 'Security Awareness / All Staff' },
  { value: 'redteam',   label: 'Red Team / Adversary Emulation' },
]

// ── Component ──────────────────────────────────────────────────────────────────

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const storageKey = `argus-chat-case-${id ?? ''}`

  const [caseData, setCaseData] = useState<CaseData | null>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<TabId>('overview')

  // IOC upload state
  const [iocText, setIocText] = useState('')
  const [iocPreview, setIocPreview] = useState<Array<{ value: string; observable_type: string }>>([])
  const [showIocForm, setShowIocForm] = useState(false)
  const [addingIOCs, setAddingIOCs] = useState(false)

  // Manual note state
  const [noteText, setNoteText] = useState('')
  const [addingNote, setAddingNote] = useState(false)
  const [showNoteForm, setShowNoteForm] = useState(false)

  // Note edit/delete/reanalyze state
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null)
  const [editNoteBody, setEditNoteBody] = useState('')
  const [savingNote, setSavingNote] = useState(false)
  const [deletingNoteId, setDeletingNoteId] = useState<string | null>(null)
  const [reanalyzingNoteId, setReanalyzingNoteId] = useState<string | null>(null)

  // Note feedback state (seeded from note metadata on load)
  const [feedbackMap, setFeedbackMap] = useState<Record<string, 'up' | 'down'>>({})
  const [correctionNoteId, setCorrectionNoteId] = useState<string | null>(null)
  const [correctionText, setCorrectionText] = useState('')

  // Review modal state
  const [showReviewModal, setShowReviewModal] = useState(false)
  const [selectedObsIds, setSelectedObsIds] = useState<Set<string>>(new Set())
  const [selectedNoteIds, setSelectedNoteIds] = useState<Set<string>>(new Set())
  const [selectedRefIds, setSelectedRefIds] = useState<Set<string>>(new Set())
  const [reviewing, setReviewing] = useState(false)
  const [reviewError, setReviewError] = useState('')

  // Reference state
  const [showRefForm, setShowRefForm] = useState(false)
  const [refUrl, setRefUrl] = useState('')
  const [refTitle, setRefTitle] = useState('')
  const [addingRef, setAddingRef] = useState(false)
  const [editingRefId, setEditingRefId] = useState<string | null>(null)
  const [editRefUrl, setEditRefUrl] = useState('')
  const [editRefTitle, setEditRefTitle] = useState('')
  const [savingRef, setSavingRef] = useState(false)
  const [deletingRefId, setDeletingRefId] = useState<string | null>(null)

  // Report state
  const [reportAudience, setReportAudience] = useState('cti')
  const [reportSpecialNotes, setReportSpecialNotes] = useState('')
  const [generatingReport, setGeneratingReport] = useState(false)
  const [activeReport, setActiveReport] = useState<ReportArtifact | null>(null)

  // Chat state
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    try {
      const raw = localStorage.getItem(`argus-chat-case-${id ?? ''}`)
      return raw ? (JSON.parse(raw) as ChatMessage[]) : []
    } catch {
      return []
    }
  })
  const [chatInput, setChatInput] = useState('')
  const [connected, setConnected] = useState(false)
  const [running, setRunning] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const progressRef = useRef('')

  // ── Data loading ─────────────────────────────────────────────────────────────

  const loadCase = useCallback(() => {
    if (!id) return
    fetch(`/api/cases/${id}`)
      .then(r => r.json())
      .then((data: CaseData) => {
        setCaseData(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [id])

  useEffect(() => { loadCase() }, [loadCase])

  // Seed feedbackMap from persisted note metadata whenever case data refreshes
  useEffect(() => {
    if (!caseData) return
    const initial: Record<string, 'up' | 'down'> = {}
    for (const n of caseData.notes) {
      const fb = n.metadata?.feedback
      if (fb === 'up' || fb === 'down') initial[n.note_id] = fb
    }
    if (Object.keys(initial).length > 0) {
      setFeedbackMap(prev => ({ ...initial, ...prev }))
    }
  }, [caseData])

  // ── Chat persistence ──────────────────────────────────────────────────────────

  useEffect(() => {
    const toSave = messages.filter(m => !m.streaming)
    localStorage.setItem(storageKey, JSON.stringify(toSave))
  }, [messages, storageKey])

  // ── WebSocket ─────────────────────────────────────────────────────────────────

  const connect = useCallback(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/api/chat/ws`)

    ws.onopen = () => setConnected(true)
    ws.onclose = () => { setConnected(false); setTimeout(connect, 3000) }
    ws.onerror = () => ws.close()

    ws.onmessage = (e: MessageEvent) => {
      const msg = JSON.parse(e.data as string) as { type: string; text: string }
      if (msg.type === 'progress') {
        progressRef.current += msg.text
        setMessages(prev => {
          const last = prev[prev.length - 1]
          if (last?.streaming) return [...prev.slice(0, -1), { ...last, content: progressRef.current }]
          return [...prev, { role: 'assistant', content: progressRef.current, streaming: true }]
        })
      } else if (msg.type === 'result') {
        progressRef.current = ''
        setMessages(prev => [...prev.filter(m => !m.streaming), { role: 'assistant', content: msg.text }])
        setRunning(false)
        loadCase()
      } else if (msg.type === 'error' || msg.type === 'cancelled') {
        progressRef.current = ''
        setMessages(prev => [...prev.filter(m => !m.streaming), { role: 'system', content: msg.text }])
        setRunning(false)
      }
    }

    wsRef.current = ws
  }, [loadCase])

  useEffect(() => {
    connect()
    return () => wsRef.current?.close()
  }, [connect])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // ── IOC preview ───────────────────────────────────────────────────────────────

  useEffect(() => {
    setIocPreview(iocText.trim() ? parseIOCText(iocText) : [])
  }, [iocText])

  // ── Review modal init ─────────────────────────────────────────────────────────

  const openReviewModal = () => {
    if (!caseData) return
    const obsIds = new Set(
      caseData.observables.filter(o => o.labels.includes('manually_added')).map(o => o.observable_id)
    )
    const noteIds = new Set(
      caseData.notes.filter(n => n.metadata?.source === 'manual').map(n => n.note_id)
    )
    const refIds = new Set(
      (caseData.references ?? []).filter(r => r.needs_review).map(r => r.ref_id)
    )
    setSelectedObsIds(obsIds)
    setSelectedNoteIds(noteIds)
    setSelectedRefIds(refIds)
    setReviewError('')
    setShowReviewModal(true)
  }

  // ── Actions ───────────────────────────────────────────────────────────────────

  const sendChat = () => {
    const text = chatInput.trim()
    if (!text || !connected || running) return
    setMessages(prev => [...prev, { role: 'user', content: text }])
    setChatInput('')
    setRunning(true)
    progressRef.current = ''
    wsRef.current?.send(JSON.stringify({ type: 'message', text, mode: 'case', case_id: id }))
  }

  const updateStatus = (status: string) => {
    if (!id) return
    fetch(`/api/cases/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    }).then(() => loadCase())
  }

  const submitIOCs = async () => {
    if (!id || iocPreview.length === 0) return
    setAddingIOCs(true)
    await fetch(`/api/cases/${id}/observables`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ observables: iocPreview }),
    })
    setIocText('')
    setShowIocForm(false)
    setAddingIOCs(false)
    loadCase()
  }

  const submitNote = async () => {
    if (!id || !noteText.trim()) return
    setAddingNote(true)
    await fetch(`/api/cases/${id}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: noteText.trim(), manually_added: true }),
    })
    setNoteText('')
    setShowNoteForm(false)
    setAddingNote(false)
    loadCase()
  }

  const startEditNote = (note: Note) => {
    setEditingNoteId(note.note_id)
    setEditNoteBody(note.body)
  }

  const saveNoteEdit = async () => {
    if (!id || !editingNoteId || !editNoteBody.trim()) return
    setSavingNote(true)
    await fetch(`/api/cases/${id}/notes/${editingNoteId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: editNoteBody.trim() }),
    })
    setEditingNoteId(null)
    setSavingNote(false)
    loadCase()
  }

  const deleteNote = async (noteId: string) => {
    if (!id || !confirm('Delete this note?')) return
    setDeletingNoteId(noteId)
    await fetch(`/api/cases/${id}/notes/${noteId}`, { method: 'DELETE' })
    setDeletingNoteId(null)
    loadCase()
  }

  const reanalyzeNote = async (noteId: string) => {
    if (!id) return
    setReanalyzingNoteId(noteId)
    await fetch(`/api/cases/${id}/notes/${noteId}/reanalyze`, { method: 'POST' })
    setReanalyzingNoteId(null)
    setActiveTab('notes')
    loadCase()
  }

  const submitFeedback = async (noteId: string, correct: boolean, correction = '') => {
    if (!id) return
    setFeedbackMap(prev => ({ ...prev, [noteId]: correct ? 'up' : 'down' }))
    setCorrectionNoteId(null)
    setCorrectionText('')
    await fetch(`/api/cases/${id}/notes/${noteId}/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ correct, correction }),
    })
  }

  const confirmReview = async () => {
    if (!id) return
    setShowReviewModal(false)  // close immediately — analysis runs in background
    setReviewing(true)
    setReviewError('')
    try {
      const r = await fetch(`/api/cases/${id}/review`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          observable_ids: [...selectedObsIds],
          note_ids: [...selectedNoteIds],
          reference_ids: [...selectedRefIds],
        }),
      })
      if (r.ok) {
        setActiveTab('notes')
        loadCase()
      } else {
        const err = (await r.json()) as { detail?: string }
        setReviewError(err.detail ?? 'Review failed')
      }
    } catch (e) {
      setReviewError('Network error — review may have timed out')
    } finally {
      setReviewing(false)
    }
  }

  // ── Reference actions ─────────────────────────────────────────────────────────

  const submitRef = async () => {
    if (!id || !refUrl.trim()) return
    setAddingRef(true)
    await fetch(`/api/cases/${id}/references`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: refUrl.trim(), title: refTitle.trim(), needs_review: true }),
    })
    setRefUrl('')
    setRefTitle('')
    setShowRefForm(false)
    setAddingRef(false)
    loadCase()
  }

  const startEditRef = (ref: Reference) => {
    setEditingRefId(ref.ref_id)
    setEditRefUrl(ref.url)
    setEditRefTitle(ref.title)
  }

  const saveRefEdit = async () => {
    if (!id || !editingRefId) return
    setSavingRef(true)
    await fetch(`/api/cases/${id}/references/${editingRefId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: editRefUrl.trim(), title: editRefTitle.trim() }),
    })
    setEditingRefId(null)
    setSavingRef(false)
    loadCase()
  }

  const markRefReviewed = async (refId: string) => {
    if (!id) return
    await fetch(`/api/cases/${id}/references/${refId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ needs_review: false }),
    })
    loadCase()
  }

  const deleteRef = async (refId: string) => {
    if (!id || !confirm('Delete this reference?')) return
    setDeletingRefId(refId)
    await fetch(`/api/cases/${id}/references/${refId}`, { method: 'DELETE' })
    setDeletingRefId(null)
    loadCase()
  }

  // ── Report actions ────────────────────────────────────────────────────────────

  const generateReport = async () => {
    if (!id) return
    setGeneratingReport(true)
    setActiveReport(null)
    const r = await fetch(`/api/cases/${id}/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ audience: reportAudience, special_notes: reportSpecialNotes }),
    })
    if (r.ok) {
      const artifact = await r.json() as ReportArtifact
      setActiveReport(artifact)
      loadCase()
    }
    setGeneratingReport(false)
  }

  const deleteReport = async (reportId: string) => {
    if (!id || !confirm('Delete this report?')) return
    await fetch(`/api/cases/${id}/reports/${reportId}`, { method: 'DELETE' })
    if (activeReport?.report_id === reportId) setActiveReport(null)
    loadCase()
  }

  // ── Render helpers ────────────────────────────────────────────────────────────

  const typeColor: Record<string, string> = {
    ip: 'bg-blue-900 text-blue-200',
    domain: 'bg-violet-900 text-violet-200',
    url: 'bg-indigo-900 text-indigo-200',
    sha256: 'bg-amber-900 text-amber-200',
    sha1: 'bg-amber-900 text-amber-200',
    md5: 'bg-amber-900 text-amber-200',
    cve: 'bg-red-900 text-red-200',
    email: 'bg-teal-900 text-teal-200',
    unknown: 'bg-zinc-800 text-zinc-400',
  }

  if (loading) return <div className="p-6 text-zinc-400 text-sm">Loading…</div>
  if (!caseData) return <div className="p-6 text-zinc-400 text-sm">Case not found.</div>

  const manualObs = caseData.observables.filter(o => o.labels.includes('manually_added'))
  const manualNotes = caseData.notes.filter(n => n.metadata?.source === 'manual')
  const pendingRefs = (caseData.references ?? []).filter(r => r.needs_review)
  const pendingRefCount = pendingRefs.length
  const reviewableCount = manualObs.length + manualNotes.length + pendingRefCount

  const tabs: Array<{ id: TabId; label: string }> = [
    { id: 'overview',   label: `Overview (${caseData.observables.length} IOCs)` },
    { id: 'graph',      label: 'Graph' },
    { id: 'chat',       label: 'Chat' },
    { id: 'notes',      label: `Notes (${caseData.notes.length})` },
    { id: 'references', label: `References (${(caseData.references ?? []).length})${pendingRefCount > 0 ? ` · ${pendingRefCount} new` : ''}` },
    { id: 'report',     label: `Report${(caseData.reports ?? []).length > 0 ? ` (${(caseData.reports ?? []).length})` : ''}` },
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* ── Review confirmation modal ── */}
      {showReviewModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-lg mx-4 max-h-[80vh] flex flex-col">
            <div className="px-5 py-4 border-b border-zinc-800">
              <h2 className="font-semibold text-zinc-100">Confirm Review Scope</h2>
              <p className="text-xs text-zinc-400 mt-0.5">Select which items to include in the Argus analysis.</p>
            </div>
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              {manualObs.length > 0 && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-zinc-500 uppercase tracking-wider">IOCs ({manualObs.length})</span>
                    <button
                      onClick={() => setSelectedObsIds(
                        selectedObsIds.size === manualObs.length ? new Set() : new Set(manualObs.map(o => o.observable_id))
                      )}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      {selectedObsIds.size === manualObs.length ? 'Deselect all' : 'Select all'}
                    </button>
                  </div>
                  <div className="space-y-1.5">
                    {manualObs.map(o => (
                      <label key={o.observable_id} className="flex items-center gap-2.5 cursor-pointer group">
                        <input
                          type="checkbox"
                          checked={selectedObsIds.has(o.observable_id)}
                          onChange={e => {
                            const next = new Set(selectedObsIds)
                            e.target.checked ? next.add(o.observable_id) : next.delete(o.observable_id)
                            setSelectedObsIds(next)
                          }}
                          className="accent-blue-500"
                        />
                        <span className={`text-xs px-1.5 py-0.5 rounded font-mono flex-none ${typeColor[o.observable_type] ?? typeColor.unknown}`}>
                          {o.observable_type}
                        </span>
                        <span className="text-sm font-mono text-zinc-300 truncate group-hover:text-zinc-100 transition-colors">{o.value}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
              {manualNotes.length > 0 && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-zinc-500 uppercase tracking-wider">Notes ({manualNotes.length})</span>
                    <button
                      onClick={() => setSelectedNoteIds(
                        selectedNoteIds.size === manualNotes.length ? new Set() : new Set(manualNotes.map(n => n.note_id))
                      )}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      {selectedNoteIds.size === manualNotes.length ? 'Deselect all' : 'Select all'}
                    </button>
                  </div>
                  <div className="space-y-1.5">
                    {manualNotes.map(n => (
                      <label key={n.note_id} className="flex items-start gap-2.5 cursor-pointer group">
                        <input
                          type="checkbox"
                          checked={selectedNoteIds.has(n.note_id)}
                          onChange={e => {
                            const next = new Set(selectedNoteIds)
                            e.target.checked ? next.add(n.note_id) : next.delete(n.note_id)
                            setSelectedNoteIds(next)
                          }}
                          className="accent-blue-500 mt-0.5"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-xs text-zinc-500">{n.author} · {new Date(n.created_at).toLocaleDateString()}</div>
                          <div className="text-sm text-zinc-300 truncate group-hover:text-zinc-100 transition-colors">
                            {n.body.slice(0, 120)}{n.body.length > 120 ? '…' : ''}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              )}
              {pendingRefs.length > 0 && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-zinc-500 uppercase tracking-wider">References — needs review ({pendingRefs.length})</span>
                    <button
                      onClick={() => setSelectedRefIds(
                        selectedRefIds.size === pendingRefs.length ? new Set() : new Set(pendingRefs.map(r => r.ref_id))
                      )}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      {selectedRefIds.size === pendingRefs.length ? 'Deselect all' : 'Select all'}
                    </button>
                  </div>
                  <div className="space-y-1.5">
                    {pendingRefs.map(r => (
                      <label key={r.ref_id} className="flex items-start gap-2.5 cursor-pointer group">
                        <input
                          type="checkbox"
                          checked={selectedRefIds.has(r.ref_id)}
                          onChange={e => {
                            const next = new Set(selectedRefIds)
                            e.target.checked ? next.add(r.ref_id) : next.delete(r.ref_id)
                            setSelectedRefIds(next)
                          }}
                          className="accent-blue-500 mt-0.5"
                        />
                        <div className="flex-1 min-w-0">
                          {r.title && <div className="text-xs text-zinc-400 truncate">{r.title}</div>}
                          <div className="text-xs font-mono text-blue-400 truncate group-hover:text-blue-300 transition-colors">{r.url}</div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
            <div className="px-5 py-4 border-t border-zinc-800 flex items-center justify-between">
              {reviewError && <span className="text-xs text-red-400">{reviewError}</span>}
              <div className="flex gap-2 ml-auto">
                <button
                  onClick={() => setShowReviewModal(false)}
                  className="px-4 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-sm transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={confirmReview}
                  disabled={selectedObsIds.size === 0 && selectedNoteIds.size === 0 && selectedRefIds.size === 0}
                  className="px-4 py-1.5 bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-white rounded text-sm transition-colors"
                >
                  {`Analyze ${selectedObsIds.size + selectedNoteIds.size + selectedRefIds.size} item(s)`}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Review status banner ── */}
      {reviewing && (
        <div className="flex-none px-6 py-2 bg-emerald-950 border-b border-emerald-800 flex items-center gap-3">
          <span className="animate-spin inline-block w-3.5 h-3.5 border border-emerald-400 border-t-transparent rounded-full flex-none" />
          <span className="text-sm text-emerald-300">Argus is analyzing — results will appear in Notes when complete.</span>
        </div>
      )}
      {reviewError && !reviewing && (
        <div className="flex-none px-6 py-2 bg-red-950 border-b border-red-800 flex items-center justify-between gap-3">
          <span className="text-sm text-red-300">{reviewError}</span>
          <button onClick={() => setReviewError('')} className="text-red-400 hover:text-red-200 text-xs flex-none">Dismiss</button>
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex-none px-6 py-4 border-b border-zinc-800 bg-zinc-900">
        <div className="flex items-center gap-2 text-xs text-zinc-500 mb-1">
          <Link to="/cases" className="hover:text-zinc-300 transition-colors">Cases</Link>
          <span>/</span>
          <span className="font-mono">{caseData.case_id.slice(0, 8)}</span>
        </div>
        <div className="flex items-center justify-between gap-4">
          <h1 className="font-semibold text-lg text-zinc-100 truncate">{caseData.title}</h1>
          <div className="flex items-center gap-2 flex-none">
            <button
              onClick={openReviewModal}
              disabled={reviewableCount === 0}
              title={reviewableCount === 0 ? 'Add IOCs or notes first' : `Review ${reviewableCount} manually-added item(s)`}
              className="px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-white rounded text-sm transition-colors"
            >
              Review ({reviewableCount})
            </button>
            <select
              value={caseData.status}
              onChange={e => updateStatus(e.target.value)}
              className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm text-zinc-200 outline-none focus:border-blue-500"
            >
              {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>
      </div>

      {/* ── Tab bar ── */}
      <div className="flex-none flex border-b border-zinc-800 bg-zinc-900 px-6">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2 text-sm border-b-2 transition-colors whitespace-nowrap ${
              activeTab === t.id
                ? 'border-blue-500 text-zinc-100'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Tab content ── */}
      <div className="flex-1 overflow-hidden">

        {/* OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="h-full overflow-y-auto p-6 space-y-6 max-w-4xl">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div><span className="text-zinc-400">Classification:</span><span className="ml-2">{caseData.classification}</span></div>
              <div><span className="text-zinc-400">Status:</span><span className="ml-2">{caseData.status}</span></div>
              <div><span className="text-zinc-400">Created:</span><span className="ml-2">{new Date(caseData.created_at).toLocaleString()}</span></div>
              <div><span className="text-zinc-400">Updated:</span><span className="ml-2">{new Date(caseData.updated_at).toLocaleString()}</span></div>
            </div>
            {caseData.description && (
              <div>
                <div className="text-xs text-zinc-500 mb-1 uppercase tracking-wider">Description</div>
                <p className="text-sm text-zinc-200">{caseData.description}</p>
              </div>
            )}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs text-zinc-500 uppercase tracking-wider">Observables ({caseData.observables.length})</div>
                <button
                  onClick={() => { setShowIocForm(v => !v); setIocText('') }}
                  className="text-xs px-2 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded transition-colors"
                >
                  {showIocForm ? 'Cancel' : '+ Add IOCs'}
                </button>
              </div>
              {showIocForm && (
                <div className="mb-3 bg-zinc-900 border border-zinc-700 rounded-lg p-4 space-y-3">
                  <p className="text-xs text-zinc-400">Paste IOCs — one per line, or comma/semicolon separated.</p>
                  <textarea
                    className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm font-mono text-zinc-100 outline-none focus:border-blue-500 resize-none"
                    rows={4}
                    placeholder={"1.2.3.4\nevil.example.com\nhttps://malware.site/payload"}
                    value={iocText}
                    onChange={e => setIocText(e.target.value)}
                    autoFocus
                  />
                  {iocPreview.length > 0 && (
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      <div className="text-xs text-zinc-500 mb-1">{iocPreview.length} IOC(s) detected:</div>
                      {iocPreview.map((item, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs">
                          <span className={`px-1.5 py-0.5 rounded font-mono flex-none ${typeColor[item.observable_type] ?? typeColor.unknown}`}>
                            {item.observable_type}
                          </span>
                          <span className="font-mono text-zinc-300 truncate">{item.value}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="flex gap-2">
                    <button
                      onClick={submitIOCs}
                      disabled={addingIOCs || iocPreview.length === 0}
                      className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
                    >
                      {addingIOCs ? 'Adding…' : `Add ${iocPreview.length} IOC(s)`}
                    </button>
                    <button
                      onClick={() => { setShowIocForm(false); setIocText('') }}
                      className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-sm transition-colors"
                    >Cancel</button>
                  </div>
                </div>
              )}
              {caseData.observables.length === 0 ? (
                <p className="text-sm text-zinc-600">No observables yet.</p>
              ) : (
                <div className="space-y-1.5">
                  {caseData.observables.map(o => (
                    <div key={o.observable_id} className="flex items-center gap-2 text-sm">
                      <span className={`text-xs px-1.5 py-0.5 rounded font-mono flex-none ${typeColor[o.observable_type] ?? typeColor.unknown}`}>
                        {o.observable_type}
                      </span>
                      <span className="font-mono text-zinc-200 break-all">{o.value}</span>
                      {o.labels.includes('manually_added') && (
                        <span className="text-xs bg-zinc-800 text-zinc-500 px-1.5 py-0.5 rounded flex-none">manual</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
            {caseData.pirs.length > 0 && (
              <div>
                <div className="text-xs text-zinc-500 mb-2 uppercase tracking-wider">PIRs</div>
                <ul className="space-y-1.5">
                  {caseData.pirs.map((p, i) => (
                    <li key={i} className="text-sm text-zinc-200 flex items-start gap-2">
                      <span className="text-zinc-600 flex-none">{i + 1}.</span>
                      <span>{p.question}</span>
                      {p.priority && <span className="text-xs text-zinc-500 ml-auto flex-none">{p.priority}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* GRAPH */}
        {activeTab === 'graph' && id && (
          <div className="h-full">
            <IocGraph caseId={id} key={`graph-${caseData.updated_at}`} />
          </div>
        )}

        {/* CHAT */}
        {activeTab === 'chat' && (
          <div className="flex flex-col h-full">
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.length === 0 && (
                <div className="text-center text-zinc-600 text-sm mt-12">
                  Ask Argus about this case. Responses are automatically saved as notes.
                </div>
              )}
              {messages.map((m, i) => (
                <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-3xl rounded-lg px-4 py-3 text-sm ${
                    m.role === 'user' ? 'bg-blue-600 text-white'
                    : m.role === 'system' ? 'bg-zinc-800 text-zinc-400 italic'
                    : 'bg-zinc-800 text-zinc-100'
                  }`}>
                    {m.role === 'user' ? (
                      <span className="whitespace-pre-wrap">{m.content}</span>
                    ) : (
                      <div className="prose prose-invert prose-sm max-w-none">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{m.content}</ReactMarkdown>
                      </div>
                    )}
                    {m.streaming && <span className="animate-pulse ml-1 text-zinc-400">▋</span>}
                  </div>
                </div>
              ))}
              <div ref={bottomRef} />
            </div>
            <div className="flex-none p-4 border-t border-zinc-800 bg-zinc-900">
              <div className="flex items-center gap-2 mb-2">
                <span className={`w-2 h-2 rounded-full flex-none ${connected ? 'bg-green-400' : 'bg-red-400'}`} />
                <span className="text-xs text-zinc-500">{connected ? 'connected' : 'reconnecting…'}</span>
              </div>
              <div className="flex gap-2">
                <textarea
                  className="flex-1 bg-zinc-800 text-zinc-100 rounded-lg px-3 py-2 text-sm resize-none outline-none border border-zinc-700 focus:border-blue-500 transition-colors"
                  rows={2}
                  value={chatInput}
                  onChange={e => setChatInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat() } }}
                  placeholder="Ask about this case… (Shift+Enter for newline)"
                  disabled={!connected}
                />
                {running ? (
                  <button
                    onClick={() => wsRef.current?.send(JSON.stringify({ type: 'cancel' }))}
                    className="px-4 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm transition-colors"
                  >Stop</button>
                ) : (
                  <button
                    onClick={sendChat}
                    disabled={!connected || !chatInput.trim()}
                    className="px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded-lg text-sm transition-colors"
                  >Send</button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* NOTES */}
        {activeTab === 'notes' && (
          <div className="h-full overflow-y-auto p-6 space-y-4 max-w-3xl">
            <div className="flex items-center justify-between">
              <span className="text-xs text-zinc-500 uppercase tracking-wider">Notes ({caseData.notes.length})</span>
              <button
                onClick={() => { setShowNoteForm(v => !v); setNoteText('') }}
                className="text-xs px-2 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded transition-colors"
              >
                {showNoteForm ? 'Cancel' : '+ Add Note'}
              </button>
            </div>
            {showNoteForm && (
              <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-4 space-y-3">
                <p className="text-xs text-zinc-400">This note will be marked as manually added.</p>
                <textarea
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500 resize-none"
                  rows={5}
                  placeholder="Paste intelligence, analyst observations, raw logs, etc."
                  value={noteText}
                  onChange={e => setNoteText(e.target.value)}
                  autoFocus
                />
                <div className="flex gap-2">
                  <button
                    onClick={submitNote}
                    disabled={addingNote || !noteText.trim()}
                    className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
                  >
                    {addingNote ? 'Saving…' : 'Save Note'}
                  </button>
                  <button
                    onClick={() => { setShowNoteForm(false); setNoteText('') }}
                    className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-sm transition-colors"
                  >Cancel</button>
                </div>
              </div>
            )}
            {caseData.notes.length === 0 ? (
              <div className="text-zinc-500 text-sm">No notes yet. Use the Chat tab or add one manually above.</div>
            ) : (
              caseData.notes.map(n => {
                const isManual = n.metadata?.source === 'manual'
                const isReview = n.metadata?.source === 'argus_review'
                const isReviewed = Boolean(n.metadata?.reviewed)
                const isEditing = editingNoteId === n.note_id
                const isReanalyzing = reanalyzingNoteId === n.note_id
                const isDeleting = deletingNoteId === n.note_id
                const feedback = feedbackMap[n.note_id]
                const inCorrectionMode = correctionNoteId === n.note_id
                return (
                  <div
                    key={n.note_id}
                    className={`bg-zinc-900 border rounded-lg p-4 ${
                      isReview ? 'border-emerald-800' : isManual ? 'border-blue-900' : 'border-zinc-800'
                    }`}
                  >
                    {/* Header */}
                    <div className="flex items-center gap-2 mb-3 flex-wrap">
                      <span className="text-xs text-zinc-500">{n.author}</span>
                      <span className="text-xs text-zinc-600">·</span>
                      <span className="text-xs text-zinc-500">{new Date(n.created_at).toLocaleString()}</span>
                      <div className="flex items-center gap-1.5 ml-auto flex-wrap">
                        {isManual && !isReviewed && (
                          <span className="text-xs bg-blue-900 text-blue-300 px-1.5 py-0.5 rounded">manually added</span>
                        )}
                        {isManual && isReviewed && (
                          <span className="text-xs bg-green-900 text-green-300 px-1.5 py-0.5 rounded">reviewed</span>
                        )}
                        {isReview && (
                          <span className="text-xs bg-emerald-900 text-emerald-300 px-1.5 py-0.5 rounded">argus review</span>
                        )}
                        {isManual && isReviewed && (
                          <button
                            onClick={() => reanalyzeNote(n.note_id)}
                            disabled={isReanalyzing}
                            className="text-xs px-2 py-0.5 bg-violet-900 hover:bg-violet-800 text-violet-200 rounded transition-colors flex items-center gap-1 disabled:opacity-40"
                          >
                            {isReanalyzing ? (
                              <><span className="animate-spin inline-block w-2.5 h-2.5 border border-violet-200 border-t-transparent rounded-full" /> Analyzing…</>
                            ) : 'Re-analyze'}
                          </button>
                        )}
                        <button
                          onClick={() => isEditing ? setEditingNoteId(null) : startEditNote(n)}
                          className="text-xs px-2 py-0.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 rounded transition-colors"
                        >
                          {isEditing ? 'Cancel' : 'Edit'}
                        </button>
                        <button
                          onClick={() => deleteNote(n.note_id)}
                          disabled={isDeleting}
                          className="text-xs px-2 py-0.5 bg-zinc-800 hover:bg-red-900 text-zinc-400 hover:text-red-300 rounded transition-colors disabled:opacity-40"
                        >
                          {isDeleting ? '…' : 'Delete'}
                        </button>
                      </div>
                    </div>

                    {/* Body / edit */}
                    {isEditing ? (
                      <div className="space-y-2">
                        <textarea
                          className="w-full bg-zinc-800 border border-zinc-600 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500 resize-none"
                          rows={6}
                          value={editNoteBody}
                          onChange={e => setEditNoteBody(e.target.value)}
                          autoFocus
                        />
                        <div className="flex gap-2">
                          <button
                            onClick={saveNoteEdit}
                            disabled={savingNote || !editNoteBody.trim()}
                            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
                          >
                            {savingNote ? 'Saving…' : 'Save'}
                          </button>
                          <button onClick={() => setEditingNoteId(null)} className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-sm transition-colors">Cancel</button>
                        </div>
                      </div>
                    ) : (
                      <div className="prose prose-invert prose-sm max-w-none">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{n.body}</ReactMarkdown>
                      </div>
                    )}

                    {/* Feedback row — only on argus review notes */}
                    {isReview && !isEditing && (
                      <div className="mt-3 pt-3 border-t border-zinc-800">
                        {inCorrectionMode ? (
                          <div className="space-y-2">
                            <textarea
                              className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-xs text-zinc-100 outline-none focus:border-blue-500 resize-none"
                              rows={2}
                              placeholder="What was wrong or missing? This will be used in future analyses."
                              value={correctionText}
                              onChange={e => setCorrectionText(e.target.value)}
                              autoFocus
                            />
                            <div className="flex gap-2">
                              <button
                                onClick={() => submitFeedback(n.note_id, false, correctionText)}
                                className="px-3 py-1 bg-red-900 hover:bg-red-800 text-red-200 rounded text-xs transition-colors"
                              >Submit correction</button>
                              <button
                                onClick={() => { setCorrectionNoteId(null); setCorrectionText('') }}
                                className="px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-400 rounded text-xs transition-colors"
                              >Cancel</button>
                            </div>
                          </div>
                        ) : (
                          <div className="flex items-center gap-3">
                            <span className="text-xs text-zinc-600">Was this analysis helpful?</span>
                            <button
                              onClick={() => submitFeedback(n.note_id, true)}
                              disabled={!!feedback}
                              className={`text-xs px-2 py-0.5 rounded transition-colors ${
                                feedback === 'up'
                                  ? 'bg-green-900 text-green-300'
                                  : 'bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-green-400 disabled:opacity-40'
                              }`}
                            >
                              {feedback === 'up' ? '✓ Yes' : '👍 Yes'}
                            </button>
                            <button
                              onClick={() => { setCorrectionNoteId(n.note_id); setCorrectionText('') }}
                              disabled={!!feedback}
                              className={`text-xs px-2 py-0.5 rounded transition-colors ${
                                feedback === 'down'
                                  ? 'bg-red-900 text-red-300'
                                  : 'bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-red-400 disabled:opacity-40'
                              }`}
                            >
                              {feedback === 'down' ? '✗ No' : '👎 No — add correction'}
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })
            )}
          </div>
        )}

        {/* REFERENCES */}
        {activeTab === 'references' && (
          <div className="h-full overflow-y-auto p-6 space-y-4 max-w-3xl">
            <div className="flex items-center justify-between">
              <span className="text-xs text-zinc-500 uppercase tracking-wider">
                References ({(caseData.references ?? []).length})
              </span>
              <button
                onClick={() => { setShowRefForm(v => !v); setRefUrl(''); setRefTitle('') }}
                className="text-xs px-2 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded transition-colors"
              >
                {showRefForm ? 'Cancel' : '+ Add Reference'}
              </button>
            </div>
            {showRefForm && (
              <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-4 space-y-3">
                <input
                  type="url"
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500"
                  placeholder="https://…"
                  value={refUrl}
                  onChange={e => setRefUrl(e.target.value)}
                  autoFocus
                />
                <input
                  type="text"
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500"
                  placeholder="Title or description (optional)"
                  value={refTitle}
                  onChange={e => setRefTitle(e.target.value)}
                />
                <div className="flex gap-2">
                  <button
                    onClick={submitRef}
                    disabled={addingRef || !refUrl.trim()}
                    className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
                  >
                    {addingRef ? 'Adding…' : 'Add Reference'}
                  </button>
                  <button
                    onClick={() => { setShowRefForm(false); setRefUrl(''); setRefTitle('') }}
                    className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-sm transition-colors"
                  >Cancel</button>
                </div>
              </div>
            )}
            {(caseData.references ?? []).length === 0 ? (
              <div className="text-zinc-500 text-sm">No references yet. Argus will auto-add URLs found during analysis.</div>
            ) : (
              (caseData.references ?? []).map(ref => {
                const isEditing = editingRefId === ref.ref_id
                const isDeleting = deletingRefId === ref.ref_id
                return (
                  <div
                    key={ref.ref_id}
                    className={`bg-zinc-900 border rounded-lg p-4 ${ref.needs_review ? 'border-amber-800' : 'border-zinc-800'}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        {isEditing ? (
                          <div className="space-y-2">
                            <input type="url" className="w-full bg-zinc-800 border border-zinc-600 rounded px-3 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500" value={editRefUrl} onChange={e => setEditRefUrl(e.target.value)} autoFocus />
                            <input type="text" className="w-full bg-zinc-800 border border-zinc-600 rounded px-3 py-1.5 text-sm text-zinc-100 outline-none focus:border-blue-500" placeholder="Title" value={editRefTitle} onChange={e => setEditRefTitle(e.target.value)} />
                            <div className="flex gap-2">
                              <button onClick={saveRefEdit} disabled={savingRef || !editRefUrl.trim()} className="px-3 py-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-xs transition-colors">{savingRef ? 'Saving…' : 'Save'}</button>
                              <button onClick={() => setEditingRefId(null)} className="px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-xs transition-colors">Cancel</button>
                            </div>
                          </div>
                        ) : (
                          <>
                            {ref.title && <div className="text-sm text-zinc-200 font-medium mb-0.5 truncate">{ref.title}</div>}
                            <a href={ref.url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:text-blue-300 break-all transition-colors">{ref.url}</a>
                            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                              <span className="text-xs text-zinc-600">{ref.added_by} · {new Date(ref.added_at).toLocaleDateString()}</span>
                              {ref.needs_review && <span className="text-xs bg-amber-900 text-amber-300 px-1.5 py-0.5 rounded">needs review</span>}
                            </div>
                          </>
                        )}
                      </div>
                      {!isEditing && (
                        <div className="flex items-center gap-1.5 flex-none">
                          {ref.needs_review && (
                            <button onClick={() => markRefReviewed(ref.ref_id)} className="text-xs px-2 py-0.5 bg-green-900 hover:bg-green-800 text-green-300 rounded transition-colors">Mark reviewed</button>
                          )}
                          <button onClick={() => startEditRef(ref)} className="text-xs px-2 py-0.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 rounded transition-colors">Edit</button>
                          <button onClick={() => deleteRef(ref.ref_id)} disabled={isDeleting} className="text-xs px-2 py-0.5 bg-zinc-800 hover:bg-red-900 text-zinc-400 hover:text-red-300 rounded transition-colors disabled:opacity-40">{isDeleting ? '…' : 'Delete'}</button>
                        </div>
                      )}
                    </div>
                  </div>
                )
              })
            )}
          </div>
        )}

        {/* REPORT */}
        {activeTab === 'report' && (
          <div className="h-full overflow-y-auto p-6 max-w-4xl">
            <div className="space-y-6">
              {/* Generation form */}
              <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-5 space-y-4">
                <div className="text-xs text-zinc-500 uppercase tracking-wider">Generate Intelligence Product</div>
                <div className="grid grid-cols-1 gap-4">
                  <div>
                    <label className="block text-xs text-zinc-400 mb-1.5">Audience</label>
                    <select
                      value={reportAudience}
                      onChange={e => setReportAudience(e.target.value)}
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500"
                    >
                      {AUDIENCE_OPTIONS.map(a => (
                        <option key={a.value} value={a.value}>{a.label}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-zinc-400 mb-1.5">
                      Special Notes for Analyst <span className="text-zinc-600">(optional — appended verbatim to report)</span>
                    </label>
                    <textarea
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500 resize-none"
                      rows={3}
                      placeholder="Caveats, additional context, distribution restrictions, known gaps, etc."
                      value={reportSpecialNotes}
                      onChange={e => setReportSpecialNotes(e.target.value)}
                    />
                  </div>
                </div>
                <button
                  onClick={generateReport}
                  disabled={generatingReport}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded text-sm transition-colors flex items-center gap-2"
                >
                  {generatingReport ? (
                    <>
                      <span className="animate-spin inline-block w-3.5 h-3.5 border border-white border-t-transparent rounded-full" />
                      Generating…
                    </>
                  ) : 'Generate Report'}
                </button>
              </div>

              {/* Generated output */}
              {activeReport && (
                <div className="bg-zinc-900 border border-zinc-700 rounded-lg">
                  <div className="px-5 py-3 border-b border-zinc-800 flex items-center justify-between">
                    <div>
                      <div className="text-sm font-medium text-zinc-100">{activeReport.title}</div>
                      <div className="text-xs text-zinc-500 mt-0.5">{activeReport.classification} · {new Date(activeReport.generated_at).toLocaleString()}</div>
                    </div>
                    <button
                      onClick={() => deleteReport(activeReport.report_id)}
                      className="text-xs px-2 py-0.5 bg-zinc-800 hover:bg-red-900 text-zinc-400 hover:text-red-300 rounded transition-colors flex-none"
                    >Delete</button>
                  </div>
                  <div className="p-5 prose prose-invert prose-sm max-w-none">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{activeReport.content}</ReactMarkdown>
                  </div>
                </div>
              )}

              {/* Saved reports */}
              {(caseData.reports ?? []).length > 0 && (
                <div>
                  <div className="text-xs text-zinc-500 uppercase tracking-wider mb-3">
                    Saved Reports ({(caseData.reports ?? []).length})
                  </div>
                  <div className="space-y-2">
                    {[...(caseData.reports ?? [])].reverse().map(r => (
                      <div
                        key={r.report_id}
                        className={`flex items-center justify-between gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                          activeReport?.report_id === r.report_id
                            ? 'border-blue-600 bg-zinc-800'
                            : 'border-zinc-800 bg-zinc-900 hover:border-zinc-700'
                        }`}
                        onClick={() => setActiveReport(activeReport?.report_id === r.report_id ? null : r)}
                      >
                        <div className="min-w-0">
                          <div className="text-sm text-zinc-200 truncate">{r.title}</div>
                          <div className="text-xs text-zinc-500 mt-0.5">{r.classification} · {new Date(r.generated_at).toLocaleString()}</div>
                        </div>
                        <button
                          onClick={e => { e.stopPropagation(); deleteReport(r.report_id) }}
                          className="text-xs px-2 py-0.5 bg-zinc-800 hover:bg-red-900 text-zinc-500 hover:text-red-300 rounded transition-colors flex-none"
                        >Delete</button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
