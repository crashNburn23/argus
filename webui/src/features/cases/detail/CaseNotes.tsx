import { useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { ChevronDown, ChevronRight, Plus } from 'lucide-react'
import Button from '../../../components/ui/Button'
import Textarea from '../../../components/ui/Textarea'
import {
  useAddNote,
  useAddObservables,
  useDeleteNote,
  useReanalyzeNote,
  useSubmitFeedback,
  useUpdateNote,
} from './queries'
import type { CaseNote, ObservableInput } from './types'

// ── IOC extraction ────────────────────────────────────────────────────────────

const IOC_PATTERNS: { type: string; re: RegExp }[] = [
  { type: 'ipv4', re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  { type: 'domain', re: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|info|biz|xyz|top|club|online|site|store|tech|app|dev|cloud|pro|us|ca|au|jp|fr|br|nl|se|no|fi|pl|ch|at|be|dk|cz|hu|ro|bg|gr|hr|sk|si|lt|lv|ee|lu|mt|cy|ie|pt|es|it)\b/gi },
  { type: 'url', re: /https?:\/\/[^\s"'<>]+/gi },
  { type: 'md5', re: /\b[a-f0-9]{32}\b/gi },
  { type: 'sha1', re: /\b[a-f0-9]{40}\b/gi },
  { type: 'sha256', re: /\b[a-f0-9]{64}\b/gi },
  { type: 'cve', re: /\bCVE-\d{4}-\d{4,7}\b/gi },
  { type: 'email', re: /\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b/gi },
]

// Map simple type names to the observable_type values the backend expects
const TYPE_MAP: Record<string, string> = {
  ipv4: 'ip',
  domain: 'domain',
  url: 'url',
  md5: 'md5',
  sha1: 'sha1',
  sha256: 'sha256',
  cve: 'cve',
  email: 'email',
}

interface ExtractedIoc {
  value: string
  type: string
  observableType: string
}

function extractIocs(text: string): ExtractedIoc[] {
  const seen = new Set<string>()
  const result: ExtractedIoc[] = []
  for (const { type, re } of IOC_PATTERNS) {
    const matches = text.match(re) ?? []
    for (const m of matches) {
      const key = `${type}:${m.toLowerCase()}`
      if (!seen.has(key)) {
        seen.add(key)
        result.push({ value: m, type, observableType: TYPE_MAP[type] ?? type })
      }
    }
  }
  return result
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function CaseNotes({ caseId, notes }: { caseId: string; notes: CaseNote[] }) {
  const [showCreate, setShowCreate] = useState(false)
  const [body, setBody] = useState('')
  const [editing, setEditing] = useState<CaseNote | null>(null)
  const [editBody, setEditBody] = useState('')
  const [correctionId, setCorrectionId] = useState<string | null>(null)
  const [correction, setCorrection] = useState('')
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null)

  // Analyst review state: noteId → draft review text
  const [reviewDraftId, setReviewDraftId] = useState<string | null>(null)
  const [reviewDraft, setReviewDraft] = useState('')

  // Re-analyze with feedback state
  const [reanalyzeFeedbackId, setReanalyzeFeedbackId] = useState<string | null>(null)
  const [reanalyzeFeedback, setReanalyzeFeedback] = useState('')

  // IOC extraction state
  const [iocPanelId, setIocPanelId] = useState<string | null>(null)
  const [selectedIocs, setSelectedIocs] = useState<Set<string>>(new Set())

  const addNote = useAddNote(caseId)
  const updateNote = useUpdateNote(caseId)
  const deleteNote = useDeleteNote(caseId)
  const reanalyzeNote = useReanalyzeNote(caseId)
  const submitFeedback = useSubmitFeedback(caseId)
  const addObservables = useAddObservables(caseId)

  const feedback = useMemo(
    () =>
      Object.fromEntries(
        notes.flatMap(note => {
          const value = note.metadata?.feedback
          return value === 'up' || value === 'down' ? [[note.note_id, value]] : []
        }),
      ),
    [notes],
  )

  const handleAdd = () => {
    const trimmed = body.trim()
    if (!trimmed) return
    addNote.mutate(trimmed, {
      onSuccess: () => {
        setBody('')
        setShowCreate(false)
      },
    })
  }

  const handleSave = () => {
    if (!editing) return
    updateNote.mutate(
      { noteId: editing.note_id, patch: { body: editBody.trim() } },
      { onSuccess: () => setEditing(null) },
    )
  }

  const handleDelete = (noteId: string) => {
    deleteNote.mutate(noteId, { onSuccess: () => setPendingDeleteId(null) })
  }

  const handleFeedback = (noteId: string, correct: boolean, text = '') => {
    submitFeedback.mutate(
      { noteId, correct, correction: text },
      {
        onSuccess: () => {
          setCorrectionId(null)
          setCorrection('')
        },
      },
    )
  }

  const handleSaveReview = (noteId: string) => {
    updateNote.mutate(
      { noteId, patch: { analyst_review: reviewDraft.trim() } },
      {
        onSuccess: () => {
          setReviewDraftId(null)
          setReviewDraft('')
        },
      },
    )
  }

  const handleReanalyze = (noteId: string, feedbackText?: string) => {
    reanalyzeNote.mutate(
      { noteId, feedback: feedbackText || undefined },
      {
        onSuccess: () => {
          setReanalyzeFeedbackId(null)
          setReanalyzeFeedback('')
        },
      },
    )
  }

  const openIocPanel = (note: CaseNote) => {
    const iocs = extractIocs(note.body)
    const allKeys = new Set(iocs.map(i => `${i.type}:${i.value}`))
    setSelectedIocs(allKeys)
    setIocPanelId(note.note_id)
  }

  const handleAddIocs = (note: CaseNote) => {
    const iocs = extractIocs(note.body)
    const toAdd: ObservableInput[] = iocs
      .filter(i => selectedIocs.has(`${i.type}:${i.value}`))
      .map(i => ({ value: i.value, observable_type: i.observableType }))
    if (!toAdd.length) return
    addObservables.mutate(toAdd, {
      onSuccess: () => {
        setIocPanelId(null)
        setSelectedIocs(new Set())
      },
    })
  }

  const mutationError =
    addNote.error ??
    updateNote.error ??
    deleteNote.error ??
    reanalyzeNote.error ??
    addObservables.error

  return (
    <div className="h-full overflow-y-auto bg-background">
      <div className="mx-auto max-w-4xl space-y-4 p-4 sm:p-6">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Notes ({notes.length})
          </span>
          <Button variant="secondary" size="sm" onClick={() => setShowCreate(v => !v)}>
            <Plus className="size-3.5" aria-hidden="true" />
            Add note
          </Button>
        </div>

        {showCreate && (
          <div className="space-y-3 rounded-xl border border-border bg-surface p-4">
            <Textarea
              rows={5}
              value={body}
              onChange={e => setBody(e.target.value)}
              autoFocus
              placeholder="Analyst note…"
            />
            <div className="flex gap-2">
              <Button onClick={handleAdd} disabled={!body.trim() || addNote.isPending}>
                {addNote.isPending ? 'Adding…' : 'Add note'}
              </Button>
              <Button variant="ghost" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {mutationError && (
          <p role="alert" className="text-sm text-danger">
            {(mutationError as Error).message ?? 'The note operation failed.'}
          </p>
        )}

        {notes.length === 0 ? (
          <p className="text-sm text-muted-foreground">No notes yet.</p>
        ) : (
          notes.map(note => {
            const manual = note.metadata?.source === 'manual'
            const review = note.metadata?.source === 'argus_review'
            const isEditing = editing?.note_id === note.note_id
            const isConfirmingDelete = pendingDeleteId === note.note_id
            const analystReview = (note.metadata?.analyst_review as string | undefined) ?? ''
            const detectedIocs = extractIocs(note.body)
            const showIocPanel = iocPanelId === note.note_id
            const showReviewDraft = reviewDraftId === note.note_id
            const showReanalyzeFeedback = reanalyzeFeedbackId === note.note_id

            return (
              <article key={note.note_id} className="rounded-xl border border-border bg-surface p-4">
                {/* ── Header ── */}
                <header className="mb-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  <span>{note.author}</span>
                  <span>·</span>
                  <time>{new Date(note.created_at).toLocaleString()}</time>
                  {manual && (
                    <span className="rounded bg-accent/10 px-1.5 py-0.5 text-accent">manual</span>
                  )}
                  {review && (
                    <span className="rounded bg-success/10 px-1.5 py-0.5 text-success">
                      Argus review
                    </span>
                  )}
                  <div className="ml-auto flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setEditing(note)
                        setEditBody(note.body)
                      }}
                    >
                      {isEditing ? 'Editing' : 'Edit'}
                    </Button>

                    {/* Extract IOCs button — shown when IOCs detected */}
                    {detectedIocs.length > 0 && !isEditing && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          showIocPanel ? setIocPanelId(null) : openIocPanel(note)
                        }
                      >
                        {showIocPanel ? (
                          <ChevronDown className="size-3 mr-1" />
                        ) : (
                          <ChevronRight className="size-3 mr-1" />
                        )}
                        IOCs ({detectedIocs.length})
                      </Button>
                    )}

                    {/* Re-analyze button with optional feedback */}
                    {manual && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={reanalyzeNote.isPending && reanalyzeNote.variables?.noteId === note.note_id}
                        onClick={() => {
                          if (showReanalyzeFeedback) {
                            setReanalyzeFeedbackId(null)
                          } else {
                            setReanalyzeFeedbackId(note.note_id)
                            setReanalyzeFeedback(analystReview)
                          }
                        }}
                      >
                        Re-analyze
                      </Button>
                    )}

                    {isConfirmingDelete ? (
                      <>
                        <Button
                          size="sm"
                          variant="danger"
                          disabled={deleteNote.isPending}
                          onClick={() => handleDelete(note.note_id)}
                        >
                          Confirm delete
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setPendingDeleteId(null)}
                        >
                          Cancel
                        </Button>
                      </>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="hover:text-danger"
                        onClick={() => setPendingDeleteId(note.note_id)}
                      >
                        Delete
                      </Button>
                    )}
                  </div>
                </header>

                {/* ── Body ── */}
                {isEditing ? (
                  <div className="space-y-2">
                    <Textarea
                      rows={6}
                      value={editBody}
                      onChange={e => setEditBody(e.target.value)}
                      autoFocus
                    />
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        onClick={handleSave}
                        disabled={!editBody.trim() || updateNote.isPending}
                      >
                        Save
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setEditing(null)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="prose prose-invert prose-sm max-w-none">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{note.body}</ReactMarkdown>
                  </div>
                )}

                {/* ── IOC extraction panel ── */}
                {showIocPanel && !isEditing && (
                  <div className="mt-3 border-t border-border pt-3 space-y-2">
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Detected IOCs — select to add to case
                    </p>
                    <div className="space-y-1">
                      {detectedIocs.map(ioc => {
                        const key = `${ioc.type}:${ioc.value}`
                        const checked = selectedIocs.has(key)
                        return (
                          <label key={key} className="flex items-center gap-2 text-sm cursor-pointer">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => {
                                setSelectedIocs(prev => {
                                  const next = new Set(prev)
                                  if (next.has(key)) next.delete(key)
                                  else next.add(key)
                                  return next
                                })
                              }}
                              className="rounded"
                            />
                            <span className="font-mono text-xs">{ioc.value}</span>
                            <span className="rounded bg-muted/30 px-1 py-0.5 text-[10px] text-muted-foreground">
                              {ioc.type}
                            </span>
                          </label>
                        )
                      })}
                    </div>
                    <div className="flex gap-2 pt-1">
                      <Button
                        size="sm"
                        onClick={() => handleAddIocs(note)}
                        disabled={selectedIocs.size === 0 || addObservables.isPending}
                      >
                        {addObservables.isPending ? 'Adding…' : `Add ${selectedIocs.size} to overview`}
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setIocPanelId(null)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}

                {/* ── Re-analyze with feedback panel ── */}
                {showReanalyzeFeedback && (
                  <div className="mt-3 border-t border-border pt-3 space-y-2">
                    <p className="text-xs text-muted-foreground">
                      Optional feedback / analyst review to guide re-analysis:
                    </p>
                    <Textarea
                      rows={3}
                      value={reanalyzeFeedback}
                      onChange={e => setReanalyzeFeedback(e.target.value)}
                      placeholder="E.g. Focus on the domain reputation. The IP belongs to a known CDN."
                    />
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        disabled={reanalyzeNote.isPending}
                        onClick={() => handleReanalyze(note.note_id, reanalyzeFeedback || undefined)}
                      >
                        {reanalyzeNote.isPending ? 'Re-analyzing…' : 'Re-analyze'}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setReanalyzeFeedbackId(null)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}

                {/* ── Analyst review section ── */}
                {!isEditing && (
                  <div className="mt-3 border-t border-border pt-3">
                    {analystReview && !showReviewDraft && (
                      <div className="mb-2 rounded-lg bg-accent/5 border border-accent/20 p-3">
                        <p className="text-xs font-medium text-accent mb-1 uppercase tracking-wider">
                          Analyst review
                        </p>
                        <p className="text-sm text-foreground whitespace-pre-wrap">{analystReview}</p>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="mt-2"
                          onClick={() => {
                            setReviewDraftId(note.note_id)
                            setReviewDraft(analystReview)
                          }}
                        >
                          Edit review
                        </Button>
                      </div>
                    )}

                    {showReviewDraft ? (
                      <div className="space-y-2">
                        <p className="text-xs text-muted-foreground">
                          Analyst review — included automatically in re-analysis and final reports
                        </p>
                        <Textarea
                          rows={3}
                          value={reviewDraft}
                          onChange={e => setReviewDraft(e.target.value)}
                          autoFocus
                          placeholder="Your assessment, corrections, or context about this note…"
                        />
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            onClick={() => handleSaveReview(note.note_id)}
                            disabled={updateNote.isPending}
                          >
                            Save review
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setReviewDraftId(null)}
                          >
                            Cancel
                          </Button>
                        </div>
                      </div>
                    ) : !analystReview ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-xs text-muted-foreground"
                        onClick={() => {
                          setReviewDraftId(note.note_id)
                          setReviewDraft('')
                        }}
                      >
                        + Add analyst review
                      </Button>
                    ) : null}
                  </div>
                )}

                {/* ── Argus review feedback section ── */}
                {review && !isEditing && (
                  <div className="mt-3 border-t border-border pt-3">
                    {correctionId === note.note_id ? (
                      <div className="space-y-2">
                        <Textarea
                          rows={2}
                          value={correction}
                          onChange={e => setCorrection(e.target.value)}
                          placeholder="What was wrong or missing?"
                        />
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            variant="danger"
                            disabled={submitFeedback.isPending}
                            onClick={() => handleFeedback(note.note_id, false, correction)}
                          >
                            Submit correction
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setCorrectionId(null)}
                          >
                            Cancel
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span>Helpful?</span>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={Boolean(feedback[note.note_id]) || submitFeedback.isPending}
                          onClick={() => handleFeedback(note.note_id, true)}
                        >
                          Yes
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={Boolean(feedback[note.note_id])}
                          onClick={() => setCorrectionId(note.note_id)}
                        >
                          No, correct it
                        </Button>
                        {feedback[note.note_id] && (
                          <span className="text-success">Feedback saved</span>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </article>
            )
          })
        )}
      </div>
    </div>
  )
}
