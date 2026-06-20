import { useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Plus } from 'lucide-react'
import Button from '../../../components/ui/Button'
import Textarea from '../../../components/ui/Textarea'
import { caseDetailApi } from './api'
import type { CaseNote } from './types'

export default function CaseNotes({ caseId, notes, onCaseChanged }: { caseId: string; notes: CaseNote[]; onCaseChanged: () => void }) {
  const [showCreate, setShowCreate] = useState(false)
  const [body, setBody] = useState('')
  const [editing, setEditing] = useState<CaseNote | null>(null)
  const [editBody, setEditBody] = useState('')
  const [busyId, setBusyId] = useState<string | null>(null)
  const [correctionId, setCorrectionId] = useState<string | null>(null)
  const [correction, setCorrection] = useState('')
  const [error, setError] = useState('')
  const feedback = useMemo(() => Object.fromEntries(notes.flatMap(note => {
    const value = note.metadata?.feedback
    return value === 'up' || value === 'down' ? [[note.note_id, value]] : []
  })), [notes])

  const run = async (id: string, action: () => Promise<unknown>) => {
    setBusyId(id); setError('')
    try { await action(); onCaseChanged() } catch { setError('The note operation failed.') } finally { setBusyId(null) }
  }

  const add = () => run('create', async () => {
    await caseDetailApi.addNote(caseId, body.trim())
    setBody(''); setShowCreate(false)
  })

  const save = () => editing && run(editing.note_id, async () => {
    await caseDetailApi.updateNote(caseId, editing.note_id, editBody.trim())
    setEditing(null)
  })

  const remove = (noteId: string) => {
    if (confirm('Delete this note?')) void run(noteId, () => caseDetailApi.deleteNote(caseId, noteId))
  }

  const submitFeedback = async (noteId: string, correct: boolean, text = '') => {
    setBusyId(noteId)
    try { await caseDetailApi.submitFeedback(caseId, noteId, correct, text); setCorrectionId(null); setCorrection(''); onCaseChanged() }
    catch { setError('Feedback could not be saved.') } finally { setBusyId(null) }
  }

  return (
    <div className="h-full overflow-y-auto bg-background">
      <div className="mx-auto max-w-4xl space-y-4 p-4 sm:p-6">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Notes ({notes.length})</span>
          <Button variant="secondary" size="sm" onClick={() => setShowCreate(value => !value)}><Plus className="size-3.5" />Add note</Button>
        </div>
        {showCreate && <div className="space-y-3 rounded-xl border border-border bg-surface p-4"><Textarea rows={5} value={body} onChange={event => setBody(event.target.value)} autoFocus placeholder="Analyst note…" /><div className="flex gap-2"><Button onClick={() => void add()} disabled={!body.trim() || busyId === 'create'}>{busyId === 'create' ? 'Adding…' : 'Add note'}</Button><Button variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button></div></div>}
        {error && <p role="alert" className="text-sm text-danger">{error}</p>}
        {notes.length === 0 ? <p className="text-sm text-muted-foreground">No notes yet.</p> : notes.map(note => {
          const manual = note.metadata?.source === 'manual'
          const review = note.metadata?.source === 'argus_review'
          const isEditing = editing?.note_id === note.note_id
          return <article key={note.note_id} className="rounded-xl border border-border bg-surface p-4">
            <header className="mb-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground"><span>{note.author}</span><span>·</span><time>{new Date(note.created_at).toLocaleString()}</time>{manual && <span className="rounded bg-accent/10 px-1.5 py-0.5 text-accent">manual</span>}{review && <span className="rounded bg-success/10 px-1.5 py-0.5 text-success">Argus review</span>}<div className="ml-auto flex gap-1"><Button variant="ghost" size="sm" onClick={() => { setEditing(note); setEditBody(note.body) }}>{isEditing ? 'Editing' : 'Edit'}</Button>{manual && <Button variant="ghost" size="sm" disabled={busyId === note.note_id} onClick={() => void run(note.note_id, () => caseDetailApi.reanalyzeNote(caseId, note.note_id))}>Re-analyze</Button>}<Button variant="ghost" size="sm" disabled={busyId === note.note_id} className="hover:text-danger" onClick={() => remove(note.note_id)}>Delete</Button></div></header>
            {isEditing ? <div className="space-y-2"><Textarea rows={6} value={editBody} onChange={event => setEditBody(event.target.value)} autoFocus /><div className="flex gap-2"><Button size="sm" onClick={() => void save()} disabled={!editBody.trim() || busyId === note.note_id}>Save</Button><Button size="sm" variant="ghost" onClick={() => setEditing(null)}>Cancel</Button></div></div> : <div className="prose prose-invert prose-sm max-w-none"><ReactMarkdown remarkPlugins={[remarkGfm]}>{note.body}</ReactMarkdown></div>}
            {review && !isEditing && <div className="mt-3 border-t border-border pt-3">{correctionId === note.note_id ? <div className="space-y-2"><Textarea rows={2} value={correction} onChange={event => setCorrection(event.target.value)} placeholder="What was wrong or missing?" /><div className="flex gap-2"><Button size="sm" variant="danger" onClick={() => void submitFeedback(note.note_id, false, correction)}>Submit correction</Button><Button size="sm" variant="ghost" onClick={() => setCorrectionId(null)}>Cancel</Button></div></div> : <div className="flex items-center gap-2 text-xs text-muted-foreground"><span>Helpful?</span><Button size="sm" variant="ghost" disabled={Boolean(feedback[note.note_id])} onClick={() => void submitFeedback(note.note_id, true)}>Yes</Button><Button size="sm" variant="ghost" disabled={Boolean(feedback[note.note_id])} onClick={() => setCorrectionId(note.note_id)}>No, correct it</Button>{feedback[note.note_id] && <span className="text-success">Feedback saved</span>}</div>}</div>}
          </article>
        })}
      </div>
    </div>
  )
}
