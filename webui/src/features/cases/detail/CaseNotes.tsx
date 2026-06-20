import { useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Plus } from 'lucide-react'
import Button from '../../../components/ui/Button'
import Textarea from '../../../components/ui/Textarea'
import {
  useAddNote,
  useDeleteNote,
  useReanalyzeNote,
  useSubmitFeedback,
  useUpdateNote,
} from './queries'
import type { CaseNote } from './types'

export default function CaseNotes({ caseId, notes }: { caseId: string; notes: CaseNote[] }) {
  const [showCreate, setShowCreate] = useState(false)
  const [body, setBody] = useState('')
  const [editing, setEditing] = useState<CaseNote | null>(null)
  const [editBody, setEditBody] = useState('')
  const [correctionId, setCorrectionId] = useState<string | null>(null)
  const [correction, setCorrection] = useState('')
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null)

  const addNote = useAddNote(caseId)
  const updateNote = useUpdateNote(caseId)
  const deleteNote = useDeleteNote(caseId)
  const reanalyzeNote = useReanalyzeNote(caseId)
  const submitFeedback = useSubmitFeedback(caseId)

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
      { noteId: editing.note_id, body: editBody.trim() },
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

  const mutationError = addNote.error ?? updateNote.error ?? deleteNote.error ?? reanalyzeNote.error

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

            return (
              <article key={note.note_id} className="rounded-xl border border-border bg-surface p-4">
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
                    {manual && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={
                          reanalyzeNote.isPending && reanalyzeNote.variables === note.note_id
                        }
                        onClick={() => reanalyzeNote.mutate(note.note_id)}
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
