import { useState } from 'react'
import { ExternalLink, Plus } from 'lucide-react'
import Button from '../../../components/ui/Button'
import Input from '../../../components/ui/Input'
import { caseDetailApi } from './api'
import type { CaseReference } from './types'

export default function CaseReferences({ caseId, references, onCaseChanged }: { caseId: string; references: CaseReference[]; onCaseChanged: () => void }) {
  const [showForm, setShowForm] = useState(false)
  const [url, setUrl] = useState('')
  const [title, setTitle] = useState('')
  const [editing, setEditing] = useState<CaseReference | null>(null)
  const [editUrl, setEditUrl] = useState('')
  const [editTitle, setEditTitle] = useState('')
  const [busyId, setBusyId] = useState<string | null>(null)
  const [error, setError] = useState('')

  const run = async (id: string, action: () => Promise<unknown>, after?: () => void) => {
    setBusyId(id); setError('')
    try { await action(); after?.(); onCaseChanged() } catch { setError('The reference operation failed.') } finally { setBusyId(null) }
  }
  const add = () => run('create', () => caseDetailApi.addReference(caseId, { url: url.trim(), title: title.trim(), needs_review: true }), () => { setUrl(''); setTitle(''); setShowForm(false) })
  const save = () => editing && run(editing.ref_id, () => caseDetailApi.updateReference(caseId, editing.ref_id, { url: editUrl.trim(), title: editTitle.trim() }), () => setEditing(null))
  const remove = (refId: string) => { if (confirm('Delete this reference?')) void run(refId, () => caseDetailApi.deleteReference(caseId, refId)) }

  return <div className="h-full overflow-y-auto bg-background"><div className="mx-auto max-w-4xl space-y-4 p-4 sm:p-6">
    <div className="flex items-center justify-between"><span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">References ({references.length})</span><Button size="sm" variant="secondary" onClick={() => setShowForm(value => !value)}><Plus className="size-3.5" />Add reference</Button></div>
    {showForm && <div className="space-y-3 rounded-xl border border-border bg-surface p-4"><Input type="url" value={url} onChange={event => setUrl(event.target.value)} placeholder="https://…" autoFocus /><Input value={title} onChange={event => setTitle(event.target.value)} placeholder="Title or description" /><div className="flex gap-2"><Button size="sm" onClick={() => void add()} disabled={!url.trim() || busyId === 'create'}>{busyId === 'create' ? 'Adding…' : 'Add reference'}</Button><Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button></div></div>}
    {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    {references.length === 0 ? <p className="text-sm text-muted-foreground">No references yet. Argus can also add URLs found during analysis.</p> : references.map(reference => {
      const isEditing = editing?.ref_id === reference.ref_id
      return <article key={reference.ref_id} className="rounded-xl border border-border bg-surface p-4">
        {isEditing ? <div className="space-y-2"><Input type="url" value={editUrl} onChange={event => setEditUrl(event.target.value)} autoFocus /><Input value={editTitle} onChange={event => setEditTitle(event.target.value)} /><div className="flex gap-2"><Button size="sm" onClick={() => void save()} disabled={!editUrl.trim() || busyId === reference.ref_id}>Save</Button><Button size="sm" variant="ghost" onClick={() => setEditing(null)}>Cancel</Button></div></div> : <div className="flex items-start gap-3"><div className="min-w-0 flex-1">{reference.title && <h2 className="truncate text-sm font-medium text-foreground">{reference.title}</h2>}<a href={reference.url} target="_blank" rel="noreferrer" className="mt-1 inline-flex max-w-full items-center gap-1 break-all text-xs text-accent hover:underline">{reference.url}<ExternalLink className="size-3 shrink-0" /></a><div className="mt-2 flex gap-2 text-xs text-muted-foreground"><span>{reference.added_by}</span><span>·</span><time>{new Date(reference.added_at).toLocaleDateString()}</time>{reference.needs_review && <span className="rounded bg-warning/10 px-1.5 py-0.5 text-warning">needs review</span>}</div></div><div className="flex shrink-0 gap-1">{reference.needs_review && <Button size="sm" variant="ghost" onClick={() => void run(reference.ref_id, () => caseDetailApi.updateReference(caseId, reference.ref_id, { needs_review: false }))}>Mark reviewed</Button>}<Button size="sm" variant="ghost" onClick={() => { setEditing(reference); setEditUrl(reference.url); setEditTitle(reference.title) }}>Edit</Button><Button size="sm" variant="ghost" className="hover:text-danger" disabled={busyId === reference.ref_id} onClick={() => remove(reference.ref_id)}>Delete</Button></div></div>}
      </article>
    })}
  </div></div>
}
