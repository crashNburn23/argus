import { useState } from 'react'
import { ExternalLink, Plus } from 'lucide-react'
import Button from '../../../components/ui/Button'
import Input from '../../../components/ui/Input'
import { useAddReference, useDeleteReference, useUpdateReference } from './queries'
import type { CaseReference } from './types'

export default function CaseReferences({
  caseId,
  references,
}: {
  caseId: string
  references: CaseReference[]
}) {
  const [showForm, setShowForm] = useState(false)
  const [url, setUrl] = useState('')
  const [title, setTitle] = useState('')
  const [editing, setEditing] = useState<CaseReference | null>(null)
  const [editUrl, setEditUrl] = useState('')
  const [editTitle, setEditTitle] = useState('')
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null)

  const addReference = useAddReference(caseId)
  const updateReference = useUpdateReference(caseId)
  const deleteReference = useDeleteReference(caseId)

  const handleAdd = () => {
    const trimmedUrl = url.trim()
    if (!trimmedUrl) return
    addReference.mutate(
      { url: trimmedUrl, title: title.trim(), needs_review: true },
      {
        onSuccess: () => {
          setUrl('')
          setTitle('')
          setShowForm(false)
        },
      },
    )
  }

  const handleSave = () => {
    if (!editing) return
    updateReference.mutate(
      { refId: editing.ref_id, input: { url: editUrl.trim(), title: editTitle.trim() } },
      { onSuccess: () => setEditing(null) },
    )
  }

  const handleMarkReviewed = (refId: string) => {
    updateReference.mutate({ refId, input: { needs_review: false } })
  }

  const handleDelete = (refId: string) => {
    deleteReference.mutate(refId, { onSuccess: () => setPendingDeleteId(null) })
  }

  const mutationError = addReference.error ?? updateReference.error ?? deleteReference.error

  return (
    <div className="h-full overflow-y-auto bg-background">
      <div className="mx-auto max-w-4xl space-y-4 p-4 sm:p-6">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            References ({references.length})
          </span>
          <Button size="sm" variant="secondary" onClick={() => setShowForm(v => !v)}>
            <Plus className="size-3.5" aria-hidden="true" />
            Add reference
          </Button>
        </div>

        {showForm && (
          <div className="space-y-3 rounded-xl border border-border bg-surface p-4">
            <Input
              type="url"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://…"
              autoFocus
            />
            <Input
              value={title}
              onChange={e => setTitle(e.target.value)}
              placeholder="Title or description"
            />
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={handleAdd}
                disabled={!url.trim() || addReference.isPending}
              >
                {addReference.isPending ? 'Adding…' : 'Add reference'}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {mutationError && (
          <p role="alert" className="text-sm text-danger">
            {(mutationError as Error).message ?? 'The reference operation failed.'}
          </p>
        )}

        {references.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No references yet. Argus can also add URLs found during analysis.
          </p>
        ) : (
          references.map(reference => {
            const isEditing = editing?.ref_id === reference.ref_id
            const isConfirmingDelete = pendingDeleteId === reference.ref_id

            return (
              <article
                key={reference.ref_id}
                className="rounded-xl border border-border bg-surface p-4"
              >
                {isEditing ? (
                  <div className="space-y-2">
                    <Input
                      type="url"
                      value={editUrl}
                      onChange={e => setEditUrl(e.target.value)}
                      autoFocus
                    />
                    <Input
                      value={editTitle}
                      onChange={e => setEditTitle(e.target.value)}
                    />
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        onClick={handleSave}
                        disabled={!editUrl.trim() || updateReference.isPending}
                      >
                        Save
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setEditing(null)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-start gap-3">
                    <div className="min-w-0 flex-1">
                      {reference.title && (
                        <h2 className="truncate text-sm font-medium text-foreground">
                          {reference.title}
                        </h2>
                      )}
                      <a
                        href={reference.url}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-1 inline-flex max-w-full items-center gap-1 break-all text-xs text-accent hover:underline"
                      >
                        {reference.url}
                        <ExternalLink className="size-3 shrink-0" />
                      </a>
                      <div className="mt-2 flex gap-2 text-xs text-muted-foreground">
                        <span>{reference.added_by}</span>
                        <span>·</span>
                        <time>{new Date(reference.added_at).toLocaleDateString()}</time>
                        {reference.needs_review && (
                          <span className="rounded bg-warning/10 px-1.5 py-0.5 text-warning">
                            needs review
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      {reference.needs_review && (
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={
                            updateReference.isPending &&
                            updateReference.variables?.refId === reference.ref_id
                          }
                          onClick={() => handleMarkReviewed(reference.ref_id)}
                        >
                          Mark reviewed
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditing(reference)
                          setEditUrl(reference.url)
                          setEditTitle(reference.title)
                        }}
                      >
                        Edit
                      </Button>
                      {isConfirmingDelete ? (
                        <>
                          <Button
                            size="sm"
                            variant="danger"
                            disabled={deleteReference.isPending}
                            onClick={() => handleDelete(reference.ref_id)}
                          >
                            Confirm
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
                          size="sm"
                          variant="ghost"
                          className="hover:text-danger"
                          onClick={() => setPendingDeleteId(reference.ref_id)}
                        >
                          Delete
                        </Button>
                      )}
                    </div>
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
