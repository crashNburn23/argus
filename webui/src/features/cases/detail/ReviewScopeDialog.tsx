import { useEffect, useRef } from 'react'
import Button from '../../../components/ui/Button'
import type { CaseNote, CaseObservable, CaseReference } from './types'

export default function ReviewScopeDialog({
  observables,
  notes,
  references,
  selectedObservables,
  selectedNotes,
  selectedReferences,
  onSelectedObservables,
  onSelectedNotes,
  onSelectedReferences,
  onCancel,
  onConfirm,
}: {
  observables: CaseObservable[]
  notes: CaseNote[]
  references: CaseReference[]
  selectedObservables: Set<string>
  selectedNotes: Set<string>
  selectedReferences: Set<string>
  onSelectedObservables: (value: Set<string>) => void
  onSelectedNotes: (value: Set<string>) => void
  onSelectedReferences: (value: Set<string>) => void
  onCancel: () => void
  onConfirm: () => void
}) {
  const cancelRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    cancelRef.current?.focus()
  }, [])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onCancel])

  const toggle = (
    current: Set<string>,
    id: string,
    checked: boolean,
    change: (value: Set<string>) => void,
  ) => {
    const next = new Set(current)
    checked ? next.add(id) : next.delete(id)
    change(next)
  }

  const count = selectedObservables.size + selectedNotes.size + selectedReferences.size

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="review-title"
    >
      <div className="flex max-h-[85vh] w-full max-w-xl flex-col rounded-xl border border-border bg-surface shadow-2xl">
        <header className="border-b border-border p-5">
          <h2 id="review-title" className="font-semibold text-foreground">
            Choose analysis inputs
          </h2>
          <p className="mt-1 text-xs text-muted-foreground">
            Argus will enrich the selected material, identify relationships, and write sourced findings to Notes.
          </p>
        </header>
        <div className="flex-1 space-y-5 overflow-y-auto p-5">
          <Group
            title="Observables"
            items={observables.map(o => ({ id: o.observable_id, label: `[${o.observable_type}] ${o.value}` }))}
            selected={selectedObservables}
            onToggle={(id, checked) => toggle(selectedObservables, id, checked, onSelectedObservables)}
          />
          <Group
            title="Notes"
            items={notes.map(n => ({ id: n.note_id, label: n.body }))}
            selected={selectedNotes}
            onToggle={(id, checked) => toggle(selectedNotes, id, checked, onSelectedNotes)}
          />
          <Group
            title="References"
            items={references.map(r => ({ id: r.ref_id, label: r.title || r.url }))}
            selected={selectedReferences}
            onToggle={(id, checked) => toggle(selectedReferences, id, checked, onSelectedReferences)}
          />
        </div>
        <footer className="flex justify-end gap-2 border-t border-border p-4">
          <Button ref={cancelRef} variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button disabled={count === 0} onClick={onConfirm}>
            Analyze {count} items
          </Button>
        </footer>
      </div>
    </div>
  )
}

function Group({
  title,
  items,
  selected,
  onToggle,
}: {
  title: string
  items: Array<{ id: string; label: string }>
  selected: Set<string>
  onToggle: (id: string, checked: boolean) => void
}) {
  if (items.length === 0) return null
  return (
    <section>
      <h3 className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {title} ({items.length})
      </h3>
      <div className="space-y-1">
        {items.map(item => (
          <label
            key={item.id}
            className="flex cursor-pointer items-start gap-3 rounded-lg p-2 text-sm hover:bg-surface-raised"
          >
            <input
              type="checkbox"
              className="mt-0.5 accent-accent"
              checked={selected.has(item.id)}
              onChange={e => onToggle(item.id, e.target.checked)}
            />
            <span className="line-clamp-2 text-foreground">{item.label}</span>
          </label>
        ))}
      </div>
    </section>
  )
}
