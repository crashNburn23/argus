import { useMemo, useState } from 'react'
import { Plus } from 'lucide-react'
import Button from '../../../components/ui/Button'
import Textarea from '../../../components/ui/Textarea'
import { cn } from '../../../lib/cn'
import { useAddObservables } from './queries'
import type { CaseDetailData } from './types'
import { parseObservableText } from './utils'

const typeStyles: Record<string, string> = {
  ip: 'bg-accent/10 text-accent',
  domain: 'bg-violet-500/10 text-violet-400',
  url: 'bg-indigo-500/10 text-indigo-400',
  sha256: 'bg-warning/10 text-warning',
  sha1: 'bg-warning/10 text-warning',
  md5: 'bg-warning/10 text-warning',
  cve: 'bg-danger/10 text-danger',
  email: 'bg-cyan-500/10 text-cyan-400',
  unknown: 'bg-muted text-muted-foreground',
}

export default function CaseOverview({ caseData }: { caseData: CaseDetailData }) {
  const [showForm, setShowForm] = useState(false)
  const [text, setText] = useState('')
  const preview = useMemo(() => (text.trim() ? parseObservableText(text) : []), [text])

  const addObservables = useAddObservables(caseData.case_id)

  const submit = () => {
    if (preview.length === 0) return
    addObservables.mutate(preview, {
      onSuccess: () => {
        setText('')
        setShowForm(false)
      },
    })
  }

  return (
    <div className="h-full overflow-y-auto bg-background">
      <div className="mx-auto max-w-5xl space-y-6 p-4 sm:p-6">
        <dl className="grid gap-3 rounded-xl border border-border bg-surface p-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
          {[
            ['Classification', caseData.classification],
            ['Status', caseData.status],
            ['Created', new Date(caseData.created_at).toLocaleString()],
            ['Updated', new Date(caseData.updated_at).toLocaleString()],
          ].map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 text-foreground">{value}</dd></div>)}
        </dl>

        {caseData.description && <section><h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Description</h2><p className="mt-2 text-sm leading-6 text-foreground">{caseData.description}</p></section>}

        <section>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Observables ({caseData.observables.length})</h2>
            <Button variant="secondary" size="sm" onClick={() => { setShowForm(v => !v); setText('') }}>
              <Plus className="size-3.5" aria-hidden="true" />Add observables
            </Button>
          </div>
          {showForm && (
            <div className="mb-4 space-y-3 rounded-xl border border-border bg-surface p-4">
              <p className="text-xs text-muted-foreground">Paste one observable per line, or separate values with commas or semicolons.</p>
              <Textarea className="font-mono" rows={4} value={text} onChange={event => setText(event.target.value)} autoFocus placeholder={'1.2.3.4\nevil.example.com'} />
              {preview.length > 0 && (
                <div className="max-h-40 space-y-1 overflow-y-auto">
                  {preview.map((item, index) => (
                    <div key={`${item.value}-${index}`} className="flex items-center gap-2 text-xs">
                      <span className={cn('rounded px-1.5 py-0.5 font-mono', typeStyles[item.observable_type] ?? typeStyles.unknown)}>
                        {item.observable_type}
                      </span>
                      <span className="truncate font-mono text-muted-foreground">{item.value}</span>
                    </div>
                  ))}
                </div>
              )}
              {addObservables.error && (
                <p role="alert" className="text-sm text-danger">
                  {(addObservables.error as Error).message ?? 'The observables could not be added.'}
                </p>
              )}
              <div className="flex gap-2">
                <Button
                  onClick={submit}
                  disabled={addObservables.isPending || preview.length === 0}
                >
                  {addObservables.isPending ? 'Adding…' : `Add ${preview.length} observables`}
                </Button>
                <Button variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
              </div>
            </div>
          )}
          {caseData.observables.length === 0 ? <p className="text-sm text-muted-foreground">No observables yet.</p> : (
            <div className="overflow-hidden rounded-xl border border-border bg-surface">
              {caseData.observables.map((observable, index) => <div key={observable.observable_id} className={cn('flex items-start gap-3 px-4 py-3 text-sm', index > 0 && 'border-t border-border')}><span className={cn('mt-0.5 rounded px-1.5 py-0.5 font-mono text-xs', typeStyles[observable.observable_type] ?? typeStyles.unknown)}>{observable.observable_type}</span><span className="min-w-0 break-all font-mono text-foreground">{observable.value}</span>{observable.labels.includes('manually_added') && <span className="ml-auto rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">manual</span>}</div>)}
            </div>
          )}
        </section>

        {caseData.pirs.length > 0 && <section><h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">Priority intelligence requirements</h2><div className="space-y-2">{caseData.pirs.map((pir, index) => <div key={`${pir.question}-${index}`} className="flex gap-3 rounded-lg border border-border bg-surface p-3 text-sm"><span className="text-muted-foreground">{index + 1}.</span><span className="flex-1 text-foreground">{pir.question}</span>{pir.priority && <span className="text-xs text-muted-foreground">{pir.priority}</span>}</div>)}</div></section>}
      </div>
    </div>
  )
}
