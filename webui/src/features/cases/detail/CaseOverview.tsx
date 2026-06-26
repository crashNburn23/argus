import { useEffect, useMemo, useState } from 'react'
import { Check, ChevronLeft, ChevronRight, Copy, Plus, Search } from 'lucide-react'
import Button from '../../../components/ui/Button'
import Input from '../../../components/ui/Input'
import Select from '../../../components/ui/Select'
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

const PAGE_SIZE = 25

function observableSource(labels: string[], metadata: Record<string, unknown>) {
  if (labels.includes('manually_added')) return 'Manual'
  const source = metadata.source
  return typeof source === 'string' && source ? source.replace(/_/g, ' ') : 'Argus'
}

export default function CaseOverview({ caseData }: { caseData: CaseDetailData }) {
  const [showForm, setShowForm] = useState(false)
  const [text, setText] = useState('')
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [page, setPage] = useState(1)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const preview = useMemo(() => (text.trim() ? parseObservableText(text) : []), [text])

  const addObservables = useAddObservables(caseData.case_id)
  const observableTypes = useMemo(
    () => [...new Set(caseData.observables.map(item => item.observable_type))].sort(),
    [caseData.observables],
  )
  const filteredObservables = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return caseData.observables.filter(item => {
      const isManual = item.labels.includes('manually_added')
      return (!normalized || item.value.toLowerCase().includes(normalized))
        && (typeFilter === 'all' || item.observable_type === typeFilter)
        && (sourceFilter === 'all' || (sourceFilter === 'manual' ? isManual : !isManual))
    })
  }, [caseData.observables, query, sourceFilter, typeFilter])
  const pageCount = Math.max(1, Math.ceil(filteredObservables.length / PAGE_SIZE))
  const pageItems = filteredObservables.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  const groupedObservables = useMemo(() => {
    const groups = new Map<string, typeof pageItems>()
    for (const item of pageItems) {
      const group = groups.get(item.observable_type) ?? []
      group.push(item)
      groups.set(item.observable_type, group)
    }
    return [...groups.entries()]
  }, [pageItems])

  useEffect(() => setPage(1), [query, sourceFilter, typeFilter])
  useEffect(() => {
    if (page > pageCount) setPage(pageCount)
  }, [page, pageCount])

  const copyObservable = async (id: string, value: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedId(id)
    window.setTimeout(() => setCopiedId(current => current === id ? null : current), 1500)
  }

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
          {caseData.observables.length === 0 ? <p className="text-sm text-muted-foreground">No observables yet.</p> : <>
            <div className="mb-3 grid gap-2 rounded-xl border border-border bg-surface p-3 sm:grid-cols-[minmax(0,1fr)_10rem_10rem]">
              <label className="relative">
                <span className="sr-only">Search observables</span>
                <Search className="pointer-events-none absolute left-3 top-3 size-4 text-muted-foreground" aria-hidden="true" />
                <Input className="pl-9" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search observable values" />
              </label>
              <Select aria-label="Filter by observable type" value={typeFilter} onChange={event => setTypeFilter(event.target.value)}>
                <option value="all">All types</option>
                {observableTypes.map(type => <option key={type} value={type}>{type}</option>)}
              </Select>
              <Select aria-label="Filter by observable source" value={sourceFilter} onChange={event => setSourceFilter(event.target.value)}>
                <option value="all">All sources</option>
                <option value="manual">Manual</option>
                <option value="discovered">Argus discovered</option>
              </Select>
            </div>

            <div className="mb-2 flex items-center justify-between text-xs text-muted-foreground">
              <span>{filteredObservables.length} of {caseData.observables.length} observables</span>
              {(query || typeFilter !== 'all' || sourceFilter !== 'all') && (
                <Button variant="ghost" size="sm" onClick={() => { setQuery(''); setTypeFilter('all'); setSourceFilter('all') }}>Clear filters</Button>
              )}
            </div>

            {groupedObservables.length === 0 ? (
              <div className="rounded-xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground">No observables match these filters.</div>
            ) : (
              <div className="space-y-3">
                {groupedObservables.map(([type, observables]) => (
                  <div key={type} className="overflow-hidden rounded-xl border border-border bg-surface">
                    <div className="flex items-center justify-between border-b border-border bg-surface-raised/50 px-4 py-2">
                      <span className={cn('rounded px-1.5 py-0.5 font-mono text-xs', typeStyles[type] ?? typeStyles.unknown)}>{type}</span>
                      <span className="text-xs text-muted-foreground">{observables.length} on this page</span>
                    </div>
                    {observables.map((observable, index) => (
                      <div key={observable.observable_id} className={cn('group flex items-center gap-3 px-4 py-3 text-sm', index > 0 && 'border-t border-border')}>
                        <div className="min-w-0 flex-1">
                          <div className="break-all font-mono text-foreground">{observable.value}</div>
                          <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] capitalize text-muted-foreground">
                            <span>{observableSource(observable.labels, observable.metadata)}</span>
                            {observable.confidence > 0 && <span>{Math.round(observable.confidence * 100)}% confidence</span>}
                          </div>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 shrink-0"
                          onClick={() => void copyObservable(observable.observable_id, observable.value)}
                          aria-label={`Copy ${observable.value}`}
                          title="Copy observable"
                        >
                          {copiedId === observable.observable_id ? <Check className="size-4 text-success" aria-hidden="true" /> : <Copy className="size-4" aria-hidden="true" />}
                        </Button>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}

            {pageCount > 1 && (
              <div className="mt-4 flex items-center justify-between">
                <Button variant="secondary" size="sm" disabled={page === 1} onClick={() => setPage(value => value - 1)}>
                  <ChevronLeft className="size-4" aria-hidden="true" />Previous
                </Button>
                <span className="text-xs text-muted-foreground">Page {page} of {pageCount}</span>
                <Button variant="secondary" size="sm" disabled={page === pageCount} onClick={() => setPage(value => value + 1)}>
                  Next<ChevronRight className="size-4" aria-hidden="true" />
                </Button>
              </div>
            )}
          </>}
        </section>

        {caseData.pirs.length > 0 && <section><h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">Priority intelligence requirements</h2><div className="space-y-2">{caseData.pirs.map((pir, index) => <div key={`${pir.question}-${index}`} className="flex gap-3 rounded-lg border border-border bg-surface p-3 text-sm"><span className="text-muted-foreground">{index + 1}.</span><span className="flex-1 text-foreground">{pir.question}</span>{pir.priority && <span className="text-xs text-muted-foreground">{pir.priority}</span>}</div>)}</div></section>}
      </div>
    </div>
  )
}
