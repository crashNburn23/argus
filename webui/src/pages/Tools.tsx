import { useMemo, useState } from 'react'
import { CheckCircle2, ChevronRight, Code2, PlugZap, Search, Settings, XCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import PageHeader from '../components/PageHeader'
import Button from '../components/ui/Button'
import Input from '../components/ui/Input'
import { cn } from '../lib/cn'
import ErrorState from '../components/ErrorState'
import LoadingState from '../components/LoadingState'
import { useToolFile, useToolFiles, useToolStatuses } from '../features/tools/queries'

type View = 'integrations' | 'source'

function displayName(value: string) {
  const brands: Record<string, string> = {
    abuseipdb: 'AbuseIPDB',
    alienvault_otx: 'AlienVault OTX',
    mitre_attack: 'MITRE ATT&CK',
    misp: 'MISP',
    nvd: 'NVD',
    passive_dns: 'Passive DNS',
    urlhaus: 'URLhaus',
    virustotal: 'VirusTotal',
  }
  if (brands[value]) return brands[value]
  return value.split('_').map(part => part === 'nvd' || part === 'http' ? part.toUpperCase() : `${part.charAt(0).toUpperCase()}${part.slice(1)}`).join(' ')
}

export default function Tools() {
  const [view, setView] = useState<View>('integrations')
  const [selected, setSelected] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const filesQuery = useToolFiles()
  const statusesQuery = useToolStatuses()
  const { data: fileContent, isFetching: loadingContent } = useToolFile(selected)
  const files = filesQuery.data ?? []
  const statuses = statusesQuery.data ?? []
  const statusMap = useMemo(() => new Map(statuses.map(status => [status.name, status])), [statuses])
  const visibleFiles = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return files.filter(file => !normalized || [file.stem, ...file.tool_names].some(value => value.toLowerCase().includes(normalized)))
  }, [files, query])
  const availableCount = statuses.filter(status => status.available).length
  const selectedFile = files.find(file => file.filename === selected)
  const lineCount = fileContent ? fileContent.content.split('\n').length : 0

  if (filesQuery.isLoading || statusesQuery.isLoading) return <LoadingState label="Checking integrations" />
  if (filesQuery.isError || statusesQuery.isError) return (
    <div className="p-6"><ErrorState message="Argus could not load integration status." onRetry={() => { void filesQuery.refetch(); void statusesQuery.refetch() }} /></div>
  )

  return (
    <div className="flex h-full min-h-0 flex-col bg-background">
      <PageHeader
        title="Tools"
        description="Threat-intelligence integrations and their current availability."
        actions={
          <div className="flex rounded-lg border border-border bg-surface p-1" aria-label="Tools view">
            <button type="button" onClick={() => setView('integrations')} className={cn('rounded-md px-3 py-1.5 text-xs font-medium', view === 'integrations' ? 'bg-surface-raised text-foreground' : 'text-muted-foreground hover:text-foreground')}>
              Integrations
            </button>
            <button type="button" onClick={() => setView('source')} className={cn('rounded-md px-3 py-1.5 text-xs font-medium', view === 'source' ? 'bg-surface-raised text-foreground' : 'text-muted-foreground hover:text-foreground')}>
              Source
            </button>
          </div>
        }
      />

      {view === 'integrations' ? (
        <div className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-6xl space-y-5 p-4 sm:p-6">
            <div className="grid gap-3 sm:grid-cols-3">
              <Summary icon={PlugZap} label="Registered capabilities" value={String(statuses.length)} />
              <Summary icon={CheckCircle2} label="Available now" value={String(availableCount)} tone="success" />
              <Summary icon={XCircle} label="Need configuration" value={String(statuses.length - availableCount)} tone="muted" />
            </div>

            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <label className="relative w-full sm:max-w-sm">
                <span className="sr-only">Search integrations</span>
                <Search className="pointer-events-none absolute left-3 top-3 size-4 text-muted-foreground" aria-hidden="true" />
                <Input className="pl-9" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search integrations" />
              </label>
              <Link to="/settings" className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-border bg-surface px-3 text-sm font-medium text-foreground hover:bg-surface-raised">
                <Settings className="size-4" aria-hidden="true" />Configure API keys
              </Link>
            </div>

            {visibleFiles.length === 0 ? (
              <div className="rounded-xl border border-dashed border-border p-10 text-center text-sm text-muted-foreground">No integrations match your search.</div>
            ) : (
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {visibleFiles.map(file => {
                  const toolStatuses = file.tool_names.map(name => statusMap.get(name)).filter(Boolean)
                  const available = toolStatuses.length > 0 && toolStatuses.some(status => status?.available)
                  const reason = toolStatuses.find(status => !status?.available)?.reason
                  const internal = file.tool_names.length === 0
                  return (
                    <article key={file.filename} className="flex min-h-40 flex-col rounded-xl border border-border bg-surface p-4 shadow-sm">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <h2 className="font-medium text-foreground">{displayName(file.stem)}</h2>
                          <p className="mt-1 text-xs text-muted-foreground">{internal ? 'Internal support module' : `${file.tool_names.length} ${file.tool_names.length === 1 ? 'capability' : 'capabilities'}`}</p>
                        </div>
                        <span className={cn('shrink-0 rounded-full px-2 py-1 text-[11px] font-medium', internal ? 'bg-muted text-muted-foreground' : available ? 'bg-success/10 text-success' : 'bg-warning/10 text-warning')}>
                          {internal ? 'internal' : available ? 'available' : 'setup needed'}
                        </span>
                      </div>
                      {file.tool_names.length > 0 && <div className="mt-4 flex flex-wrap gap-1.5">{file.tool_names.map(name => <span key={name} className="rounded bg-surface-raised px-2 py-1 font-mono text-[11px] text-muted-foreground">{name}</span>)}</div>}
                      {reason && <p className="mt-3 text-xs leading-5 text-muted-foreground">{reason}</p>}
                      <button type="button" onClick={() => { setSelected(file.filename); setView('source') }} className="mt-auto flex items-center gap-1 pt-4 text-xs font-medium text-accent hover:underline">
                        View implementation<ChevronRight className="size-3.5" aria-hidden="true" />
                      </button>
                    </article>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="grid min-h-0 flex-1 grid-rows-[auto_minmax(0,1fr)] overflow-hidden md:grid-cols-[18rem_minmax(0,1fr)] md:grid-rows-1">
          <aside className="max-h-52 overflow-y-auto border-b border-border bg-surface md:max-h-none md:border-b-0 md:border-r">
            <div className="sticky top-0 z-10 border-b border-border bg-surface p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold">Implementation files</span>
                <Button variant="ghost" size="sm" onClick={() => setView('integrations')}>Back</Button>
              </div>
            </div>
            {files.map(file => (
              <button key={file.filename} type="button" onClick={() => setSelected(file.filename)} className={cn('w-full border-b border-border/50 px-4 py-2.5 text-left hover:bg-surface-raised', selected === file.filename && 'bg-surface-raised')}>
                <div className="flex items-center gap-2"><Code2 className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" /><span className="truncate font-mono text-sm">{file.stem}</span></div>
                {file.tool_names.length > 0 && <p className="ml-5 mt-0.5 truncate text-xs text-muted-foreground">{file.tool_names.join(', ')}</p>}
              </button>
            ))}
          </aside>
          <section className="flex min-h-0 min-w-0 flex-col overflow-hidden">
            {selected ? <>
              <div className="flex shrink-0 items-center justify-between border-b border-border bg-surface px-4 py-3">
                <span className="truncate font-mono text-sm">{selected}</span>
                {fileContent && <span className="shrink-0 text-xs text-muted-foreground">{lineCount} lines · {Math.ceil((selectedFile?.size ?? 0) / 1024)}KB</span>}
              </div>
              <div className="min-h-0 flex-1 overflow-auto">{loadingContent ? <p className="p-4 text-xs text-muted-foreground">Loading…</p> : <pre className="whitespace-pre p-4 font-mono text-xs leading-relaxed text-foreground/80">{fileContent?.content}</pre>}</div>
            </> : <div className="flex flex-1 items-center justify-center p-6 text-center text-sm text-muted-foreground">Select an implementation file to inspect its source.</div>}
          </section>
        </div>
      )}
    </div>
  )
}

function Summary({ icon: Icon, label, value, tone = 'default' }: { icon: typeof PlugZap; label: string; value: string; tone?: 'default' | 'success' | 'muted' }) {
  return <div className="flex items-center gap-3 rounded-xl border border-border bg-surface p-4"><div className={cn('flex size-10 items-center justify-center rounded-lg bg-accent/10 text-accent', tone === 'success' && 'bg-success/10 text-success', tone === 'muted' && 'bg-muted text-muted-foreground')}><Icon className="size-5" aria-hidden="true" /></div><div><div className="text-xl font-semibold text-foreground">{value}</div><div className="text-xs text-muted-foreground">{label}</div></div></div>
}
