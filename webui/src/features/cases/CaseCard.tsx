import { ArrowUpRight, Binoculars, FileText, NotebookPen, Trash2 } from 'lucide-react'
import { Link } from 'react-router-dom'
import Button from '../../components/ui/Button'
import { cn } from '../../lib/cn'
import type { CaseSummary } from './types'

const statusStyles: Record<string, string> = {
  open: 'bg-accent/10 text-accent',
  active: 'bg-success/10 text-success',
  monitoring: 'bg-warning/10 text-warning',
  closed: 'bg-muted text-muted-foreground',
}

function formatDate(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Unknown date'
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(date)
}

interface CaseCardProps {
  item: CaseSummary
  onDelete: (item: CaseSummary) => void
  deleting?: boolean
}

export default function CaseCard({ item, onDelete, deleting = false }: CaseCardProps) {
  return (
    <article className="group rounded-xl border border-border bg-surface p-4 shadow-sm transition hover:border-accent/50 hover:bg-surface-raised/60 sm:p-5">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className={cn('rounded-full px-2 py-0.5 text-[11px] font-medium capitalize', statusStyles[item.status] ?? statusStyles.closed)}>
              {item.status.replace('_', ' ')}
            </span>
            <span className="rounded-full border border-border px-2 py-0.5 text-[11px] text-muted-foreground">{item.classification}</span>
            <span className="font-mono text-[11px] text-muted-foreground">{item.case_id.slice(0, 13)}</span>
          </div>
          <Link
            to={`/cases/${item.case_id}`}
            className="inline-flex max-w-full items-center gap-2 text-sm font-semibold text-foreground transition hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <span className="truncate">{item.title}</span>
            <ArrowUpRight className="size-4 shrink-0 text-muted-foreground transition group-hover:text-accent" aria-hidden="true" />
          </Link>
          {item.description && <p className="mt-1 line-clamp-2 text-sm leading-5 text-muted-foreground">{item.description}</p>}
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="size-8 shrink-0 text-muted-foreground hover:bg-danger/10 hover:text-danger"
          aria-label={`Delete case ${item.title}`}
          title="Delete case"
          disabled={deleting}
          onClick={() => onDelete(item)}
        >
          <Trash2 className="size-4" aria-hidden="true" />
        </Button>
      </div>

      {item.tags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {item.tags.map(tag => <span key={tag} className="rounded bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">{tag}</span>)}
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border pt-3 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1.5"><Binoculars className="size-3.5" aria-hidden="true" />{item.observable_count} observables</span>
        <span className="inline-flex items-center gap-1.5"><NotebookPen className="size-3.5" aria-hidden="true" />{item.note_count} notes</span>
        <span className="inline-flex items-center gap-1.5"><FileText className="size-3.5" aria-hidden="true" />{item.report_count} reports</span>
        <span className="ml-auto" title={new Date(item.updated_at).toLocaleString()}>Updated {formatDate(item.updated_at)}</span>
      </div>
    </article>
  )
}
