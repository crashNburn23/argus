import { ChevronLeft, ScanSearch } from 'lucide-react'
import { Link } from 'react-router-dom'
import Button from '../../../components/ui/Button'
import Select from '../../../components/ui/Select'
import { cn } from '../../../lib/cn'
import type { CaseDetailData, CaseTabId } from './types'

const STATUS_OPTIONS = ['open', 'active', 'monitoring', 'closed']

export default function CaseWorkspaceHeader({
  caseData,
  activeTab,
  pendingReferenceCount,
  reviewableCount,
  onTabChange,
  onReview,
  onStatusChange,
}: {
  caseData: CaseDetailData
  activeTab: CaseTabId
  pendingReferenceCount: number
  reviewableCount: number
  onTabChange: (tab: CaseTabId) => void
  onReview: () => void
  onStatusChange: (status: string) => void
}) {
  const tabs: Array<{ id: CaseTabId; label: string }> = [
    { id: 'overview', label: `Overview (${caseData.observables.length})` },
    { id: 'graph', label: 'Graph' },
    { id: 'chat', label: 'Chat' },
    { id: 'notes', label: `Notes (${caseData.notes.length})` },
    { id: 'references', label: `References (${caseData.references.length})${pendingReferenceCount ? ` · ${pendingReferenceCount} new` : ''}` },
    { id: 'report', label: `Reports${caseData.reports.length ? ` (${caseData.reports.length})` : ''}` },
  ]

  return (
    <>
      <header className="shrink-0 border-b border-border bg-surface px-4 py-4 sm:px-6">
        <Link to="/cases" className="mb-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
          <ChevronLeft className="size-3.5" aria-hidden="true" />Cases
        </Link>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <h1 className="truncate text-lg font-semibold text-foreground">{caseData.title}</h1>
            <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{caseData.case_id}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Button onClick={onReview} disabled={reviewableCount === 0} title={reviewableCount ? `Review ${reviewableCount} manually added items` : 'Add observables or notes first'}>
              <ScanSearch className="size-4" aria-hidden="true" />Review ({reviewableCount})
            </Button>
            <Select className="w-32" value={caseData.status} onChange={event => onStatusChange(event.target.value)} aria-label="Case status">
              {STATUS_OPTIONS.map(status => <option key={status} value={status}>{status}</option>)}
            </Select>
          </div>
        </div>
      </header>
      <nav className="flex shrink-0 overflow-x-auto border-b border-border bg-surface px-2 sm:px-4" aria-label="Case workspace">
        {tabs.map(tab => (
          <button
            key={tab.id}
            type="button"
            onClick={() => onTabChange(tab.id)}
            className={cn(
              'whitespace-nowrap border-b-2 px-3 py-2.5 text-sm transition-colors',
              activeTab === tab.id ? 'border-accent text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {tab.label}
          </button>
        ))}
      </nav>
    </>
  )
}
