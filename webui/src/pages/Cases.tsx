import { useMemo, useState } from 'react'
import { Plus, Search, X } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import ErrorState from '../components/ErrorState'
import LoadingState from '../components/LoadingState'
import PageHeader from '../components/PageHeader'
import Button from '../components/ui/Button'
import Input from '../components/ui/Input'
import Select from '../components/ui/Select'
import CaseCard from '../features/cases/CaseCard'
import CreateCaseForm from '../features/cases/CreateCaseForm'
import { useCases, useDeleteCase } from '../features/cases/queries'
import type { CaseSort, CaseSummary } from '../features/cases/types'

export default function Cases() {
  const casesQuery = useCases()
  const deleteCaseMutation = useDeleteCase()
  const [showCreate, setShowCreate] = useState(false)
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [sortBy, setSortBy] = useState<CaseSort>('updated')

  const cases = casesQuery.data ?? []
  const statuses = useMemo(() => [...new Set(cases.map(item => item.status))].sort(), [cases])
  const visibleCases = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    return cases
      .filter(item => {
        const matchesQuery = !normalizedQuery || [
          item.title,
          item.description,
          item.case_id,
          ...item.tags,
        ].some(value => value.toLowerCase().includes(normalizedQuery))
        return matchesQuery && (statusFilter === 'all' || item.status === statusFilter)
      })
      .sort((a, b) => {
        if (sortBy === 'title') return a.title.localeCompare(b.title)
        const field = sortBy === 'created' ? 'created_at' : 'updated_at'
        return new Date(b[field]).getTime() - new Date(a[field]).getTime()
      })
  }, [cases, query, sortBy, statusFilter])

  const filtersActive = Boolean(query || statusFilter !== 'all')
  const resetFilters = () => {
    setQuery('')
    setStatusFilter('all')
  }
  const handleDelete = (item: CaseSummary) => {
    const confirmed = window.confirm(`Delete case "${item.title}"?\n\nThis removes the case and all stored notes, observables, evidence, and reports.`)
    if (!confirmed) return
    deleteCaseMutation.mutate(item.case_id)
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-background">
      <PageHeader
        title="Cases"
        description="Investigations, observables, evidence, and analyst reporting."
        actions={
          <Button onClick={() => setShowCreate(value => !value)}>
            {showCreate ? <X className="size-4" aria-hidden="true" /> : <Plus className="size-4" aria-hidden="true" />}
            {showCreate ? 'Close' : 'New case'}
          </Button>
        }
      />

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl space-y-5 px-4 py-5 sm:px-6 sm:py-6">
          {showCreate && <CreateCaseForm onCancel={() => setShowCreate(false)} onCreated={() => setShowCreate(false)} />}

          <section aria-label="Case filters" className="grid gap-2 rounded-xl border border-border bg-surface p-3 sm:grid-cols-[minmax(0,1fr)_11rem_12rem]">
            <label className="relative">
              <span className="sr-only">Search cases</span>
              <Search className="pointer-events-none absolute left-3 top-3 size-4 text-muted-foreground" aria-hidden="true" />
              <Input className="pl-9" placeholder="Search cases, tags, or IDs" value={query} onChange={event => setQuery(event.target.value)} />
            </label>
            <label>
              <span className="sr-only">Filter by status</span>
              <Select value={statusFilter} onChange={event => setStatusFilter(event.target.value)}>
                <option value="all">All statuses</option>
                {statuses.map(status => <option key={status} value={status}>{status.replace('_', ' ')}</option>)}
              </Select>
            </label>
            <label>
              <span className="sr-only">Sort cases</span>
              <Select value={sortBy} onChange={event => setSortBy(event.target.value as CaseSort)}>
                <option value="updated">Recently updated</option>
                <option value="created">Recently created</option>
                <option value="title">Title A–Z</option>
              </Select>
            </label>
          </section>

          {casesQuery.isPending ? (
            <LoadingState label="Loading cases" />
          ) : casesQuery.isError ? (
            <ErrorState message="Argus could not load the case index." onRetry={() => void casesQuery.refetch()} />
          ) : cases.length === 0 ? (
            <EmptyState
              title="No cases yet"
              description="Create a case to begin collecting observables and recording analysis."
              action={<Button onClick={() => setShowCreate(true)}><Plus className="size-4" aria-hidden="true" />Create case</Button>}
            />
          ) : visibleCases.length === 0 ? (
            <EmptyState
              title="No matching cases"
              description="Change the search text or status filter to broaden the results."
              action={filtersActive ? <Button variant="secondary" onClick={resetFilters}>Clear filters</Button> : undefined}
            />
          ) : (
            <section aria-label="Case list">
              <div className="mb-3 flex items-center justify-between text-xs text-muted-foreground">
                <span>{visibleCases.length} of {cases.length} cases</span>
                {filtersActive && <Button variant="ghost" size="sm" onClick={resetFilters}>Clear filters</Button>}
              </div>
              <div className="space-y-3">
                {visibleCases.map(item => (
                  <CaseCard
                    key={item.case_id}
                    item={item}
                    deleting={deleteCaseMutation.isPending && deleteCaseMutation.variables === item.case_id}
                    onDelete={handleDelete}
                  />
                ))}
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  )
}
