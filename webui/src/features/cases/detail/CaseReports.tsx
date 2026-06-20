import { useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import Button from '../../../components/ui/Button'
import Select from '../../../components/ui/Select'
import Textarea from '../../../components/ui/Textarea'
import { useDeleteReport, useGenerateReport } from './queries'
import type { CaseReport } from './types'

const AUDIENCES = [
  ['cti', 'CTI Team — Intelligence Product'],
  ['soc', 'SOC / Detection Engineering'],
  ['vm', 'Vulnerability Management'],
  ['ir', 'Incident Response'],
  ['exec', 'Executive Leadership'],
  ['awareness', 'Security Awareness / All Staff'],
  ['redteam', 'Red Team / Adversary Emulation'],
]

export default function CaseReports({
  caseId,
  reports,
}: {
  caseId: string
  reports: CaseReport[]
}) {
  const [audience, setAudience] = useState('cti')
  const [notes, setNotes] = useState('')
  const [active, setActive] = useState<CaseReport | null>(null)
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null)

  const generateReport = useGenerateReport(caseId)
  const deleteReport = useDeleteReport(caseId)

  const handleGenerate = () => {
    generateReport.mutate(
      { audience, special_notes: notes },
      { onSuccess: report => setActive(report) },
    )
  }

  const handleDelete = (reportId: string) => {
    deleteReport.mutate(reportId, {
      onSuccess: () => {
        if (active?.report_id === reportId) setActive(null)
        setPendingDeleteId(null)
      },
    })
  }

  return (
    <div className="h-full overflow-y-auto bg-background">
      <div className="mx-auto max-w-5xl space-y-6 p-4 sm:p-6">
        <section className="space-y-4 rounded-xl border border-border bg-surface p-4 sm:p-5">
          <h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Generate intelligence product
          </h2>
          <label className="block">
            <span className="mb-1.5 block text-xs text-muted-foreground">Audience</span>
            <Select value={audience} onChange={e => setAudience(e.target.value)}>
              {AUDIENCES.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </Select>
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs text-muted-foreground">
              Special analyst notes
            </span>
            <Textarea
              rows={3}
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="Caveats, distribution restrictions, or known gaps…"
            />
          </label>
          {generateReport.error && (
            <p role="alert" className="text-sm text-danger">
              {(generateReport.error as Error).message ?? 'The report could not be generated.'}
            </p>
          )}
          <Button onClick={handleGenerate} disabled={generateReport.isPending}>
            {generateReport.isPending ? 'Generating…' : 'Generate report'}
          </Button>
        </section>

        {active && (
          <article className="rounded-xl border border-border bg-surface">
            <header className="flex items-start justify-between border-b border-border p-4">
              <div>
                <h2 className="text-sm font-medium text-foreground">{active.title}</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  {active.classification} · {new Date(active.generated_at).toLocaleString()}
                </p>
              </div>
              {pendingDeleteId === active.report_id ? (
                <div className="flex gap-1">
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={deleteReport.isPending}
                    onClick={() => handleDelete(active.report_id)}
                  >
                    Confirm
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setPendingDeleteId(null)}>
                    Cancel
                  </Button>
                </div>
              ) : (
                <Button
                  size="sm"
                  variant="ghost"
                  className="hover:text-danger"
                  onClick={() => setPendingDeleteId(active.report_id)}
                >
                  Delete
                </Button>
              )}
            </header>
            <div className="prose prose-invert prose-sm max-w-none p-5">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{active.content}</ReactMarkdown>
            </div>
          </article>
        )}

        {reports.length > 0 && (
          <section>
            <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Saved reports ({reports.length})
            </h2>
            <div className="space-y-2">
              {[...reports].reverse().map(report => (
                <div
                  key={report.report_id}
                  className="flex items-center gap-3 rounded-lg border border-border bg-surface p-3"
                >
                  <button
                    type="button"
                    className="min-w-0 flex-1 text-left"
                    onClick={() =>
                      setActive(active?.report_id === report.report_id ? null : report)
                    }
                  >
                    <span className="block truncate text-sm text-foreground">{report.title}</span>
                    <span className="mt-1 block text-xs text-muted-foreground">
                      {report.classification} · {new Date(report.generated_at).toLocaleString()}
                    </span>
                  </button>
                  {pendingDeleteId === report.report_id ? (
                    <div className="flex gap-1">
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={deleteReport.isPending}
                        onClick={() => handleDelete(report.report_id)}
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
                    </div>
                  ) : (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="hover:text-danger"
                      onClick={() => setPendingDeleteId(report.report_id)}
                    >
                      Delete
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  )
}
