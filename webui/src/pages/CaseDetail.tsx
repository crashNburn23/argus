import { lazy, Suspense, useState } from 'react'
import { useParams } from 'react-router-dom'
import { ApiError } from '../api/client'
import ErrorState from '../components/ErrorState'
import LoadingState from '../components/LoadingState'
import CaseChat from '../features/cases/detail/CaseChat'
import CaseOverview from '../features/cases/detail/CaseOverview'
import CaseNotes from '../features/cases/detail/CaseNotes'
import CaseReferences from '../features/cases/detail/CaseReferences'
import CaseReports from '../features/cases/detail/CaseReports'
import ReviewScopeDialog from '../features/cases/detail/ReviewScopeDialog'
import CaseWorkspaceHeader from '../features/cases/detail/CaseWorkspaceHeader'
import { useCaseDetail, useUpdateCase, useReviewCase } from '../features/cases/detail/queries'
import type { CaseTabId as TabId } from '../features/cases/detail/types'

const IocGraph = lazy(() => import('../features/cases/graph/CaseGraph'))

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: caseData, isPending: loading, isError, refetch } = useCaseDetail(id)
  const updateCase = useUpdateCase(id ?? '')
  const reviewCase = useReviewCase(id ?? '')
  const [activeTab, setActiveTab] = useState<TabId>('overview')

  // Review modal state
  const [showReviewModal, setShowReviewModal] = useState(false)
  const [selectedObsIds, setSelectedObsIds] = useState<Set<string>>(new Set())
  const [selectedNoteIds, setSelectedNoteIds] = useState<Set<string>>(new Set())
  const [selectedRefIds, setSelectedRefIds] = useState<Set<string>>(new Set())
  const [reviewing, setReviewing] = useState(false)
  const [reviewError, setReviewError] = useState('')
  const [analysisCount, setAnalysisCount] = useState(0)
  const [analysisComplete, setAnalysisComplete] = useState(false)

  const openReviewModal = () => {
    if (!caseData) return
    setSelectedObsIds(
      new Set(
        caseData.observables
          .filter(o => o.labels.includes('manually_added'))
          .map(o => o.observable_id),
      ),
    )
    setSelectedNoteIds(
      new Set(
        caseData.notes.filter(n => n.metadata?.source === 'manual').map(n => n.note_id),
      ),
    )
    setSelectedRefIds(
      new Set((caseData.references ?? []).filter(r => r.needs_review).map(r => r.ref_id)),
    )
    setReviewError('')
    setShowReviewModal(true)
  }

  const confirmReview = async () => {
    const count = selectedObsIds.size + selectedNoteIds.size + selectedRefIds.size
    setShowReviewModal(false)
    setReviewing(true)
    setAnalysisCount(count)
    setAnalysisComplete(false)
    setReviewError('')
    try {
      await reviewCase.mutateAsync({
        observable_ids: [...selectedObsIds],
        note_ids: [...selectedNoteIds],
        reference_ids: [...selectedRefIds],
      })
      setActiveTab('notes')
      setAnalysisComplete(true)
    } catch (error) {
      setReviewError(
        error instanceof ApiError ? error.message : 'Network error — review may have timed out',
      )
    } finally {
      setReviewing(false)
    }
  }

  if (loading) return <LoadingState label="Loading case workspace" />
  if (isError || !caseData) return (
    <div className="p-6">
      <ErrorState
        title="Case unavailable"
        message="Argus could not load this case."
        onRetry={() => void refetch()}
      />
    </div>
  )

  const manualObs = caseData.observables.filter(o => o.labels.includes('manually_added'))
  const manualNotes = caseData.notes.filter(n => n.metadata?.source === 'manual')
  const pendingRefs = (caseData.references ?? []).filter(r => r.needs_review)
  const pendingRefCount = pendingRefs.length
  const reviewableCount = manualObs.length + manualNotes.length + pendingRefCount

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {showReviewModal && (
        <ReviewScopeDialog
          observables={manualObs}
          notes={manualNotes}
          references={pendingRefs}
          selectedObservables={selectedObsIds}
          selectedNotes={selectedNoteIds}
          selectedReferences={selectedRefIds}
          onSelectedObservables={setSelectedObsIds}
          onSelectedNotes={setSelectedNoteIds}
          onSelectedReferences={setSelectedRefIds}
          onCancel={() => setShowReviewModal(false)}
          onConfirm={() => void confirmReview()}
        />
      )}

      {reviewing && (
        <div className="flex flex-none items-center gap-3 border-b border-success/20 bg-success/10 px-6 py-2">
          <span className="inline-block size-3.5 flex-none animate-spin rounded-full border border-success border-t-transparent" />
          <span className="text-sm text-success">
            Analyzing {analysisCount} {analysisCount === 1 ? 'item' : 'items'} — results will appear in Notes when complete.
          </span>
        </div>
      )}
      {analysisComplete && !reviewing && (
        <div className="flex flex-none items-center justify-between gap-3 border-b border-success/20 bg-success/10 px-4 py-2 sm:px-6">
          <span className="text-sm text-success">Analysis complete. Review the generated findings in Notes.</span>
          <button type="button" onClick={() => setAnalysisComplete(false)} className="flex-none text-xs text-success/70 hover:text-success">Dismiss</button>
        </div>
      )}
      {reviewError && !reviewing && (
        <div className="flex flex-none items-center justify-between gap-3 border-b border-danger/20 bg-danger/10 px-6 py-2">
          <span className="text-sm text-danger">{reviewError}</span>
          <button
            type="button"
            onClick={() => setReviewError('')}
            className="flex-none text-xs text-danger/70 hover:text-danger"
          >
            Dismiss
          </button>
        </div>
      )}

      <CaseWorkspaceHeader
        caseData={caseData}
        activeTab={activeTab}
        pendingReferenceCount={pendingRefCount}
        reviewableCount={reviewableCount}
        onTabChange={setActiveTab}
        onReview={openReviewModal}
        onStatusChange={status => updateCase.mutate({ status })}
      />

      <div className="flex-1 overflow-hidden">
        {activeTab === 'overview' && <CaseOverview caseData={caseData} />}

        {activeTab === 'graph' && id && (
          <div className="h-full">
            <Suspense fallback={<LoadingState label="Loading graph workspace" />}>
              <IocGraph caseId={id} key={`graph-${caseData.updated_at}`} />
            </Suspense>
          </div>
        )}

        {activeTab === 'chat' && id && <CaseChat caseId={id} />}

        {activeTab === 'notes' && id && <CaseNotes caseId={id} notes={caseData.notes} />}

        {activeTab === 'references' && id && (
          <CaseReferences caseId={id} references={caseData.references} />
        )}

        {activeTab === 'report' && id && <CaseReports caseId={id} reports={caseData.reports} />}
      </div>
    </div>
  )
}
