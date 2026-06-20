import { lazy, Suspense, useState, useCallback } from 'react'
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
import { caseDetailApi } from '../features/cases/detail/api'
import { useCaseDetail } from '../features/cases/detail/queries'
import type { CaseTabId as TabId } from '../features/cases/detail/types'

const IocGraph = lazy(() => import('../features/cases/graph/CaseGraph'))

// ── Constants ──────────────────────────────────────────────────────────────────

// ── Component ──────────────────────────────────────────────────────────────────

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: caseData, isPending: loading, isError, refetch } = useCaseDetail(id)
  const loadCase = useCallback(() => { void refetch() }, [refetch])
  const [activeTab, setActiveTab] = useState<TabId>('overview')

  // Review modal state
  const [showReviewModal, setShowReviewModal] = useState(false)
  const [selectedObsIds, setSelectedObsIds] = useState<Set<string>>(new Set())
  const [selectedNoteIds, setSelectedNoteIds] = useState<Set<string>>(new Set())
  const [selectedRefIds, setSelectedRefIds] = useState<Set<string>>(new Set())
  const [reviewing, setReviewing] = useState(false)
  const [reviewError, setReviewError] = useState('')

  // ── Review modal init ─────────────────────────────────────────────────────────

  const openReviewModal = () => {
    if (!caseData) return
    const obsIds = new Set(
      caseData.observables.filter(o => o.labels.includes('manually_added')).map(o => o.observable_id)
    )
    const noteIds = new Set(
      caseData.notes.filter(n => n.metadata?.source === 'manual').map(n => n.note_id)
    )
    const refIds = new Set(
      (caseData.references ?? []).filter(r => r.needs_review).map(r => r.ref_id)
    )
    setSelectedObsIds(obsIds)
    setSelectedNoteIds(noteIds)
    setSelectedRefIds(refIds)
    setReviewError('')
    setShowReviewModal(true)
  }

  // ── Actions ───────────────────────────────────────────────────────────────────

  const updateStatus = (status: string) => {
    if (!id) return
    void caseDetailApi.update(id, { status }).then(loadCase)
  }

  const confirmReview = async () => {
    if (!id) return
    setShowReviewModal(false)  // close immediately — analysis runs in background
    setReviewing(true)
    setReviewError('')
    try {
      await caseDetailApi.review(id, {
          observable_ids: [...selectedObsIds],
          note_ids: [...selectedNoteIds],
          reference_ids: [...selectedRefIds],
      })
      setActiveTab('notes')
      loadCase()
    } catch (error) {
      setReviewError(error instanceof ApiError ? error.message : 'Network error — review may have timed out')
    } finally {
      setReviewing(false)
    }
  }

  // ── Render helpers ────────────────────────────────────────────────────────────

  if (loading) return <LoadingState label="Loading case workspace" />
  if (isError || !caseData) return <div className="p-6"><ErrorState title="Case unavailable" message="Argus could not load this case." onRetry={() => void refetch()} /></div>

  const manualObs = caseData.observables.filter(o => o.labels.includes('manually_added'))
  const manualNotes = caseData.notes.filter(n => n.metadata?.source === 'manual')
  const pendingRefs = (caseData.references ?? []).filter(r => r.needs_review)
  const pendingRefCount = pendingRefs.length
  const reviewableCount = manualObs.length + manualNotes.length + pendingRefCount

  return (
    <div className="flex flex-col h-full overflow-hidden">

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

      {/* ── Review status banner ── */}
      {reviewing && (
        <div className="flex-none px-6 py-2 bg-emerald-950 border-b border-emerald-800 flex items-center gap-3">
          <span className="animate-spin inline-block w-3.5 h-3.5 border border-emerald-400 border-t-transparent rounded-full flex-none" />
          <span className="text-sm text-emerald-300">Argus is analyzing — results will appear in Notes when complete.</span>
        </div>
      )}
      {reviewError && !reviewing && (
        <div className="flex-none px-6 py-2 bg-red-950 border-b border-red-800 flex items-center justify-between gap-3">
          <span className="text-sm text-red-300">{reviewError}</span>
          <button onClick={() => setReviewError('')} className="text-red-400 hover:text-red-200 text-xs flex-none">Dismiss</button>
        </div>
      )}

      <CaseWorkspaceHeader
        caseData={caseData}
        activeTab={activeTab}
        pendingReferenceCount={pendingRefCount}
        reviewableCount={reviewableCount}
        onTabChange={setActiveTab}
        onReview={openReviewModal}
        onStatusChange={updateStatus}
      />

      {/* ── Tab content ── */}
      <div className="flex-1 overflow-hidden">

        {/* OVERVIEW */}
        {activeTab === 'overview' && (
          <CaseOverview caseData={caseData} onCaseChanged={loadCase} />
        )}

        {/* GRAPH */}
        {activeTab === 'graph' && id && (
          <div className="h-full">
            <Suspense fallback={<LoadingState label="Loading graph workspace" />}>
              <IocGraph caseId={id} key={`graph-${caseData.updated_at}`} />
            </Suspense>
          </div>
        )}

        {/* CHAT */}
        {activeTab === 'chat' && (
          id && <CaseChat caseId={id} onCaseChanged={loadCase} />
        )}

        {/* NOTES */}
        {activeTab === 'notes' && id && (
          <CaseNotes caseId={id} notes={caseData.notes} onCaseChanged={loadCase} />
        )}

        {/* REFERENCES */}
        {activeTab === 'references' && id && <CaseReferences caseId={id} references={caseData.references} onCaseChanged={loadCase} />}

        {/* REPORT */}
        {activeTab === 'report' && id && <CaseReports caseId={id} reports={caseData.reports} onCaseChanged={loadCase} />}

      </div>
    </div>
  )
}
