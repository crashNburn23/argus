import { api } from '../../../api/client'
import type { CaseDetailData, CaseReport, ObservableInput } from './types'

const casePath = (caseId: string) => `/api/cases/${encodeURIComponent(caseId)}`

export const caseDetailApi = {
  get: (caseId: string) => api.get<CaseDetailData>(casePath(caseId)),
  update: (caseId: string, input: Record<string, unknown>) => api.patch<CaseDetailData>(casePath(caseId), input),
  addObservables: (caseId: string, observables: ObservableInput[]) =>
    api.post<CaseDetailData>(`${casePath(caseId)}/observables`, { observables }),
  addNote: (caseId: string, body: string) =>
    api.post<CaseDetailData>(`${casePath(caseId)}/notes`, { body, manually_added: true }),
  updateNote: (caseId: string, noteId: string, patch: { body?: string; analyst_review?: string }) =>
    api.patch<CaseDetailData>(`${casePath(caseId)}/notes/${encodeURIComponent(noteId)}`, patch),
  deleteNote: (caseId: string, noteId: string) =>
    api.delete<CaseDetailData>(`${casePath(caseId)}/notes/${encodeURIComponent(noteId)}`),
  reanalyzeNote: (caseId: string, noteId: string, feedback?: string) =>
    api.post<CaseDetailData>(`${casePath(caseId)}/notes/${encodeURIComponent(noteId)}/reanalyze`, feedback ? { feedback } : {}),
  submitFeedback: (caseId: string, noteId: string, correct: boolean, correction: string) =>
    api.post<{ saved: boolean }>(`${casePath(caseId)}/notes/${encodeURIComponent(noteId)}/feedback`, { correct, correction }),
  review: (caseId: string, input: { observable_ids: string[]; note_ids: string[]; reference_ids: string[] }) =>
    api.post<CaseDetailData>(`${casePath(caseId)}/review`, input),
  addReference: (caseId: string, input: { url: string; title: string; needs_review: boolean }) =>
    api.post<CaseDetailData>(`${casePath(caseId)}/references`, input),
  updateReference: (caseId: string, refId: string, input: Record<string, unknown>) =>
    api.patch<CaseDetailData>(`${casePath(caseId)}/references/${encodeURIComponent(refId)}`, input),
  deleteReference: (caseId: string, refId: string) =>
    api.delete<CaseDetailData>(`${casePath(caseId)}/references/${encodeURIComponent(refId)}`),
  generateReport: (caseId: string, input: { audience: string; special_notes: string }) =>
    api.post<CaseReport>(`${casePath(caseId)}/reports`, input),
  deleteReport: (caseId: string, reportId: string) =>
    api.delete<CaseDetailData>(`${casePath(caseId)}/reports/${encodeURIComponent(reportId)}`),
}
