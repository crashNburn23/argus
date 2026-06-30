import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { caseKeys } from '../queries'
import { caseDetailApi } from './api'
import type { CaseDetailData, ObservableInput } from './types'

export const caseDetailKey = (caseId: string) =>
  [...caseKeys.all, 'detail', caseId] as const

export function useCaseDetail(caseId: string | undefined) {
  return useQuery({
    queryKey: caseDetailKey(caseId ?? ''),
    queryFn: () => caseDetailApi.get(caseId!),
    enabled: Boolean(caseId),
  })
}

// Shared factory: mutations that return updated CaseDetailData write it to cache directly.
function useDetailMutation<TVariables>(
  caseId: string,
  mutationFn: (vars: TVariables) => Promise<CaseDetailData>,
) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn,
    onSuccess: data => {
      queryClient.setQueryData(caseDetailKey(caseId), data)
    },
  })
}

export function useUpdateCase(caseId: string) {
  return useDetailMutation(caseId, (input: Record<string, unknown>) =>
    caseDetailApi.update(caseId, input),
  )
}

export function useAddObservables(caseId: string) {
  return useDetailMutation(caseId, (observables: ObservableInput[]) =>
    caseDetailApi.addObservables(caseId, observables),
  )
}

export function useAddNote(caseId: string) {
  return useDetailMutation(caseId, (body: string) =>
    caseDetailApi.addNote(caseId, body),
  )
}

export function useUpdateNote(caseId: string) {
  return useDetailMutation(
    caseId,
    ({ noteId, patch }: { noteId: string; patch: { body?: string; analyst_review?: string } }) =>
      caseDetailApi.updateNote(caseId, noteId, patch),
  )
}

export function useDeleteNote(caseId: string) {
  return useDetailMutation(caseId, (noteId: string) =>
    caseDetailApi.deleteNote(caseId, noteId),
  )
}

export function useReanalyzeNote(caseId: string) {
  return useDetailMutation(
    caseId,
    ({ noteId, feedback }: { noteId: string; feedback?: string }) =>
      caseDetailApi.reanalyzeNote(caseId, noteId, feedback),
  )
}

export function useSubmitFeedback(caseId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      noteId,
      correct,
      correction,
    }: { noteId: string; correct: boolean; correction: string }) =>
      caseDetailApi.submitFeedback(caseId, noteId, correct, correction),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: caseDetailKey(caseId) })
    },
  })
}

export function useAddReference(caseId: string) {
  return useDetailMutation(
    caseId,
    (input: { url: string; title: string; needs_review: boolean }) =>
      caseDetailApi.addReference(caseId, input),
  )
}

export function useUpdateReference(caseId: string) {
  return useDetailMutation(
    caseId,
    ({ refId, input }: { refId: string; input: Record<string, unknown> }) =>
      caseDetailApi.updateReference(caseId, refId, input),
  )
}

export function useDeleteReference(caseId: string) {
  return useDetailMutation(caseId, (refId: string) =>
    caseDetailApi.deleteReference(caseId, refId),
  )
}

export function useDeleteReport(caseId: string) {
  return useDetailMutation(caseId, (reportId: string) =>
    caseDetailApi.deleteReport(caseId, reportId),
  )
}

export function useGenerateReport(caseId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { audience: string; special_notes: string }) =>
      caseDetailApi.generateReport(caseId, input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: caseDetailKey(caseId) })
    },
  })
}

export function useReviewCase(caseId: string) {
  return useDetailMutation(
    caseId,
    (input: { observable_ids: string[]; note_ids: string[]; reference_ids: string[] }) =>
      caseDetailApi.review(caseId, input),
  )
}
