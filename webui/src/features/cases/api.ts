import { api } from '../../api/client'
import type { CaseSummary, CreatedCase, CreateCaseInput } from './types'

export function listCases() {
  return api.get<CaseSummary[]>('/api/cases')
}

export function createCase(input: CreateCaseInput) {
  return api.post<CreatedCase>('/api/cases', input)
}

export function deleteCase(caseId: string) {
  return api.delete<{ deleted: boolean }>(`/api/cases/${caseId}`)
}
