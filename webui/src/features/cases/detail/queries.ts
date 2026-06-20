import { useQuery } from '@tanstack/react-query'
import { caseKeys } from '../queries'
import { caseDetailApi } from './api'

export function useCaseDetail(caseId: string | undefined) {
  return useQuery({
    queryKey: [...caseKeys.all, 'detail', caseId] as const,
    queryFn: () => caseDetailApi.get(caseId!),
    enabled: Boolean(caseId),
  })
}
