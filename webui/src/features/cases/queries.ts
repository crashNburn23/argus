import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createCase, deleteCase, listCases } from './api'

export const caseKeys = {
  all: ['cases'] as const,
  lists: () => [...caseKeys.all, 'list'] as const,
}

export function useCases() {
  return useQuery({
    queryKey: caseKeys.lists(),
    queryFn: listCases,
  })
}

export function useCreateCase() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: createCase,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: caseKeys.lists() })
    },
  })
}

export function useDeleteCase() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: deleteCase,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: caseKeys.lists() })
    },
  })
}
