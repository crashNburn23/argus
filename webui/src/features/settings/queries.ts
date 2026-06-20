import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { settingsApi } from './api'
import type { UpdateSettingsPayload } from './types'

export const settingsKeys = {
  all: ['settings'] as const,
  tools: ['settings', 'tools'] as const,
  agents: ['settings', 'agents'] as const,
}

export function useSettings() {
  return useQuery({ queryKey: settingsKeys.all, queryFn: settingsApi.get })
}

export function useTools() {
  return useQuery({ queryKey: settingsKeys.tools, queryFn: settingsApi.getTools })
}

export function useAgents() {
  return useQuery({ queryKey: settingsKeys.agents, queryFn: settingsApi.getAgents })
}

export function useUpdateSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: UpdateSettingsPayload) => settingsApi.update(payload),
    onSuccess: data => {
      queryClient.setQueryData(settingsKeys.all, data)
    },
  })
}
