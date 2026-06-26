import { useQuery } from '@tanstack/react-query'
import { toolsApi } from './api'

export const toolsKeys = {
  files: ['tools', 'files'] as const,
  statuses: ['tools', 'statuses'] as const,
  file: (filename: string) => ['tools', 'files', filename] as const,
}

export function useToolFiles() {
  return useQuery({ queryKey: toolsKeys.files, queryFn: toolsApi.listFiles })
}

export function useToolStatuses() {
  return useQuery({ queryKey: toolsKeys.statuses, queryFn: toolsApi.listStatuses })
}

export function useToolFile(filename: string | null) {
  return useQuery({
    queryKey: toolsKeys.file(filename ?? ''),
    queryFn: () => toolsApi.getFile(filename!),
    enabled: !!filename,
  })
}
