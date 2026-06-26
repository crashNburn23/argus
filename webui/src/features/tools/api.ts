import { api } from '../../api/client'
import type { ToolFile, ToolFileContent, ToolStatus } from './types'

export const toolsApi = {
  listFiles: () => api.get<ToolFile[]>('/api/tools/files'),
  listStatuses: () => api.get<ToolStatus[]>('/api/tools'),
  getFile: (filename: string) =>
    api.get<ToolFileContent>(`/api/tools/files/${encodeURIComponent(filename)}`),
}
