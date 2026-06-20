import { api } from '../../api/client'
import type { ToolFile, ToolFileContent } from './types'

export const toolsApi = {
  listFiles: () => api.get<ToolFile[]>('/api/tools/files'),
  getFile: (filename: string) =>
    api.get<ToolFileContent>(`/api/tools/files/${encodeURIComponent(filename)}`),
}
