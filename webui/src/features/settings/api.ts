import { api } from '../../api/client'
import type { Agent, AppSettings, Tool, UpdateSettingsPayload } from './types'

export const settingsApi = {
  get: () => api.get<AppSettings>('/api/settings'),
  update: (payload: UpdateSettingsPayload) => api.patch<AppSettings>('/api/settings', payload),
  getTools: () => api.get<Tool[]>('/api/tools'),
  getAgents: () => api.get<Agent[]>('/api/agents'),
}
