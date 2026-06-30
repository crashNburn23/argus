export interface ToolFile {
  filename: string
  stem: string
  tool_names: string[]
  available: boolean | null
  size: number
}

export interface ToolFileContent {
  filename: string
  content: string
}

export interface ToolStatus {
  name: string
  available: boolean
  reason?: string
  configured?: boolean
  blocked?: boolean
  locality?: string
  data_sent?: string
}
