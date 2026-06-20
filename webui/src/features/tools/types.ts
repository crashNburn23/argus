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
