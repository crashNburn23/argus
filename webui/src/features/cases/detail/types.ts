export interface CaseObservable {
  observable_id: string
  value: string
  observable_type: string
  labels: string[]
  confidence: number
  metadata: Record<string, unknown>
}

export interface CaseNote {
  note_id: string
  body: string
  author: string
  created_at: string
  metadata: Record<string, unknown>
}

export interface CaseReference {
  ref_id: string
  url: string
  title: string
  added_by: string
  added_at: string
  needs_review: boolean
  metadata: Record<string, unknown>
}

export interface CaseReport {
  report_id: string
  report_type: string
  title: string
  classification: string
  generated_at: string
  content: string
  metadata: Record<string, unknown>
}

export interface CasePir {
  question: string
  priority: string
}

export interface CaseDetailData {
  case_id: string
  title: string
  status: string
  classification: string
  description: string
  created_at: string
  updated_at: string
  observables: CaseObservable[]
  notes: CaseNote[]
  references: CaseReference[]
  reports: CaseReport[]
  pirs: CasePir[]
  tags: string[]
}

export interface ObservableInput {
  value: string
  observable_type: string
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system'
  content: string
  streaming?: boolean
}

export type CaseTabId = 'overview' | 'chat' | 'notes' | 'references' | 'report' | 'graph'
