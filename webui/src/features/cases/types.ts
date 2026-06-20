export interface CaseSummary {
  case_id: string
  title: string
  status: string
  classification: string
  description: string
  created_at: string
  updated_at: string
  observable_count: number
  evidence_count: number
  note_count: number
  pir_count: number
  report_count: number
  tags: string[]
}

export interface CreateCaseInput {
  title: string
  description: string
  classification: string
}

export interface CreatedCase {
  case_id: string
  title: string
}

export type CaseSort = 'updated' | 'created' | 'title'
