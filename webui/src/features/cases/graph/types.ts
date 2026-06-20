export interface GraphEvidence {
  id: string
  source: string
  status: string
  confidence: number
  summary: string
  excerpt: string
  reference: string
  inference_basis: string
}

export interface GraphEntity {
  id: string
  label: string
  type: string
  manually_added: boolean
  argus_discovered: boolean
  confidence: number
  source: string
  evidence: GraphEvidence[]
  synthetic?: boolean
}

export interface GraphRelationship {
  id: string
  source: string
  target: string
  source_label: string
  target_label: string
  label: string
  confidence: number
  rationale: string
  evidence: GraphEvidence[]
  synthetic?: boolean
}

export interface CaseGraphData {
  nodes: GraphEntity[]
  edges: GraphRelationship[]
}

export type GraphSelection = { kind: 'node'; data: GraphEntity } | { kind: 'edge'; data: GraphRelationship }
