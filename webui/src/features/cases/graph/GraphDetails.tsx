import { X } from 'lucide-react'
import Button from '../../../components/ui/Button'
import type { GraphEntity, GraphEvidence, GraphRelationship, GraphSelection } from './types'

export default function GraphDetails({ selection, edges, onClose }: { selection: GraphSelection; edges: GraphRelationship[]; onClose: () => void }) {
  return <aside className="absolute inset-y-0 right-0 z-20 w-full overflow-y-auto border-l border-border bg-surface shadow-2xl sm:w-96">
    <header className="sticky top-0 flex items-center justify-between border-b border-border bg-surface p-4"><span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{selection.kind === 'node' ? 'Entity' : 'Relationship'}</span><Button variant="ghost" size="icon" onClick={onClose} aria-label="Close details"><X className="size-4" /></Button></header>
    {selection.kind === 'node' ? <NodeDetails node={selection.data} edges={edges} /> : <EdgeDetails edge={selection.data} />}
  </aside>
}

function NodeDetails({ node, edges }: { node: GraphEntity; edges: GraphRelationship[] }) {
  const related = edges.filter(edge => edge.source === node.id || edge.target === node.id)
  return <div className="space-y-5 p-4"><Field label="Value"><p className="break-all font-mono text-sm text-foreground">{node.label}</p></Field><div className="flex flex-wrap gap-2"><Badge>{node.type}</Badge>{node.manually_added && <Badge>manual</Badge>}{node.argus_discovered && <Badge>discovered</Badge>}</div>{node.confidence > 0 && <Field label="Confidence"><p>{Math.round(node.confidence * 100)}%</p></Field>}{node.source && <Field label="Source"><p className="font-mono text-xs">{node.source}</p></Field>}<EvidenceList evidence={node.evidence ?? []} />{related.length > 0 && <Field label={`Relationships (${related.length})`}><div className="space-y-2">{related.map(edge => <div key={edge.id} className="rounded-lg border border-border bg-background p-3 text-xs"><strong className="text-foreground">{edge.label}</strong><p className="mt-1 truncate font-mono text-muted-foreground">{edge.source === node.id ? `→ ${edge.target_label}` : `← ${edge.source_label}`}</p>{edge.rationale && <p className="mt-2 text-muted-foreground">{edge.rationale}</p>}</div>)}</div></Field>}</div>
}

function EdgeDetails({ edge }: { edge: GraphRelationship }) {
  return <div className="space-y-5 p-4"><Field label="Relationship"><p className="font-medium capitalize text-foreground">{edge.label}</p></Field><Field label="Source"><p className="break-all font-mono text-xs">{edge.source_label}</p></Field><Field label="Target"><p className="break-all font-mono text-xs">{edge.target_label}</p></Field>{edge.confidence > 0 && <Field label="Confidence"><p>{Math.round(edge.confidence * 100)}%</p></Field>}{edge.rationale && <Field label="Rationale"><p className="text-sm leading-5">{edge.rationale}</p></Field>}<EvidenceList evidence={edge.evidence ?? []} /></div>
}

function Field({ label, children }: { label: string; children: React.ReactNode }) { return <section><h3 className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</h3><div className="text-muted-foreground">{children}</div></section> }
function Badge({ children }: { children: React.ReactNode }) { return <span className="rounded bg-muted px-2 py-1 font-mono text-xs text-muted-foreground">{children}</span> }
function EvidenceList({ evidence }: { evidence: GraphEvidence[] }) { if (!evidence.length) return null; return <Field label={`Evidence (${evidence.length})`}><div className="space-y-2">{evidence.map(item => <div key={item.id} className="rounded-lg border border-border bg-background p-3 text-xs"><div className="flex justify-between gap-2"><span className="truncate font-mono text-foreground">{item.source || 'unknown source'}</span>{item.confidence > 0 && <span>{Math.round(item.confidence * 100)}%</span>}</div>{(item.summary || item.inference_basis) && <p className="mt-2 text-muted-foreground">{item.summary || item.inference_basis}</p>}{item.reference && <p className="mt-2 truncate font-mono text-muted-foreground">{item.reference}</p>}</div>)}</div></Field> }
