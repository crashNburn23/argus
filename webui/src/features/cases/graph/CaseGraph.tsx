import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Maximize2, Search } from 'lucide-react'
import { Background, BackgroundVariant, Controls, MarkerType, MiniMap, ReactFlow, useEdgesState, useNodesState, type Edge, type ReactFlowInstance } from '@xyflow/react'
import { api } from '../../../api/client'
import EmptyState from '../../../components/EmptyState'
import ErrorState from '../../../components/ErrorState'
import LoadingState from '../../../components/LoadingState'
import Button from '../../../components/ui/Button'
import Input from '../../../components/ui/Input'
import { cn } from '../../../lib/cn'
import CtiNode, { type CtiFlowNode } from './CtiNode'
import GraphDetails from './GraphDetails'
import { layoutCaseGraph } from './layout'
import type { CaseGraphData, GraphRelationship, GraphSelection } from './types'

const nodeTypes = { cti: CtiNode }
const typeOrder = ['ip', 'domain', 'url', 'sha256', 'sha1', 'md5', 'cve', 'email', 'actor', 'malware', 'attack_ttp', 'unknown']

function withMembershipEdges(caseId: string, graph: CaseGraphData): CaseGraphData {
  if (graph.edges.length > 0 || graph.nodes.length === 0) return graph
  const rootId = `case:${caseId}`
  return {
    nodes: [{ id: rootId, label: 'Case', type: 'case', manually_added: false, argus_discovered: false, confidence: 0, source: '', evidence: [], synthetic: true }, ...graph.nodes],
    edges: graph.nodes.map(node => ({ id: `${rootId}:${node.id}`, source: rootId, target: node.id, source_label: 'Case', target_label: node.label, label: 'in case', confidence: 0, rationale: '', evidence: [], synthetic: true })),
  }
}

export default function CaseGraph({ caseId }: { caseId: string }) {
  const query = useQuery({ queryKey: ['cases', 'detail', caseId, 'graph'], queryFn: () => api.get<CaseGraphData>(`/api/cases/${encodeURIComponent(caseId)}/graph`) })
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set())
  const [search, setSearch] = useState('')
  const [selection, setSelection] = useState<GraphSelection | null>(null)
  const [flow, setFlow] = useState<ReactFlowInstance<CtiFlowNode, Edge<{ relationship: GraphRelationship }>> | null>(null)
  const [nodes, setNodes, onNodesChange] = useNodesState<CtiFlowNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<{ relationship: GraphRelationship }>>([])
  const graph = query.data
  const types = useMemo(() => graph ? [...new Set(graph.nodes.map(node => node.type || 'unknown'))].sort((a, b) => typeOrder.indexOf(a) - typeOrder.indexOf(b)) : [], [graph])
  const visibleGraph = useMemo(() => {
    if (!graph) return null
    const normalized = search.trim().toLowerCase()
    const visibleNodes = graph.nodes.filter(node => !hiddenTypes.has(node.type || 'unknown') && (!normalized || node.label.toLowerCase().includes(normalized) || node.type.toLowerCase().includes(normalized)))
    const ids = new Set(visibleNodes.map(node => node.id))
    return withMembershipEdges(caseId, { nodes: visibleNodes, edges: graph.edges.filter(edge => ids.has(edge.source) && ids.has(edge.target)) })
  }, [caseId, graph, hiddenTypes, search])

  useEffect(() => {
    if (!visibleGraph) return
    let cancelled = false
    void layoutCaseGraph(visibleGraph).then(positions => {
      if (cancelled) return
      setNodes(visibleGraph.nodes.map(entity => ({ id: entity.id, type: 'cti', position: positions.get(entity.id) ?? { x: 0, y: 0 }, data: { entity } })))
      setEdges(visibleGraph.edges.map(relationship => ({ id: relationship.id, source: relationship.source, target: relationship.target, label: relationship.synthetic ? undefined : relationship.label, data: { relationship }, markerEnd: { type: MarkerType.ArrowClosed, color: '#64748b' }, style: { stroke: '#64748b', strokeWidth: relationship.synthetic ? 1 : 2, strokeDasharray: relationship.synthetic ? '4 5' : undefined }, labelStyle: { fill: '#94a3b8', fontSize: 11 }, labelBgStyle: { fill: '#0f141d', fillOpacity: 0.9 } })))
      window.setTimeout(() => void flow?.fitView({ padding: 0.2, duration: 250 }), 0)
    })
    return () => { cancelled = true }
  }, [flow, setEdges, setNodes, visibleGraph])

  useEffect(() => { if (selection?.kind === 'node' && hiddenTypes.has(selection.data.type)) setSelection(null) }, [hiddenTypes, selection])

  if (query.isPending) return <LoadingState label="Laying out investigation graph" />
  if (query.isError) return <div className="p-6"><ErrorState message="Argus could not load the graph." onRetry={() => void query.refetch()} /></div>
  if (!graph || graph.nodes.length === 0) return <div className="p-6"><EmptyState title="No graph entities" description="Add observables and run a review to populate the investigation graph." /></div>

  const toggleType = (type: string) => setHiddenTypes(current => { const next = new Set(current); next.has(type) ? next.delete(type) : next.add(type); return next })
  const resetFilters = () => { setHiddenTypes(new Set()); setSearch('') }
  return <div className="flex h-full flex-col bg-background">
    <div className="shrink-0 space-y-2 border-b border-border bg-surface px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <label className="relative min-w-48 flex-1 sm:max-w-64">
          <span className="sr-only">Search graph entities</span>
          <Search className="pointer-events-none absolute left-2.5 top-2 size-3.5 text-muted-foreground" aria-hidden="true" />
          <Input className="h-8 pl-8 text-xs" value={search} onChange={event => setSearch(event.target.value)} placeholder="Find entity" />
        </label>
        <Button size="sm" variant="secondary" onClick={() => void flow?.fitView({ padding: 0.2, duration: 250 })}><Maximize2 className="size-3.5" aria-hidden="true" />Fit view</Button>
        {(hiddenTypes.size > 0 || search) && <Button size="sm" variant="ghost" onClick={resetFilters}>Reset filters</Button>}
        <span className="ml-auto text-xs text-muted-foreground">{visibleGraph?.nodes.filter(node => !node.synthetic).length ?? 0}/{graph.nodes.length} entities · {visibleGraph?.edges.filter(edge => !edge.synthetic).length ?? 0}/{graph.edges.length} relationships</span>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-[11px] text-muted-foreground">Entity types</span>
        {types.map(type => <button key={type} type="button" aria-pressed={!hiddenTypes.has(type)} onClick={() => toggleType(type)} className={cn('rounded border border-accent/20 bg-accent/10 px-2 py-1 font-mono text-[11px] text-accent transition', hiddenTypes.has(type) && 'border-border bg-muted text-muted-foreground opacity-45 line-through')}>{type}</button>)}
        <span className="ml-auto hidden items-center gap-3 text-[10px] text-muted-foreground sm:flex"><span><i className="mr-1 inline-block size-1.5 rounded-full bg-accent" />manual</span><span><i className="mr-1 inline-block size-1.5 rounded-full bg-success" />discovered</span></span>
      </div>
    </div>
    <div className="relative min-h-0 flex-1">
      <ReactFlow<CtiFlowNode, Edge<{ relationship: GraphRelationship }>> nodes={nodes} edges={edges} nodeTypes={nodeTypes} onInit={setFlow} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={(_, node) => setSelection({ kind: 'node', data: node.data.entity })} onEdgeClick={(_, edge) => edge.data && setSelection({ kind: 'edge', data: edge.data.relationship })} onPaneClick={() => setSelection(null)} fitView fitViewOptions={{ padding: 0.2 }} minZoom={0.2} maxZoom={2.5} nodesConnectable={false} proOptions={{ hideAttribution: true }}>
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#334155" />
        <Controls showInteractive={false} className="!border-border !bg-surface !shadow-lg" />
        <MiniMap pannable zoomable nodeColor="#2563eb" maskColor="rgba(9,12,18,.72)" className="!border !border-border !bg-surface" />
      </ReactFlow>
      {selection && <GraphDetails selection={selection} edges={visibleGraph?.edges ?? []} onClose={() => setSelection(null)} />}
    </div>
  </div>
}
