import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'

interface GraphNode {
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

interface GraphEvidence {
  id: string
  source: string
  status: string
  confidence: number
  summary: string
  excerpt: string
  reference: string
  inference_basis: string
}

interface GraphEdge {
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

interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

interface SelectedItem {
  kind: 'node' | 'edge'
  data: GraphNode | GraphEdge
}

// Node color by observable type — matches CaseDetail typeColor
const TYPE_COLORS: Record<string, string> = {
  case:      '#e4e4e7',
  ip:        '#3b82f6',  // blue
  domain:    '#8b5cf6',  // violet
  url:       '#6366f1',  // indigo
  sha256:    '#f59e0b',  // amber
  sha1:      '#f59e0b',
  md5:       '#f59e0b',
  cve:       '#ef4444',  // red
  email:     '#14b8a6',  // teal
  actor:     '#10b981',  // emerald
  malware:   '#f97316',  // orange
  attack_ttp:'#ec4899',  // pink
  unknown:   '#6b7280',  // gray
}

const TYPE_BG: Record<string, string> = {
  case:      'bg-zinc-700 text-zinc-100',
  ip:        'bg-blue-900 text-blue-200',
  domain:    'bg-violet-900 text-violet-200',
  url:       'bg-indigo-900 text-indigo-200',
  sha256:    'bg-amber-900 text-amber-200',
  sha1:      'bg-amber-900 text-amber-200',
  md5:       'bg-amber-900 text-amber-200',
  cve:       'bg-red-900 text-red-200',
  email:     'bg-teal-900 text-teal-200',
  actor:     'bg-emerald-900 text-emerald-200',
  malware:   'bg-orange-900 text-orange-200',
  attack_ttp:'bg-pink-900 text-pink-200',
  unknown:   'bg-zinc-800 text-zinc-400',
}

function nodeColor(type: string) {
  return TYPE_COLORS[type] ?? TYPE_COLORS.unknown
}

const RELATION_COLORS: Record<string, string> = {
  'derived from': '#22c55e',
  'resolves to': '#38bdf8',
  hosts: '#a78bfa',
  'attributed to': '#f472b6',
  uses: '#fb923c',
  exploits: '#ef4444',
  targets: '#facc15',
  evidences: '#94a3b8',
  indicates: '#2dd4bf',
  'observed in': '#818cf8',
  'in case': '#71717a',
}

function relationshipColor(label: string) {
  return RELATION_COLORS[label] ?? '#94a3b8'
}

function compactLabel(label: string, max = 30) {
  return label.length > max ? `${label.slice(0, max - 1)}…` : label
}

const TYPE_ORDER = ['ip', 'domain', 'url', 'sha256', 'sha1', 'md5', 'cve', 'email', 'actor', 'malware', 'attack_ttp', 'unknown']

export default function IocGraph({ caseId }: { caseId: string }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<SelectedItem | null>(null)
  const [error, setError] = useState('')
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(() => new Set())

  const clearSelection = () => {
    cyRef.current?.elements().unselect().removeClass('faded focused')
    setSelected(null)
  }

  // ── Fetch graph data ────────────────────────────────────────────────────────

  useEffect(() => {
    setLoading(true)
    fetch(`/api/cases/${caseId}/graph`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<GraphData>
      })
      .then(data => {
        setGraph(data)
        setLoading(false)
      })
      .catch(e => {
        setError(String(e))
        setLoading(false)
      })
  }, [caseId])

  const typeOptions = useMemo(() => {
    if (!graph) return []
    const types = new Set(graph.nodes.map(n => n.type || 'unknown'))
    return [...types].sort((a, b) => {
      const ai = TYPE_ORDER.indexOf(a)
      const bi = TYPE_ORDER.indexOf(b)
      if (ai === -1 && bi === -1) return a.localeCompare(b)
      if (ai === -1) return 1
      if (bi === -1) return -1
      return ai - bi
    })
  }, [graph])

  const visibleGraph = useMemo<GraphData | null>(() => {
    if (!graph) return null
    const nodes = graph.nodes.filter(n => !hiddenTypes.has(n.type || 'unknown'))
    const visibleNodeIds = new Set(nodes.map(n => n.id))
    return {
      nodes,
      edges: graph.edges.filter(e => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)),
    }
  }, [graph, hiddenTypes])

  useEffect(() => {
    if (!selected || !visibleGraph) return
    if (selected.kind === 'node') {
      const node = selected.data as GraphNode
      if (!visibleGraph.nodes.some(n => n.id === node.id)) setSelected(null)
      return
    }

    const edge = selected.data as GraphEdge
    if (!visibleGraph.edges.some(e => e.id === edge.id)) setSelected(null)
  }, [selected, visibleGraph])

  // ── Build Cytoscape instance ────────────────────────────────────────────────

  useEffect(() => {
    if (!visibleGraph || !containerRef.current) return

    // Destroy previous instance
    cyRef.current?.destroy()

    const hasExplicitEdges = visibleGraph.edges.length > 0
    const displayGraph: GraphData = hasExplicitEdges
      ? visibleGraph
      : {
          nodes: [
            {
              id: `case:${caseId}`,
              label: 'Case',
              type: 'case',
              manually_added: false,
              argus_discovered: false,
              confidence: 0,
              source: '',
              evidence: [],
              synthetic: true,
            },
            ...visibleGraph.nodes,
          ],
          edges: visibleGraph.nodes.map(n => ({
            id: `case:${caseId}:${n.id}`,
            source: `case:${caseId}`,
            target: n.id,
            source_label: 'Case',
            target_label: n.label,
            label: 'in case',
            confidence: 0,
            rationale: '',
            evidence: [],
            synthetic: true,
          })),
        }

    const degree = new Map<string, number>()
    displayGraph.nodes.forEach(n => degree.set(n.id, 0))
    displayGraph.edges.forEach(e => {
      degree.set(e.source, (degree.get(e.source) ?? 0) + 1)
      degree.set(e.target, (degree.get(e.target) ?? 0) + 1)
    })
    const rootIds = displayGraph.nodes
      .filter(n => n.synthetic || n.manually_added)
      .sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0))
      .map(n => `#${CSS.escape(n.id)}`)
    const fallbackRoot = [...displayGraph.nodes]
      .sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0))[0]?.id

    const elements: cytoscape.ElementDefinition[] = [
      ...displayGraph.nodes.map(n => ({
        group: 'nodes' as const,
        data: {
          id: n.id,
          label: n.synthetic ? n.label : compactLabel(n.label),
          fullLabel: n.label,
          type: n.type,
          manually_added: n.manually_added,
          argus_discovered: n.argus_discovered,
          confidence: n.confidence,
          source: n.source ?? '',
          evidence: n.evidence ?? [],
          synthetic: n.synthetic ?? false,
        },
      })),
      ...displayGraph.edges.map(e => ({
        group: 'edges' as const,
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
          confidence: e.confidence,
          rationale: e.rationale,
          evidence: e.evidence ?? [],
          source_label: e.source_label,
          target_label: e.target_label,
          synthetic: e.synthetic ?? false,
        },
      })),
    ]

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      pixelRatio: Math.min(window.devicePixelRatio || 1, 2),
      style: [
        {
          selector: 'node',
          style: {
            'background-color': (ele: cytoscape.NodeSingular) => nodeColor(ele.data('type') as string),
            'label': 'data(label)',
            'color': '#e4e4e7',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '11px',
            'font-weight': 600,
            'text-margin-y': 7,
            'text-background-color': '#09090b',
            'text-background-opacity': 0.86,
            'text-background-padding': '3px',
            'text-border-color': '#27272a',
            'text-border-width': 1,
            'text-border-opacity': 1,
            'width': (ele: cytoscape.NodeSingular) => ele.data('synthetic') ? 58 : 42,
            'height': (ele: cytoscape.NodeSingular) => ele.data('synthetic') ? 58 : 42,
            'border-width': 2,
            'border-color': '#3f3f46',
            'cursor': 'pointer',
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node[?synthetic]',
          style: {
            'shape': 'round-rectangle',
            'background-color': '#27272a',
            'border-color': '#a1a1aa',
            'border-width': 2,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node[?manually_added]',
          style: {
            'border-color': '#60a5fa',
            'border-width': 3,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node[?argus_discovered]',
          style: {
            'border-color': '#34d399',
            'border-width': 2,
            'border-style': 'dashed',
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#facc15',
            'border-width': 3,
            'background-color': (ele: cytoscape.NodeSingular) => nodeColor(ele.data('type') as string),
          } as cytoscape.Css.Node,
        },
        {
          selector: 'edge',
          style: {
            'width': (ele: cytoscape.EdgeSingular) => ele.data('synthetic') ? 1.4 : 3,
            'line-color': (ele: cytoscape.EdgeSingular) => relationshipColor(ele.data('label') as string),
            'target-arrow-color': (ele: cytoscape.EdgeSingular) => relationshipColor(ele.data('label') as string),
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '10px',
            'font-weight': 600,
            'color': '#d4d4d8',
            'text-rotation': 'autorotate',
            'text-background-color': '#09090b',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
            'edge-text-rotation': 'autorotate',
            'opacity': (ele: cytoscape.EdgeSingular) => ele.data('synthetic') ? 0.72 : 0.94,
          } as cytoscape.Css.Edge,
        },
        {
          selector: 'edge:selected',
          style: {
            'line-color': '#facc15',
            'target-arrow-color': '#facc15',
            'color': '#facc15',
          } as cytoscape.Css.Edge,
        },
        {
          selector: 'edge[label = "derived from"]',
          style: {
            'line-style': 'dashed',
          } as cytoscape.Css.Edge,
        },
        {
          selector: 'edge[?synthetic]',
          style: {
            'line-style': 'dotted',
            'label': '',
          } as cytoscape.Css.Edge,
        },
        {
          selector: '.faded',
          style: {
            'opacity': 0.16,
            'text-opacity': 0.08,
          },
        },
        {
          selector: '.focused',
          style: {
            'opacity': 1,
            'z-index': 20,
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        circle: false,
        spacingFactor: hasExplicitEdges ? 1.35 : 1.05,
        roots: rootIds.length > 0 ? rootIds.join(', ') : fallbackRoot ? `#${CSS.escape(fallbackRoot)}` : undefined,
        fit: true,
        padding: 40,
        avoidOverlap: true,
      } as cytoscape.LayoutOptions,
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
      minZoom: 0.15,
      maxZoom: 3,
    })

    if (hasExplicitEdges) {
      const layout = cy.layout({
        name: 'cose',
        idealEdgeLength: 180,
        nodeOverlap: 24,
        refresh: 20,
        fit: true,
        padding: 42,
        randomize: false,
        componentSpacing: 120,
        nodeRepulsion: () => 900000,
        edgeElasticity: () => 140,
        nestingFactor: 5,
        gravity: 70,
        numIter: 650,
        initialTemp: 180,
        coolingFactor: 0.95,
        minTemp: 1.0,
      } as cytoscape.LayoutOptions)
      layout.run()
    }

    const focusNeighborhood = (target: cytoscape.NodeSingular | cytoscape.EdgeSingular) => {
      cy.elements().removeClass('faded focused')
      if (target.isNode()) {
        const neighborhood = target.closedNeighborhood()
        cy.elements().not(neighborhood).addClass('faded')
        neighborhood.addClass('focused')
      } else {
        const connected = target.connectedNodes().union(target)
        cy.elements().not(connected).addClass('faded')
        connected.addClass('focused')
      }
    }

    cy.on('mouseover', 'node, edge', (e) => focusNeighborhood(e.target))
    cy.on('mouseout', 'node, edge', () => {
      if (!cy.$(':selected').length) cy.elements().removeClass('faded focused')
    })

    // ── Selection handlers ──────────────────────────────────────────────────

    cy.on('tap', 'node', (e) => {
      const d = e.target.data() as {
        fullLabel: string
        type: string
        manually_added: boolean
        argus_discovered: boolean
        confidence: number
        source: string
        evidence: GraphEvidence[]
        synthetic: boolean
      }
      cy.elements().unselect()
      e.target.select()
      focusNeighborhood(e.target)
      setSelected({
        kind: 'node',
        data: {
          id: e.target.id(),
          label: d.fullLabel,
          type: d.type,
          manually_added: d.manually_added,
          argus_discovered: d.argus_discovered,
          confidence: d.confidence,
          source: d.source ?? '',
          evidence: d.evidence ?? [],
          synthetic: d.synthetic,
        },
      })
    })

    cy.on('tap', 'edge', (e) => {
      const d = e.target.data() as GraphEdge
      cy.elements().unselect()
      e.target.select()
      focusNeighborhood(e.target)
      setSelected({ kind: 'edge', data: { ...d, evidence: d.evidence ?? [] } })
    })

    cy.on('tap', (e) => {
      if (e.target === cy) {
        cy.elements().unselect().removeClass('faded focused')
        setSelected(null)
      }
    })

    cyRef.current = cy

    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [visibleGraph, caseId])

  // ── Controls ────────────────────────────────────────────────────────────────

  const fitView = () => cyRef.current?.fit(undefined, 42)
  const resetLayout = () => {
    if (!cyRef.current || !visibleGraph) return
    const cy = cyRef.current
    cy.elements().removeClass('faded focused')

    if (visibleGraph.edges.length === 0) {
      cy.layout({
        name: 'breadthfirst',
        directed: true,
        circle: false,
        fit: true,
        padding: 42,
        spacingFactor: 1.05,
        roots: `#${CSS.escape(`case:${caseId}`)}`,
      } as cytoscape.LayoutOptions).run()
      return
    }

    cy.layout({
      name: 'cose',
      idealEdgeLength: 180,
      nodeOverlap: 24,
      refresh: 20,
      fit: true,
      padding: 42,
      randomize: false,
      componentSpacing: 120,
      nodeRepulsion: () => 900000,
      edgeElasticity: () => 140,
      gravity: 70,
      numIter: 650,
      initialTemp: 180,
      coolingFactor: 0.95,
      minTemp: 1.0,
    } as cytoscape.LayoutOptions).run()
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-zinc-500 text-sm gap-2">
        <span className="animate-spin w-4 h-4 border border-zinc-500 border-t-transparent rounded-full" />
        Loading graph…
      </div>
    )
  }

  if (error) {
    return <div className="flex items-center justify-center h-full text-red-400 text-sm">{error}</div>
  }

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-500 text-sm gap-2">
        <svg className="w-10 h-10 text-zinc-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <circle cx="6" cy="6" r="2" strokeWidth="2" />
          <circle cx="18" cy="6" r="2" strokeWidth="2" />
          <circle cx="12" cy="18" r="2" strokeWidth="2" />
          <path strokeLinecap="round" strokeWidth="1.5" d="M8 6h8M7 7.5l4 9M17 7.5l-4 9" />
        </svg>
        <p>No observables yet.</p>
        <p className="text-xs text-zinc-600">Add IOCs and run a review to populate the graph.</p>
      </div>
    )
  }

  const visibleNodeCount = visibleGraph?.nodes.length ?? 0
  const visibleEdgeCount = visibleGraph?.edges.length ?? 0
  const hasExplicitEdges = visibleEdgeCount > 0
  const visibleEdges = visibleGraph?.edges ?? []

  const toggleType = (type: string) => {
    setHiddenTypes(prev => {
      const next = new Set(prev)
      if (next.has(type)) next.delete(type)
      else next.add(type)
      return next
    })
  }

  const showAllTypes = () => setHiddenTypes(new Set())

  return (
    <div className="flex flex-col h-full">

      {/* ── Toolbar ── */}
      <div className="flex-none flex items-center gap-3 px-4 py-2 border-b border-zinc-800 bg-zinc-900">
        <div className="flex items-center gap-2">
          <button
            onClick={fitView}
            className="text-xs px-2 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded transition-colors"
          >Fit view</button>
          <button
            onClick={resetLayout}
            className="text-xs px-2 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded transition-colors"
          >Re-layout</button>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 ml-4 flex-wrap text-xs text-zinc-500">
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full border-2 border-blue-400 bg-blue-400/30 inline-block" />
            manually added
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full border-2 border-dashed border-emerald-400 bg-emerald-400/20 inline-block" />
            argus discovered
          </span>
          {!hasExplicitEdges && (
            <span className="flex items-center gap-1.5">
              <span className="w-4 border-t border-dotted border-zinc-500 inline-block" />
              case membership
            </span>
          )}
        </div>

        {/* Type filters */}
        <div className="flex items-center gap-1.5 ml-auto flex-wrap">
          {typeOptions.map(t => (
            <button
              key={t}
              onClick={() => toggleType(t)}
              className={`text-xs px-1.5 py-0.5 rounded font-mono transition-opacity ${TYPE_BG[t] ?? TYPE_BG.unknown} ${
                hiddenTypes.has(t) ? 'opacity-35 ring-1 ring-zinc-700 line-through' : 'opacity-100'
              }`}
              title={`${hiddenTypes.has(t) ? 'Show' : 'Hide'} ${t}`}
            >
              {t}
            </button>
          ))}
          {hiddenTypes.size > 0 && (
            <button
              onClick={showAllTypes}
              className="text-xs px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
            >
              show all
            </button>
          )}
        </div>

        <div className="text-xs text-zinc-600 ml-2">
          {visibleNodeCount}/{graph.nodes.length} nodes · {visibleEdgeCount}/{graph.edges.length} edges
        </div>
      </div>

      {/* ── Graph + detail panel ── */}
      <div className="flex-1 flex overflow-hidden relative">

        {/* Cytoscape container */}
        <div ref={containerRef} className="flex-1 bg-zinc-950" />

        {/* Detail panel */}
        {selected && (
          <div className="absolute inset-y-0 right-0 z-20 w-[min(24rem,100%)] border-l border-zinc-800 bg-zinc-900 overflow-y-auto shadow-2xl">
            <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
              <span className="text-xs text-zinc-500 uppercase tracking-wider">
                {selected.kind === 'node' ? 'Observable' : 'Relationship'}
              </span>
              <button
                onClick={clearSelection}
                className="text-zinc-600 hover:text-zinc-300 transition-colors text-lg leading-none"
              >×</button>
            </div>

            {selected.kind === 'node' && (() => {
              const n = selected.data as GraphNode
              const evidence = n.evidence ?? []
              const related = visibleEdges.filter(
                e => e.source === n.id || e.target === n.id
              )
              const provenanceEdges = related.filter(e => e.rationale || e.evidence?.length > 0)
              return (
                <div className="p-4 space-y-3">
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">Value</div>
                    <div className="font-mono text-sm text-zinc-100 break-all">{n.label}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-1.5 py-0.5 rounded font-mono ${TYPE_BG[n.type] ?? TYPE_BG.unknown}`}>
                      {n.type}
                    </span>
                    {n.manually_added && (
                      <span className="text-xs bg-blue-900 text-blue-300 px-1.5 py-0.5 rounded">manual</span>
                    )}
                    {n.argus_discovered && (
                      <span className="text-xs bg-emerald-900 text-emerald-300 px-1.5 py-0.5 rounded">discovered</span>
                    )}
                  </div>
                  {n.confidence > 0 && (
                    <div>
                      <div className="text-xs text-zinc-500 mb-1">Confidence</div>
                      <div className="text-sm text-zinc-300">{(n.confidence * 100).toFixed(0)}%</div>
                    </div>
                  )}
                  {(n.source || evidence.length > 0) && (
                    <div>
                      <div className="text-xs text-zinc-500 mb-2">Discovery</div>
                      {n.source && (
                        <div className="text-xs text-zinc-300 bg-zinc-800 rounded p-2 mb-2">
                          Source: <span className="font-mono">{n.source}</span>
                        </div>
                      )}
                      <EvidenceList evidence={evidence} />
                    </div>
                  )}
                  {provenanceEdges.length > 0 && (
                    <div>
                      <div className="text-xs text-zinc-500 mb-2">Found via</div>
                      <div className="space-y-2">
                        {provenanceEdges.map(e => (
                          <div key={e.id} className="text-xs text-zinc-400 bg-zinc-800 rounded p-2 border-l-2" style={{ borderColor: relationshipColor(e.label) }}>
                            <div className="flex items-center justify-between gap-2 mb-1">
                              <span className="text-zinc-300 font-medium">{e.label}</span>
                              {e.confidence > 0 && <span className="text-zinc-500 flex-none">{(e.confidence * 100).toFixed(0)}%</span>}
                            </div>
                            <div className="font-mono truncate mb-1">
                              {e.source === n.id ? `to ${e.target_label}` : `from ${e.source_label}`}
                            </div>
                            {e.rationale && <div className="text-zinc-300">{e.rationale}</div>}
                            <EvidenceList evidence={e.evidence ?? []} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {/* Show edges involving this node */}
                  {!n.synthetic && (() => {
                    if (related.length === 0) return null
                    return (
                      <div>
                        <div className="text-xs text-zinc-500 mb-2">Relationships ({related.length})</div>
                        <div className="space-y-2">
                          {related.map(e => (
                            <div key={e.id} className="text-xs text-zinc-400 bg-zinc-800 rounded p-2 border-l-2" style={{ borderColor: relationshipColor(e.label) }}>
                              <div className="text-zinc-300 font-medium mb-0.5">{e.label}</div>
                              <div className="font-mono truncate">
                                {e.source === n.id ? `→ ${e.target_label}` : `← ${e.source_label}`}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  })()}
                </div>
              )
            })()}

            {selected.kind === 'edge' && (() => {
              const e = selected.data as GraphEdge
              const evidence = e.evidence ?? []
              return (
                <div className="p-4 space-y-3">
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">Relationship</div>
                    <div className="text-sm font-medium text-zinc-100 capitalize">{e.label}</div>
                  </div>
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">Source</div>
                    <div className="font-mono text-xs text-zinc-300 break-all">{e.source_label}</div>
                  </div>
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">Target</div>
                    <div className="font-mono text-xs text-zinc-300 break-all">{e.target_label}</div>
                  </div>
                  {e.confidence > 0 && (
                    <div>
                      <div className="text-xs text-zinc-500 mb-1">Confidence</div>
                      <div className="text-sm text-zinc-300">{(e.confidence * 100).toFixed(0)}%</div>
                    </div>
                  )}
                  {e.rationale && (
                    <div>
                      <div className="text-xs text-zinc-500 mb-1">Rationale</div>
                      <div className="text-xs text-zinc-300">{e.rationale}</div>
                    </div>
                  )}
                  {evidence.length > 0 && (
                    <div>
                      <div className="text-xs text-zinc-500 mb-2">Evidence</div>
                      <EvidenceList evidence={evidence} />
                    </div>
                  )}
                </div>
              )
            })()}
          </div>
        )}
      </div>
    </div>
  )
}

function EvidenceList({ evidence }: { evidence: GraphEvidence[] }) {
  if (evidence.length === 0) return null

  return (
    <div className="space-y-2">
      {evidence.map(ev => (
        <div key={ev.id} className="text-xs text-zinc-400 bg-zinc-800 rounded p-2">
          <div className="flex items-center justify-between gap-2 mb-1">
            <span className="font-mono text-zinc-200 truncate">{ev.source || 'unknown source'}</span>
            {ev.confidence > 0 && (
              <span className="text-zinc-500 flex-none">{(ev.confidence * 100).toFixed(0)}%</span>
            )}
          </div>
          {(ev.summary || ev.inference_basis) && (
            <div className="text-zinc-300 mb-1">{ev.summary || ev.inference_basis}</div>
          )}
          {ev.excerpt && <div className="text-zinc-500 line-clamp-3">{ev.excerpt}</div>}
          {ev.reference && <div className="text-zinc-500 font-mono truncate mt-1">{ev.reference}</div>}
        </div>
      ))}
    </div>
  )
}
